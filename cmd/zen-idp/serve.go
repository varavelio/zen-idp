package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/varavelio/zen-idp/internal/id"
	"github.com/varavelio/zen-idp/internal/jwt"
	"github.com/varavelio/zen-idp/internal/lock"
	"github.com/varavelio/zen-idp/internal/login"
	"github.com/varavelio/zen-idp/internal/onetoken"
	"github.com/varavelio/zen-idp/internal/ratelimit"
	"github.com/varavelio/zen-idp/internal/server"
	"github.com/varavelio/zen-idp/internal/session"
	"github.com/varavelio/zen-idp/internal/statestore"
	"github.com/varavelio/zen-idp/internal/token"
	"github.com/varavelio/zen-idp/internal/ui"
	"github.com/varavelio/zen-idp/internal/userinfo"
)

const (
	// gracefulShutdownTimeout bounds how long serve waits for in-flight
	// requests after a termination signal before giving up.
	gracefulShutdownTimeout = 10 * time.Second
	// readHeaderTimeout bounds how long serve waits for a request header.
	readHeaderTimeout = 5 * time.Second
	// idleTimeout drops keep-alive connections idle longer than this.
	idleTimeout = 60 * time.Second
)

// runServe bootstraps the OIDC service and serves until a failure or a
// termination signal.
func runServe(envFile string, dependencies dependencies) error {
	runtime, err := dependencies.loadRuntime(envFile)
	if err != nil {
		return fmt.Errorf("load runtime configuration: %w", err)
	}

	configuration, err := dependencies.loadConfiguration(runtime.ConfigPath)
	if err != nil {
		return err
	}

	ctx := context.Background()

	db, err := dependencies.openStateStore(ctx, runtime.StateDBPath)
	if err != nil {
		return fmt.Errorf("open state database: %w", err)
	}
	defer func() { _ = db.Close() }()

	if err := dependencies.migrateStateStore(ctx, db); err != nil {
		return fmt.Errorf("migrate state database: %w", err)
	}

	signingKey, err := dependencies.deriveSigningKey(runtime.RootSecret)
	if err != nil {
		return fmt.Errorf("derive signing identity: %w", err)
	}

	publicJWK, err := dependencies.derivePublicJWK(&signingKey.PublicKey)
	if err != nil {
		return fmt.Errorf("derive signing identity: %w", err)
	}

	queries := statestore.New(db)

	rateLimiter, err := ratelimit.New(
		queries,
		configuration.Security.RateLimits.MaxUserLoginAttempts,
		configuration.Security.RateLimits.UserLoginAttemptsWindow,
	)
	if err != nil {
		return fmt.Errorf("build login rate limiter: %w", err)
	}

	locks, err := lock.NewLocks(queries)
	if err != nil {
		return fmt.Errorf("build user locks: %w", err)
	}

	sessionStore, err := session.NewStore(
		queries,
		id.NewIDGenerator(),
		runtime.RootSecret,
		configuration.Security.Session.MaxAge,
	)
	if err != nil {
		return fmt.Errorf("build session store: %w", err)
	}

	codeStore, err := onetoken.NewStore(queries, id.NewIDGenerator(), runtime.RootSecret)
	if err != nil {
		return fmt.Errorf("build one-use token store: %w", err)
	}

	jwtSigner, err := jwt.NewSigner(signingKey, publicJWK.Kid)
	if err != nil {
		return fmt.Errorf("build token signer: %w", err)
	}

	jwtVerifier, err := jwt.NewVerifier(&signingKey.PublicKey, publicJWK.Kid)
	if err != nil {
		return fmt.Errorf("build token verifier: %w", err)
	}

	tokenIssuer, err := token.NewIssuer(
		jwtSigner,
		configuration.Issuer,
		configuration.Users,
		locks,
	)
	if err != nil {
		return fmt.Errorf("build token issuer: %w", err)
	}

	userinfoService, err := userinfo.New(
		jwtVerifier,
		configuration.Issuer,
		configuration.Users,
		locks,
		sessionStore,
	)
	if err != nil {
		return fmt.Errorf("build userinfo service: %w", err)
	}

	logins, err := login.New(
		configuration.Users,
		runtime.RootSecret,
		rateLimiter,
		locks,
		sessionStore,
	)
	if err != nil {
		return fmt.Errorf("build login service: %w", err)
	}

	address := net.JoinHostPort(configuration.Server.Host, strconv.Itoa(configuration.Server.Port))
	listener, err := dependencies.listen("tcp", address)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", address, err)
	}

	slog.InfoContext(ctx, "http server listening",
		slog.String("address", listener.Addr().String()),
	)

	app := server.New(
		publicJWK,
		configuration.Clients,
		ui.Assets(),
		server.LoginDependencies{
			Service:       logins,
			UI:            configuration.UI,
			SecureCookies: strings.HasPrefix(configuration.Issuer, "https://"),
			SessionMaxAge: configuration.Security.Session.MaxAge,
		},
		server.AuthorizeDependencies{
			Sessions: sessionStore,
			Codes:    codeStore,
		},
		server.TokenDependencies{
			Codes:                  codeStore,
			Issuer:                 tokenIssuer,
			RequireClientSecretTLS: strings.HasPrefix(configuration.Issuer, "https://"),
		},
		server.UserinfoDependencies{
			Service: userinfoService,
		},
	)
	httpServer := &http.Server{
		Handler:           app.Handler(),
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
	}

	return dependencies.serve(listener, httpServer)
}

// serveWithGracefulShutdown serves requests on listener until the server
// fails or a termination signal arrives. On a signal it shuts the server down
// gracefully, giving in-flight requests gracefulShutdownTimeout to finish
// before the function returns.
func serveWithGracefulShutdown(listener net.Listener, httpServer *http.Server) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	serveErrors := make(chan error, 1)
	go func() {
		serveErrors <- httpServer.Serve(listener)
	}()

	select {
	case err := <-serveErrors:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve http: %w", err)
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), gracefulShutdownTimeout)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("graceful shutdown: %w", err)
		}
		return nil
	}
}
