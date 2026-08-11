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
	"syscall"
	"time"

	"github.com/varavelio/zen-idp/internal/server"
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

	address := net.JoinHostPort(configuration.Server.Host, strconv.Itoa(configuration.Server.Port))
	listener, err := dependencies.listen("tcp", address)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", address, err)
	}

	slog.InfoContext(ctx, "http server listening",
		slog.String("address", listener.Addr().String()),
	)

	app := server.New(publicJWK, configuration.Clients)
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
