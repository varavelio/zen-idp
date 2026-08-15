package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"database/sql"
	"errors"
	"net"
	"net/http"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/varavelio/zen-idp/internal/config"
	"github.com/varavelio/zen-idp/internal/jwk"
	"github.com/varavelio/zen-idp/internal/runtimeconfig"
)

func TestRunServe(t *testing.T) {
	t.Run("performs full bootstrap and starts the HTTP server", func(t *testing.T) {
		dependencies := testDependencies(t)
		var selected string
		dependencies.loadConfiguration = func(selector string) (*config.Config, error) {
			selected = selector
			return config.Parse([]byte(instanceYAML))
		}
		var runtime runtimeconfig.RuntimeConfig
		dependencies.loadRuntime = func(envFile string) (runtimeconfig.RuntimeConfig, error) {
			require.Empty(t, envFile)
			var err error
			runtime, err = runtimeconfig.Load("")
			require.NoError(t, err)
			return runtime, nil
		}
		var openedPath string
		var migratedDB *sql.DB
		dependencies.openStateStore = func(_ context.Context, path string) (*sql.DB, error) {
			openedPath = path
			return sql.Open("sqlite", "file:"+path)
		}
		dependencies.migrateStateStore = func(_ context.Context, db *sql.DB) error {
			migratedDB = db
			return nil
		}
		var derivedRootSecret [sha256.Size]byte
		var derivedKey *rsa.PrivateKey
		dependencies.deriveSigningKey = func(rootSecret [sha256.Size]byte) (*rsa.PrivateKey, error) {
			derivedRootSecret = rootSecret
			key, err := rsa.GenerateKey(rand.Reader, 1024)
			require.NoError(t, err)
			derivedKey = key
			return key, nil
		}
		var receivedPublicKey rsa.PublicKey
		dependencies.derivePublicJWK = func(key *rsa.PublicKey) (jwk.PublicJWK, error) {
			receivedPublicKey = *key
			return jwk.PublicJWK{Kid: "18o8WQf60YOSXryGuVEqiEWfO80TcNyB3FLCRWyLzsE"}, nil
		}
		listener := listenOnRandomPort(t)
		defer func() { _ = listener.Close() }()
		var listenedAddress string
		dependencies.listen = func(network, address string) (net.Listener, error) {
			require.Equal(t, "tcp", network)
			listenedAddress = address
			return listener, nil
		}
		var servedListener net.Listener
		var servedServer *http.Server
		dependencies.serve = func(listener net.Listener, httpServer *http.Server) error {
			servedListener = listener
			servedServer = httpServer
			return nil
		}
		var stdout bytes.Buffer
		var stderr bytes.Buffer

		exitCode := run([]string{"serve"}, &stdout, &stderr, dependencies)

		require.Zero(t, exitCode)
		require.Equal(t, "config", selected)
		require.Equal(t, runtime.StateDBPath, openedPath)
		require.NotNil(t, migratedDB)
		require.Equal(t, runtime.RootSecret, derivedRootSecret)
		require.Equal(t, derivedKey.PublicKey, receivedPublicKey)
		require.Equal(t, "0.0.0.0:8080", listenedAddress)
		require.Same(t, listener, servedListener)
		require.NotNil(t, servedServer.Handler)
		require.Equal(t, 5*time.Second, servedServer.ReadHeaderTimeout)
		require.Empty(t, stdout.String())
		require.Empty(t, stderr.String())
	})

	t.Run("passes the selected env file to runtime loading", func(t *testing.T) {
		dependencies := testDependencies(t)
		var receivedEnvFile string
		dependencies.loadRuntime = func(envFile string) (runtimeconfig.RuntimeConfig, error) {
			receivedEnvFile = envFile
			return runtimeconfig.RuntimeConfig{}, errors.New("stop")
		}
		var stdout bytes.Buffer
		var stderr bytes.Buffer

		exitCode := run(
			[]string{"serve", "--env-file", "runtime.env"},
			&stdout,
			&stderr,
			dependencies,
		)

		require.Equal(t, 1, exitCode)
		require.Equal(t, "runtime.env", receivedEnvFile)
		require.Contains(t, stderr.String(), "stop")
	})

	t.Run("fails when the state database cannot be opened", func(t *testing.T) {
		dependencies := testDependencies(t)
		dependencies.openStateStore = func(context.Context, string) (*sql.DB, error) {
			return nil, errors.New("cannot open store")
		}
		dependencies.migrateStateStore = func(context.Context, *sql.DB) error {
			t.Fatal("migrations must not run when the database cannot be opened")
			return nil
		}
		var stdout bytes.Buffer
		var stderr bytes.Buffer

		exitCode := run([]string{"serve"}, &stdout, &stderr, dependencies)

		require.Equal(t, 1, exitCode)
		require.Empty(t, stdout.String())
		require.Contains(t, stderr.String(), "open state database")
		require.Contains(t, stderr.String(), "cannot open store")
	})

	t.Run("fails when state database migrations fail", func(t *testing.T) {
		dependencies := testDependencies(t)
		dependencies.migrateStateStore = func(context.Context, *sql.DB) error {
			return errors.New("cannot migrate store")
		}
		var stdout bytes.Buffer
		var stderr bytes.Buffer

		exitCode := run([]string{"serve"}, &stdout, &stderr, dependencies)

		require.Equal(t, 1, exitCode)
		require.Empty(t, stdout.String())
		require.Contains(t, stderr.String(), "migrate state database")
		require.Contains(t, stderr.String(), "cannot migrate store")
	})

	t.Run("fails when the signing identity cannot be derived", func(t *testing.T) {
		dependencies := testDependencies(t)
		dependencies.deriveSigningKey = func([sha256.Size]byte) (*rsa.PrivateKey, error) {
			return nil, errors.New("cannot derive key")
		}
		dependencies.derivePublicJWK = func(*rsa.PublicKey) (jwk.PublicJWK, error) {
			t.Fatal("public JWK must not be derived when key derivation fails")
			return jwk.PublicJWK{}, nil
		}
		var stdout bytes.Buffer
		var stderr bytes.Buffer

		exitCode := run([]string{"serve"}, &stdout, &stderr, dependencies)

		require.Equal(t, 1, exitCode)
		require.Empty(t, stdout.String())
		require.Contains(t, stderr.String(), "derive signing identity")
		require.Contains(t, stderr.String(), "cannot derive key")
	})

	t.Run("fails when the public JWK cannot be derived", func(t *testing.T) {
		dependencies := testDependencies(t)
		dependencies.derivePublicJWK = func(*rsa.PublicKey) (jwk.PublicJWK, error) {
			return jwk.PublicJWK{}, errors.New("cannot derive jwk")
		}
		var stdout bytes.Buffer
		var stderr bytes.Buffer

		exitCode := run([]string{"serve"}, &stdout, &stderr, dependencies)

		require.Equal(t, 1, exitCode)
		require.Empty(t, stdout.String())
		require.Contains(t, stderr.String(), "derive signing identity")
		require.Contains(t, stderr.String(), "cannot derive jwk")
	})

	t.Run("fails when the HTTP listener cannot be created", func(t *testing.T) {
		dependencies := testDependencies(t)
		dependencies.listen = func(string, string) (net.Listener, error) {
			return nil, errors.New("cannot listen")
		}
		dependencies.serve = func(net.Listener, *http.Server) error {
			t.Fatal("HTTP server must not start when the listener cannot be created")
			return nil
		}
		var stdout bytes.Buffer
		var stderr bytes.Buffer

		exitCode := run([]string{"serve"}, &stdout, &stderr, dependencies)

		require.Equal(t, 1, exitCode)
		require.Empty(t, stdout.String())
		require.Contains(t, stderr.String(), "listen on 0.0.0.0:8080")
		require.Contains(t, stderr.String(), "cannot listen")
	})

	t.Run("fails when the HTTP server fails", func(t *testing.T) {
		dependencies := testDependencies(t)
		dependencies.serve = func(net.Listener, *http.Server) error {
			return errors.New("http server failed")
		}
		var stdout bytes.Buffer
		var stderr bytes.Buffer

		exitCode := run([]string{"serve"}, &stdout, &stderr, dependencies)

		require.Equal(t, 1, exitCode)
		require.Empty(t, stdout.String())
		require.Contains(t, stderr.String(), "http server failed")
	})

	t.Run("stops when runtime loading fails", func(t *testing.T) {
		dependencies := testDependencies(t)
		dependencies.loadRuntime = func(string) (runtimeconfig.RuntimeConfig, error) {
			return runtimeconfig.RuntimeConfig{}, errors.New("invalid runtime")
		}
		dependencies.loadConfiguration = func(string) (*config.Config, error) {
			t.Fatal("YAML must not be loaded before runtime validation")
			return nil, nil
		}
		dependencies.openStateStore = func(context.Context, string) (*sql.DB, error) {
			t.Fatal("state database must not be opened before runtime validation")
			return nil, nil
		}
		dependencies.migrateStateStore = func(context.Context, *sql.DB) error {
			t.Fatal("migrations must not run before runtime validation")
			return nil
		}
		dependencies.deriveSigningKey = func([sha256.Size]byte) (*rsa.PrivateKey, error) {
			t.Fatal("signing identity must not be derived before runtime validation")
			return nil, nil
		}
		dependencies.derivePublicJWK = func(*rsa.PublicKey) (jwk.PublicJWK, error) {
			t.Fatal("public JWK must not be derived before runtime validation")
			return jwk.PublicJWK{}, nil
		}
		dependencies.listen = func(string, string) (net.Listener, error) {
			t.Fatal("listener must not be created before runtime validation")
			return nil, nil
		}
		dependencies.serve = func(net.Listener, *http.Server) error {
			t.Fatal("HTTP server must not start before runtime validation")
			return nil
		}
		var stdout bytes.Buffer
		var stderr bytes.Buffer

		exitCode := run([]string{"serve"}, &stdout, &stderr, dependencies)

		require.Equal(t, 1, exitCode)
		require.Empty(t, stdout.String())
		require.Contains(t, stderr.String(), "invalid runtime")
	})

	t.Run("fails when the system clock is implausible", func(t *testing.T) {
		dependencies := testDependencies(t)
		dependencies.checkClock = func(time.Time) error {
			return errors.New("implausible clock")
		}
		dependencies.loadRuntime = func(string) (runtimeconfig.RuntimeConfig, error) {
			t.Fatal("runtime must not be loaded when the clock is implausible")
			return runtimeconfig.RuntimeConfig{}, nil
		}
		dependencies.loadConfiguration = func(string) (*config.Config, error) {
			t.Fatal("YAML must not be loaded when the clock is implausible")
			return nil, nil
		}
		dependencies.openStateStore = func(context.Context, string) (*sql.DB, error) {
			t.Fatal("state database must not be opened when the clock is implausible")
			return nil, nil
		}
		dependencies.migrateStateStore = func(context.Context, *sql.DB) error {
			t.Fatal("migrations must not run when the clock is implausible")
			return nil
		}
		dependencies.deriveSigningKey = func([sha256.Size]byte) (*rsa.PrivateKey, error) {
			t.Fatal("signing identity must not be derived when the clock is implausible")
			return nil, nil
		}
		dependencies.derivePublicJWK = func(*rsa.PublicKey) (jwk.PublicJWK, error) {
			t.Fatal("public JWK must not be derived when the clock is implausible")
			return jwk.PublicJWK{}, nil
		}
		dependencies.listen = func(string, string) (net.Listener, error) {
			t.Fatal("listener must not be created when the clock is implausible")
			return nil, nil
		}
		dependencies.serve = func(net.Listener, *http.Server) error {
			t.Fatal("HTTP server must not start when the clock is implausible")
			return nil
		}
		var stdout bytes.Buffer
		var stderr bytes.Buffer

		exitCode := run([]string{"serve"}, &stdout, &stderr, dependencies)

		require.Equal(t, 1, exitCode)
		require.Empty(t, stdout.String())
		require.Contains(t, stderr.String(), "check system clock")
		require.Contains(t, stderr.String(), "implausible clock")
	})
}

func listenOnRandomPort(t *testing.T) net.Listener {
	t.Helper()
	var listenConfig net.ListenConfig
	listener, err := listenConfig.Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	return listener
}

func TestServeWithGracefulShutdown(t *testing.T) {
	t.Run("shuts down gracefully on a termination signal", func(t *testing.T) {
		handlerEntered := make(chan struct{})
		releaseHandler := make(chan struct{})
		httpServer := &http.Server{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				close(handlerEntered)
				<-releaseHandler
				w.WriteHeader(http.StatusOK)
			}),
		}
		listener := listenOnRandomPort(t)
		defer func() { _ = listener.Close() }()

		serveDone := make(chan error, 1)
		go func() {
			serveDone <- serveWithGracefulShutdown(listener, httpServer)
		}()

		requestCtx, cancelRequest := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancelRequest()
		request, err := http.NewRequestWithContext(
			requestCtx,
			http.MethodGet,
			"http://"+listener.Addr().String()+"/",
			nil,
		)
		require.NoError(t, err)
		requestDone := make(chan int, 1)
		requestErrors := make(chan error, 1)
		go func() {
			response, err := http.DefaultClient.Do(request)
			if err != nil {
				requestErrors <- err
				return
			}
			status := response.StatusCode
			_ = response.Body.Close()
			requestDone <- status
		}()

		<-handlerEntered
		require.NoError(t, syscall.Kill(os.Getpid(), syscall.SIGTERM))
		close(releaseHandler)

		select {
		case err := <-requestErrors:
			t.Fatalf("in-flight request failed during shutdown: %v", err)
		case status := <-requestDone:
			require.Equal(t, http.StatusOK, status)
		}
		require.NoError(t, <-serveDone)
	})

	t.Run("returns the server failure", func(t *testing.T) {
		listener := listenOnRandomPort(t)
		require.NoError(t, listener.Close())
		httpServer := &http.Server{Handler: http.NotFoundHandler()}

		err := serveWithGracefulShutdown(listener, httpServer)

		require.ErrorContains(t, err, "serve http")
	})
}
