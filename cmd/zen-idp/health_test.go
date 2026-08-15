package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/varavelio/zen-idp/internal/config"
)

func TestRunHealth(t *testing.T) {
	t.Run("reports a healthy service", func(t *testing.T) {
		dependencies := testDependencies(t)
		dependencies.loadConfiguration = func(string) (*config.Config, error) {
			return &config.Config{Server: config.Server{Host: "127.0.0.1", Port: 8080}}, nil
		}
		var checked string
		dependencies.checkHealth = func(_ context.Context, url string) (int, error) {
			checked = url
			return http.StatusOK, nil
		}
		var stdout bytes.Buffer
		var stderr bytes.Buffer

		exitCode := run([]string{"health"}, &stdout, &stderr, dependencies)

		require.Zero(t, exitCode)
		require.Equal(t, "http://127.0.0.1:8080/health", checked)
		require.Equal(t, "ok\n", stdout.String())
		require.Empty(t, stderr.String())
	})

	t.Run("replaces wildcard bind hosts with the loopback address", func(t *testing.T) {
		dependencies := testDependencies(t)
		dependencies.loadConfiguration = func(string) (*config.Config, error) {
			return &config.Config{Server: config.Server{Host: "0.0.0.0", Port: 8080}}, nil
		}
		var checked string
		dependencies.checkHealth = func(_ context.Context, url string) (int, error) {
			checked = url
			return http.StatusOK, nil
		}
		var stdout, stderr bytes.Buffer

		exitCode := run([]string{"health"}, &stdout, &stderr, dependencies)

		require.Zero(t, exitCode)
		require.Equal(t, "http://127.0.0.1:8080/health", checked)
	})

	t.Run("fails when the endpoint is unreachable", func(t *testing.T) {
		dependencies := testDependencies(t)
		dependencies.checkHealth = func(context.Context, string) (int, error) {
			return 0, errors.New("connection refused")
		}
		var stdout bytes.Buffer
		var stderr bytes.Buffer

		exitCode := run([]string{"health"}, &stdout, &stderr, dependencies)

		require.Equal(t, 1, exitCode)
		require.Empty(t, stdout.String())
		require.Contains(t, stderr.String(), "health check failed: connection refused")
	})

	t.Run("fails when the service reports unhealthy", func(t *testing.T) {
		dependencies := testDependencies(t)
		dependencies.checkHealth = func(context.Context, string) (int, error) {
			return http.StatusServiceUnavailable, nil
		}
		var stdout bytes.Buffer
		var stderr bytes.Buffer

		exitCode := run([]string{"health"}, &stdout, &stderr, dependencies)

		require.Equal(t, 1, exitCode)
		require.Empty(t, stdout.String())
		require.Contains(t, stderr.String(), "health check failed: status 503")
	})
}
