package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

// healthCheckTimeout bounds how long the health command waits for the
// endpoint to answer.
const healthCheckTimeout = 3 * time.Second

// runHealth checks the health endpoint of the configured listener and
// reports the result on stdout, exiting non-zero when the service is
// unreachable or unhealthy. It needs only the configuration path, exactly
// like validate-config, so container health checks stay zero-config.
func runHealth(envFile string, stdout io.Writer, dependencies dependencies) error {
	configPath, err := dependencies.loadConfigPath(envFile)
	if err != nil {
		return fmt.Errorf("load configuration path: %w", err)
	}
	configuration, err := dependencies.loadConfiguration(configPath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), healthCheckTimeout)
	defer cancel()
	status, err := dependencies.checkHealth(
		ctx,
		healthURL(configuration.Server.Host, configuration.Server.Port),
	)
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}
	if status != http.StatusOK {
		return fmt.Errorf("health check failed: status %d", status)
	}
	if _, err := fmt.Fprintln(stdout, "ok"); err != nil {
		return fmt.Errorf("write health result: %w", err)
	}
	return nil
}

// healthURL builds the health endpoint URL of the configured listener,
// replacing wildcard bind hosts with the loopback address so the check
// always targets a connectable address.
func healthURL(host string, port int) string {
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return fmt.Sprintf("http://%s:%d/health", host, port)
}

// checkHealthEndpoint performs one GET against the given URL and returns
// the response status.
func checkHealthEndpoint(ctx context.Context, url string) (int, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return 0, err
	}
	defer func() { _ = response.Body.Close() }()
	return response.StatusCode, nil
}
