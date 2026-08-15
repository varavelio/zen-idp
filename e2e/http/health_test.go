//go:build e2e

package e2e

import (
	"net/http"
	"net/url"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/varavelio/zen-idp/e2e/http/harness"
)

// TestHealth verifies the health endpoint reports a live state database.
func TestHealth(t *testing.T) {
	app := harness.New(t, harness.Config{
		RootSecret: testRootSecret,
		AdminHash:  testAdminHash,
	})
	var body struct {
		OK bool `json:"ok"`
	}
	response := app.Browser().Get(t, "/health")
	response.RequireStatus(t, http.StatusOK).JSON(t, &body)
	require.True(t, body.OK)
	require.Equal(t, "no-store", response.Header.Get("Cache-Control"))
}

// TestHealthCommand verifies the health command checks the configured
// listener and reports the outcome through its exit code.
func TestHealthCommand(t *testing.T) {
	app := harness.New(t, harness.Config{
		RootSecret: testRootSecret,
		AdminHash:  testAdminHash,
	})
	base, err := url.Parse(app.BaseURL())
	require.NoError(t, err)
	port, err := strconv.Atoi(base.Port())
	require.NoError(t, err)
	dir := t.TempDir()
	configPath := (harness.Config{
		RootSecret: testRootSecret,
		AdminHash:  testAdminHash,
	}).WriteFile(t, dir, app.BaseURL(), port)

	// The command reports ok against the running instance.
	stdout, stderr, code := harness.Run(t,
		[]string{"ZEN_IDP_CONFIG_PATH=" + configPath},
		"health",
	)
	require.Equal(t, 0, code)
	require.Equal(t, "ok\n", stdout)
	require.Empty(t, stderr)

	// The command fails when nothing listens on the configured port.
	deadPath := (harness.Config{
		RootSecret: testRootSecret,
		AdminHash:  testAdminHash,
	}).WriteFile(t, dir, app.BaseURL(), port+1)
	_, stderr, code = harness.Run(t,
		[]string{"ZEN_IDP_CONFIG_PATH=" + deadPath},
		"health",
	)
	require.Equal(t, 1, code)
	require.Contains(t, stderr, "health check failed")
}
