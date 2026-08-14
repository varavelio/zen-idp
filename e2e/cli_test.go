//go:build e2e

package e2e

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/varavelio/zen-idp/e2e/harness"
)

// TestValidateConfig exercises the configuration validation command against
// the exact startup discovery, merge, parse, and validation path, requiring
// only the configuration path.
func TestValidateConfig(t *testing.T) {
	dir := t.TempDir()
	path := (harness.Config{
		AdminHash: testAdminHash,
		Users:     []harness.User{{Sub: "alice"}},
		Clients: []harness.Client{{
			ID:           "app",
			RedirectURIs: []string{"http://127.0.0.1:9999/callback"},
		}},
	}).WriteFile(t, dir, "https://auth.example.com", 8080)

	stdout, stderr, code := harness.Run(t,
		[]string{"ZEN_IDP_CONFIG_PATH=" + path},
		"validate-config",
	)
	require.Equal(t, 0, code)
	require.Contains(t, stdout, "configuration is valid")
	require.Empty(t, stderr)

	// An invalid configuration fails with the offending field.
	badPath := filepath.Join(dir, "bad.yaml")
	badYAML := "config:\n" +
		"  issuer: \"not a url\"\n" +
		"  security:\n" +
		"    admin_password_hash: \"" + testAdminHash + "\"\n"
	require.NoError(t, os.WriteFile(badPath, []byte(badYAML), 0o600))
	_, stderr, code = harness.Run(t,
		[]string{"ZEN_IDP_CONFIG_PATH=" + badPath},
		"validate-config",
	)
	require.Equal(t, 1, code)
	require.Contains(t, stderr, "issuer")

	// A missing configuration path fails closed.
	_, stderr, code = harness.Run(t, nil, "validate-config")
	require.Equal(t, 1, code)
	require.Contains(t, stderr, "ZEN_IDP_CONFIG_PATH")
}

// TestGenerateSecrets verifies the bootstrap secret bundle: complete output
// on standard output, the exact Base62 alphabet, the exact credential
// lengths, and Argon2id PHC hashes.
func TestGenerateSecrets(t *testing.T) {
	stdout, stderr, code := harness.Run(t, nil, "generate-secrets")
	require.Equal(t, 0, code)
	require.Empty(t, stderr)

	for _, label := range []string{
		"WARNING: This output contains plaintext credentials.",
		"ZEN_IDP_SECRET=",
		"Administrator",
		"OIDC client",
		"Store plaintext values securely",
	} {
		require.Contains(t, stdout, label)
	}

	base62 := regexp.MustCompile(`^[0-9a-zA-Z]+$`)
	argon2id := regexp.MustCompile(`^\$argon2id\$`)

	root := regexp.MustCompile(`ZEN_IDP_SECRET=([0-9a-zA-Z]+)`).FindStringSubmatch(stdout)
	require.Len(t, root, 2)
	require.Len(t, root[1], 43)
	require.True(t, base62.MatchString(root[1]))

	adminPlain := regexp.MustCompile(`(?m)^plain: ([0-9a-zA-Z]+)$`).
		FindAllStringSubmatch(stdout, -1)
	require.Len(t, adminPlain, 2)
	require.Len(t, adminPlain[0][1], 14)
	require.Len(t, adminPlain[1][1], 43)
	require.True(t, base62.MatchString(adminPlain[0][1]))
	require.True(t, base62.MatchString(adminPlain[1][1]))

	hashes := regexp.MustCompile(`(?m)^hash: "([^"]+)"$`).FindAllStringSubmatch(stdout, -1)
	require.Len(t, hashes, 2)
	require.True(t, argon2id.MatchString(hashes[0][1]))
	require.True(t, argon2id.MatchString(hashes[1][1]))
	require.Contains(t, hashes[0][1], "$v=19$")
	require.Contains(t, hashes[1][1], "$v=19$")
}

// TestServeFailsClosed verifies that the service refuses to start without
// its required runtime settings.
func TestServeFailsClosed(t *testing.T) {
	// Missing environment variables fail at startup.
	_, stderr, code := harness.Run(t, nil, "serve")
	require.Equal(t, 1, code)
	require.Contains(t, stderr, "ZEN_IDP_CONFIG_PATH")

	// A too-short root secret fails at startup.
	dir := t.TempDir()
	path := (harness.Config{
		AdminHash: testAdminHash,
	}).WriteFile(t, dir, "https://auth.example.com", 8080)
	_, stderr, code = harness.Run(t, []string{
		"ZEN_IDP_CONFIG_PATH=" + path,
		"ZEN_IDP_SECRET=short",
		"ZEN_IDP_DB_PATH=" + filepath.Join(dir, "state.db"),
	}, "serve")
	require.Equal(t, 1, code)
	require.Contains(t, stderr, "ZEN_IDP_SECRET")
}
