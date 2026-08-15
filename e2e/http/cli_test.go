//go:build e2e

package e2e

import (
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/varavelio/zen-idp/e2e/http/harness"
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

// writeCompositionFile writes one configuration fragment of the
// composition tests.
func writeCompositionFile(t *testing.T, path, contents string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
}

// compositionInstance is a valid configuration fragment declaring the
// issuer and the administrator credential.
const compositionInstance = "config:\n" +
	"  issuer: \"https://auth.example.com\"\n" +
	"  security:\n" +
	"    admin_password_hash: \"" + testAdminHash + "\"\n"

// TestValidateConfigComposition verifies the multi-file configuration
// pipeline: directory and recursive-glob selectors compose their YAML
// sources deterministically, both extensions are accepted, and a
// conflicting duplicate value fails validation.
func TestValidateConfigComposition(t *testing.T) {
	t.Run("composes the yaml and yml files of a directory", func(t *testing.T) {
		dir := t.TempDir()
		writeCompositionFile(t, filepath.Join(dir, "10-instance.yaml"),
			compositionInstance+
				"users:\n"+
				"  - sub: alice\n",
		)
		writeCompositionFile(t, filepath.Join(dir, "20-override.yml"),
			"config:\n"+
				"  ui:\n"+
				"    name: \"Composed\"\n"+
				"clients:\n"+
				"  - id: app\n"+
				"    redirect_uris:\n"+
				"      - \"http://127.0.0.1:9999/callback\"\n",
		)

		stdout, _, code := harness.Run(t,
			[]string{"ZEN_IDP_CONFIG_PATH=" + dir},
			"validate-config",
		)
		require.Equal(t, 0, code)
		require.Contains(t, stdout, "configuration is valid")
	})

	t.Run("a conflicting duplicate value fails composition", func(t *testing.T) {
		dir := t.TempDir()
		writeCompositionFile(t, filepath.Join(dir, "10-instance.yaml"),
			compositionInstance,
		)
		writeCompositionFile(t, filepath.Join(dir, "30-conflict.yaml"),
			"config:\n"+
				"  issuer: \"https://other.example.com\"\n",
		)

		_, stderr, code := harness.Run(t,
			[]string{"ZEN_IDP_CONFIG_PATH=" + dir},
			"validate-config",
		)
		require.Equal(t, 1, code)
		require.Contains(t, stderr, "config.issuer")
	})

	t.Run("composes recursive glob selectors across depths", func(t *testing.T) {
		root := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(root, "nested", "deep"), 0o700))
		writeCompositionFile(t, filepath.Join(root, "instance.yaml"),
			compositionInstance,
		)
		writeCompositionFile(t, filepath.Join(root, "nested", "users.yaml"),
			"users:\n"+
				"  - sub: alice\n",
		)
		writeCompositionFile(t, filepath.Join(root, "nested", "deep", "clients.yaml"),
			"clients:\n"+
				"  - id: app\n"+
				"    redirect_uris:\n"+
				"      - \"http://127.0.0.1:9999/callback\"\n",
		)
		// A .yml sibling is deliberately excluded by the yaml-only glob.
		writeCompositionFile(t, filepath.Join(root, "nested", "deep", "ignored.yml"),
			"config:\n"+
				"  ui:\n"+
				"    name: \"Ignored\"\n",
		)

		selector := filepath.Join(root, "**", "*.yaml")
		stdout, _, code := harness.Run(t,
			[]string{"ZEN_IDP_CONFIG_PATH=" + selector},
			"validate-config",
		)
		require.Equal(t, 0, code)
		require.Contains(t, stdout, "configuration is valid")
	})
}

// TestBootstrapWithGeneratedSecrets closes the bootstrap loop: a server
// configured with the exact bundle printed by generate-secrets accepts the
// generated administrator credential.
func TestBootstrapWithGeneratedSecrets(t *testing.T) {
	stdout, _, code := harness.Run(t, nil, "generate-secrets")
	require.Equal(t, 0, code)

	root := regexp.MustCompile(`ZEN_IDP_SECRET=([0-9a-zA-Z]+)`).FindStringSubmatch(stdout)
	require.Len(t, root, 2)
	adminPlain := regexp.MustCompile(`(?m)^plain: ([0-9a-zA-Z]+)$`).FindStringSubmatch(stdout)
	require.Len(t, adminPlain, 2)
	adminHash := regexp.MustCompile(`(?m)^hash: "([^"]+)"$`).FindStringSubmatch(stdout)
	require.Len(t, adminHash, 2)

	// A server bootstrapped with the generated bundle accepts the
	// generated administrator credential.
	app := harness.New(t, harness.Config{
		RootSecret: root[1],
		AdminHash:  adminHash[1],
		Users:      []harness.User{{Sub: "alice"}},
		Clients: []harness.Client{{ID: "app", RedirectURIs: []string{
			"http://127.0.0.1:9999/callback",
		}}},
	})
	c := app.Browser()
	form := c.Get(t, "/admin")
	form.RequireStatus(t, 200)
	csrf := harness.FormValue(form.Body, "csrf_token")
	require.NotEmpty(t, csrf)
	response := c.PostForm(t, "/admin/login", url.Values{
		"password":   {adminPlain[1]},
		"csrf_token": {csrf},
	})
	response.RequireStatus(t, 303)
	require.True(t, strings.HasPrefix(c.Cookie("zen_idp_admin_session"), "sess_"))
}

// TestEnvFileExplicit verifies that an environment file is loaded only when
// serve or validate-config explicitly receives --env-file, that
// process-environment values take precedence by presence, and that a .env
// file is never loaded implicitly.
func TestEnvFileExplicit(t *testing.T) {
	dir := t.TempDir()
	configPath := (harness.Config{
		AdminHash: testAdminHash,
	}).WriteFile(t, dir, "https://auth.example.com", 8080)
	envFile := filepath.Join(dir, "instance.env")
	require.NoError(t, os.WriteFile(
		envFile,
		[]byte("ZEN_IDP_CONFIG_PATH="+configPath+"\n"),
		0o600,
	))

	// The explicitly selected env file satisfies validate-config alone.
	stdout, _, code := harness.Run(t, nil, "validate-config", "--env-file", envFile)
	require.Equal(t, 0, code)
	require.Contains(t, stdout, "configuration is valid")

	// Process-environment values take precedence by presence, even when
	// the env file carries a valid value.
	_, stderr, code := harness.Run(t,
		[]string{"ZEN_IDP_CONFIG_PATH=" + filepath.Join(dir, "missing.yaml")},
		"validate-config", "--env-file", envFile,
	)
	require.Equal(t, 1, code)
	require.Contains(t, stderr, "missing.yaml")

	// An empty process value also takes precedence and fails validation.
	_, stderr, code = harness.Run(t,
		[]string{"ZEN_IDP_CONFIG_PATH="},
		"validate-config", "--env-file", envFile,
	)
	require.Equal(t, 1, code)
	require.Contains(t, stderr, "ZEN_IDP_CONFIG_PATH")

	// A .env file in the working directory is never loaded implicitly:
	// without --env-file the variable stays absent.
	t.Chdir(dir)
	_, stderr, code = harness.Run(t, nil, "validate-config")
	require.Equal(t, 1, code)
	require.Contains(t, stderr, "ZEN_IDP_CONFIG_PATH")

	// serve also honors --env-file: the database path it carries reaches
	// the startup validation and fails on the exact configured location.
	badDB := filepath.Join(dir, "no-such-dir", "state.db")
	require.NoError(t, os.WriteFile(
		envFile,
		[]byte(
			"ZEN_IDP_CONFIG_PATH="+configPath+"\n"+
				"ZEN_IDP_SECRET="+testRootSecret+"\n"+
				"ZEN_IDP_DB_PATH="+badDB+"\n",
		),
		0o600,
	))
	_, stderr, code = harness.Run(t, nil, "serve", "--env-file", envFile)
	require.Equal(t, 1, code)
	require.Contains(t, stderr, badDB)
}
