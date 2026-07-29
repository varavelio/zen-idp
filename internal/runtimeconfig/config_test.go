package runtimeconfig

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const validSecret = "0123456789abcdef0123456789abcdef"

func TestLoad(t *testing.T) {
	t.Run("loads process environment variables", func(t *testing.T) {
		t.Chdir(t.TempDir())
		t.Setenv("ZEN_IDP_SECRET", validSecret)
		t.Setenv("ZEN_IDP_DB_PATH", "state/zen-idp.db")

		configuration, err := Load()
		require.NoError(t, err)

		require.Equal(t, sha256.Sum256([]byte(validSecret)), configuration.RootSecret)
		require.Equal(t, "state/zen-idp.db", configuration.StateDBPath)
	})

	t.Run("loads values from dotenv", func(t *testing.T) {
		t.Chdir(t.TempDir())
		unsetEnvironment(t, "ZEN_IDP_SECRET")
		unsetEnvironment(t, "ZEN_IDP_DB_PATH")
		writeDotEnv(t, validSecret, "dotenv/state.db")

		configuration, err := Load()
		require.NoError(t, err)

		require.Equal(t, sha256.Sum256([]byte(validSecret)), configuration.RootSecret)
		require.Equal(t, "dotenv/state.db", configuration.StateDBPath)
	})

	t.Run("process environment overrides dotenv", func(t *testing.T) {
		t.Chdir(t.TempDir())
		t.Setenv("ZEN_IDP_SECRET", validSecret)
		t.Setenv("ZEN_IDP_DB_PATH", "runtime/state.db")
		writeDotEnv(t, strings.Repeat("x", 32), "dotenv/state.db")

		configuration, err := Load()
		require.NoError(t, err)

		require.Equal(t, sha256.Sum256([]byte(validSecret)), configuration.RootSecret)
		require.Equal(t, "runtime/state.db", configuration.StateDBPath)
	})
}

func TestParseEnvironment(t *testing.T) {
	t.Run("hashes a secret with the minimum character count", func(t *testing.T) {
		configuration, err := parseEnvironment(validEnvironment(validSecret))
		require.NoError(t, err)

		require.Equal(t, sha256.Sum256([]byte(validSecret)), configuration.RootSecret)
	})

	t.Run("accepts secrets longer than the minimum", func(t *testing.T) {
		secret := strings.Repeat("long-secret-", 4)

		configuration, err := parseEnvironment(validEnvironment(secret))
		require.NoError(t, err)
		require.Equal(t, sha256.Sum256([]byte(secret)), configuration.RootSecret)
	})

	t.Run("counts Unicode characters rather than bytes", func(t *testing.T) {
		secret := strings.Repeat("á", minimumSecretCharacterCount)

		configuration, err := parseEnvironment(validEnvironment(secret))
		require.NoError(t, err)
		require.Equal(t, sha256.Sum256([]byte(secret)), configuration.RootSecret)
	})

	t.Run("requires every runtime variable", func(t *testing.T) {
		configuration, err := parseEnvironment(map[string]string{})

		require.Empty(t, configuration)
		require.ErrorContains(t, err, "ZEN_IDP_SECRET")
		require.ErrorContains(t, err, "ZEN_IDP_DB_PATH")
	})

	t.Run("rejects secrets shorter than 32 characters", func(t *testing.T) {
		configuration, err := parseEnvironment(validEnvironment(strings.Repeat("x", 31)))

		require.Empty(t, configuration)
		require.ErrorContains(t, err, "at least 32 valid UTF-8 characters")
		require.ErrorContains(t, err, "https://zen-idp.varavel.com/secret-generator")
	})

	t.Run("rejects invalid UTF-8 secrets", func(t *testing.T) {
		configuration, err := parseEnvironment(validEnvironment(strings.Repeat("x", 32) + "\xff"))

		require.Empty(t, configuration)
		require.ErrorContains(t, err, "at least 32 valid UTF-8 characters")
	})

	t.Run("rejects a blank state database path", func(t *testing.T) {
		values := validEnvironment(validSecret)
		values["ZEN_IDP_DB_PATH"] = "   "

		configuration, err := parseEnvironment(values)

		require.Empty(t, configuration)
		require.ErrorContains(t, err, "ZEN_IDP_DB_PATH must not be blank")
	})

	t.Run("rejects null bytes in the state database path", func(t *testing.T) {
		values := validEnvironment(validSecret)
		values["ZEN_IDP_DB_PATH"] = "state\x00.db"

		configuration, err := parseEnvironment(values)

		require.Empty(t, configuration)
		require.ErrorContains(t, err, "ZEN_IDP_DB_PATH must not contain null bytes")
	})
}

func TestLoadDotEnvIfPresent(t *testing.T) {
	t.Run("ignores a missing file", func(t *testing.T) {
		t.Chdir(t.TempDir())

		require.NoError(t, loadDotEnvIfPresent())
	})

	t.Run("returns malformed dotenv errors", func(t *testing.T) {
		t.Chdir(t.TempDir())
		require.NoError(t, os.WriteFile(dotEnvPath, []byte("BROKEN='unterminated\n"), 0o600))

		err := loadDotEnvIfPresent()

		require.ErrorContains(t, err, "load "+dotEnvPath+" file")
	})
}

func validEnvironment(secret string) map[string]string {
	return map[string]string{
		"ZEN_IDP_SECRET":  secret,
		"ZEN_IDP_DB_PATH": "state/zen-idp.db",
	}
}

func writeDotEnv(t *testing.T, secret, stateDBPath string) {
	t.Helper()

	contents := "ZEN_IDP_SECRET=" + secret +
		"\nZEN_IDP_DB_PATH=" + stateDBPath + "\n"
	require.NoError(t, os.WriteFile(filepath.Join(".", dotEnvPath), []byte(contents), 0o600))
}

func unsetEnvironment(t *testing.T, name string) {
	t.Helper()

	previous, existed := os.LookupEnv(name)
	require.NoError(t, os.Unsetenv(name))
	t.Cleanup(func() {
		if existed {
			require.NoError(t, os.Setenv(name, previous))
			return
		}
		require.NoError(t, os.Unsetenv(name))
	})
}
