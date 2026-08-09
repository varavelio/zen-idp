package runtimeconfig

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const validSecret = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"

func TestLoad(t *testing.T) {
	t.Run("loads and validates the process environment", func(t *testing.T) {
		stateDBPath := filepath.Join(t.TempDir(), "zen-idp.db")
		setRuntimeEnvironment(t, "config", validSecret, stateDBPath)

		configuration, err := Load("")
		require.NoError(t, err)
		require.Equal(t, "config", configuration.ConfigPath)
		require.Equal(t, sha256.Sum256([]byte(validSecret)), configuration.RootSecret)
		require.Equal(t, stateDBPath, configuration.StateDBPath)
		require.FileExists(t, stateDBPath)
	})

	t.Run("parses quoted dotenv values", func(t *testing.T) {
		unsetRuntimeEnvironment(t)
		directory := filepath.Join(t.TempDir(), "state directory")
		require.NoError(t, os.Mkdir(directory, 0o700))
		stateDBPath := filepath.Join(directory, "zen idp.db")
		envFile := filepath.Join(t.TempDir(), "runtime.env")
		contents := configPathVariable + "=\"dotenv config\"\n" +
			secretVariable + "='" + validSecret + "'\n" +
			stateDBPathVariable + "=\"" + stateDBPath + "\"\n"
		require.NoError(t, os.WriteFile(envFile, []byte(contents), 0o600))

		configuration, err := Load(envFile)
		require.NoError(t, err)
		require.Equal(t, "dotenv config", configuration.ConfigPath)
		require.Equal(t, stateDBPath, configuration.StateDBPath)
		for _, name := range runtimeVariableNames {
			_, exists := os.LookupEnv(name)
			require.False(t, exists)
		}
	})

	t.Run("process values override the dotenv file", func(t *testing.T) {
		stateDBPath := filepath.Join(t.TempDir(), "zen-idp.db")
		setRuntimeEnvironment(t, "runtime/config", validSecret, stateDBPath)
		envFile := writeEnvFile(
			t,
			"dotenv/config",
			strings.Repeat("X", minimumSecretCharacterCount),
			"dotenv/state.db",
		)

		configuration, err := Load(envFile)
		require.NoError(t, err)
		require.Equal(t, "runtime/config", configuration.ConfigPath)
		require.Equal(t, sha256.Sum256([]byte(validSecret)), configuration.RootSecret)
		require.Equal(t, stateDBPath, configuration.StateDBPath)
	})

	emptyOverrides := map[string]struct {
		name      string
		errorText string
	}{
		"config path": {
			name:      configPathVariable,
			errorText: configPathVariable + " must not be blank",
		},
		"secret": {name: secretVariable, errorText: secretVariable},
		"database path": {
			name:      stateDBPathVariable,
			errorText: stateDBPathVariable + " must not be blank",
		},
	}
	for name, test := range emptyOverrides {
		t.Run("empty process "+name+" overrides dotenv", func(t *testing.T) {
			unsetRuntimeEnvironment(t)
			t.Setenv(test.name, "")
			envFile := writeEnvFile(
				t,
				"config",
				validSecret,
				filepath.Join(t.TempDir(), "state.db"),
			)

			configuration, err := Load(envFile)

			require.Empty(t, configuration)
			require.ErrorContains(t, err, test.errorText)
		})
	}

	t.Run("does not load dot env implicitly", func(t *testing.T) {
		unsetRuntimeEnvironment(t)
		t.Chdir(t.TempDir())
		_ = writeEnvFileAt(t, ".env", "config", validSecret, "state.db")

		configuration, err := Load("")

		require.Empty(t, configuration)
		require.ErrorContains(t, err, configPathVariable)
	})

	t.Run("counts Unicode secret characters", func(t *testing.T) {
		secret := strings.Repeat("á", minimumSecretCharacterCount)
		stateDBPath := filepath.Join(t.TempDir(), "zen-idp.db")
		setRuntimeEnvironment(t, "config", secret, stateDBPath)

		configuration, err := Load("")
		require.NoError(t, err)
		require.Equal(t, sha256.Sum256([]byte(secret)), configuration.RootSecret)
	})

	t.Run("rejects a short root secret", func(t *testing.T) {
		setRuntimeEnvironment(
			t,
			"config",
			strings.Repeat("X", minimumSecretCharacterCount-1),
			filepath.Join(t.TempDir(), "state.db"),
		)

		configuration, err := Load("")

		require.Empty(t, configuration)
		require.ErrorContains(t, err, "at least 32 valid UTF-8 characters")
	})

	t.Run("rejects invalid UTF-8 root secrets", func(t *testing.T) {
		setRuntimeEnvironment(
			t,
			"config",
			strings.Repeat("X", minimumSecretCharacterCount)+"\xff",
			filepath.Join(t.TempDir(), "state.db"),
		)

		configuration, err := Load("")

		require.Empty(t, configuration)
		require.ErrorContains(t, err, secretVariable)
	})

	t.Run("opens an existing database file", func(t *testing.T) {
		stateDBPath := filepath.Join(t.TempDir(), "state.db")
		require.NoError(t, os.WriteFile(stateDBPath, nil, 0o600))
		setRuntimeEnvironment(t, "config", validSecret, stateDBPath)

		configuration, err := Load("")
		require.NoError(t, err)
		require.Equal(t, stateDBPath, configuration.StateDBPath)
	})

	databaseErrors := map[string]struct {
		path      func(t *testing.T) string
		errorText string
	}{
		"missing parent": {
			path:      func(t *testing.T) string { return filepath.Join(t.TempDir(), "missing", "state.db") },
			errorText: stateDBPathVariable,
		},
		"invalid filename": {
			path: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), strings.Repeat("x", 300))
			},
			errorText: stateDBPathVariable,
		},
		"directory": {
			path:      func(t *testing.T) string { return t.TempDir() },
			errorText: "must identify a regular file",
		},
		"broad permissions": {
			path: func(t *testing.T) string {
				stateDBPath := filepath.Join(t.TempDir(), "state.db")
				require.NoError(t, os.WriteFile(stateDBPath, nil, 0o600))
				require.NoError(t, os.Chmod(stateDBPath, 0o644))
				return stateDBPath
			},
			errorText: "must not grant group or world permissions",
		},
		"dangling symlink": {
			path: func(t *testing.T) string {
				directory := t.TempDir()
				stateDBPath := filepath.Join(directory, "state.db")
				if err := os.Symlink(
					filepath.Join(directory, "missing.db"),
					stateDBPath,
				); err != nil {
					t.Skipf("cannot create symlink: %v", err)
				}
				return stateDBPath
			},
			errorText: "cannot be created",
		},
	}
	for name, test := range databaseErrors {
		t.Run("rejects database "+name, func(t *testing.T) {
			setRuntimeEnvironment(t, "config", validSecret, test.path(t))

			configuration, err := Load("")

			require.Empty(t, configuration)
			require.ErrorContains(t, err, test.errorText)
		})
	}

	t.Run("returns selected dotenv file errors", func(t *testing.T) {
		unsetRuntimeEnvironment(t)

		configuration, err := Load(filepath.Join(t.TempDir(), "missing.env"))

		require.Empty(t, configuration)
		require.ErrorContains(t, err, "load env file")
	})

	t.Run("returns malformed dotenv file errors", func(t *testing.T) {
		unsetRuntimeEnvironment(t)
		envFile := filepath.Join(t.TempDir(), "broken.env")
		require.NoError(t, os.WriteFile(envFile, []byte("BROKEN='unterminated\n"), 0o600))

		configuration, err := Load(envFile)

		require.Empty(t, configuration)
		require.ErrorContains(t, err, "load env file")
	})
}

func TestLoadConfigPath(t *testing.T) {
	t.Run("requires only the config path", func(t *testing.T) {
		unsetRuntimeEnvironment(t)
		t.Setenv(configPathVariable, "config/**/*.yaml")

		configPath, err := LoadConfigPath("")
		require.NoError(t, err)
		require.Equal(t, "config/**/*.yaml", configPath)
	})

	t.Run("parses a quoted config path from dotenv", func(t *testing.T) {
		unsetRuntimeEnvironment(t)
		envFile := filepath.Join(t.TempDir(), "runtime.env")
		require.NoError(t, os.WriteFile(
			envFile,
			[]byte(configPathVariable+"=\"config directory\"\n"),
			0o600,
		))

		configPath, err := LoadConfigPath(envFile)
		require.NoError(t, err)
		require.Equal(t, "config directory", configPath)
	})

	t.Run("empty process value overrides dotenv", func(t *testing.T) {
		unsetRuntimeEnvironment(t)
		t.Setenv(configPathVariable, "")
		envFile := writeEnvFile(t, "config", "", "")

		configPath, err := LoadConfigPath(envFile)

		require.Empty(t, configPath)
		require.ErrorContains(t, err, configPathVariable+" must not be blank")
	})
}

var runtimeVariableNames = [...]string{configPathVariable, secretVariable, stateDBPathVariable}

func setRuntimeEnvironment(t *testing.T, configPath, secret, stateDBPath string) {
	t.Helper()
	t.Setenv(configPathVariable, configPath)
	t.Setenv(secretVariable, secret)
	t.Setenv(stateDBPathVariable, stateDBPath)
}

func unsetRuntimeEnvironment(t *testing.T) {
	t.Helper()
	for _, name := range runtimeVariableNames {
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
}

func writeEnvFile(t *testing.T, configPath, secret, stateDBPath string) string {
	t.Helper()
	return writeEnvFileAt(
		t,
		filepath.Join(t.TempDir(), "runtime.env"),
		configPath,
		secret,
		stateDBPath,
	)
}

func writeEnvFileAt(t *testing.T, path, configPath, secret, stateDBPath string) string {
	t.Helper()
	contents := configPathVariable + "=" + configPath + "\n" +
		secretVariable + "=" + secret + "\n" +
		stateDBPathVariable + "=" + stateDBPath + "\n"
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
	return path
}
