package configloader

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

const instanceYAML = `
config:
  issuer: https://auth.example.com
  security:
    admin_password_hash: "$argon2id$v=19$m=19456,t=2,p=1$YWRtaW5TYWx0$MDEyMzQ1Njc4OWFiY2RlZg"
`

func TestLoad(t *testing.T) {
	t.Run("composes files in deterministic path order", func(t *testing.T) {
		directory := t.TempDir()
		writeConfigFile(t, filepath.Join(directory, "20-second.yaml"), "users:\n  - sub: second\n")
		writeConfigFile(t, filepath.Join(directory, "10-first.yaml"), "users:\n  - sub: first\n")
		writeConfigFile(t, filepath.Join(directory, "00-instance.yaml"), instanceYAML)

		configuration, err := Load(directory)
		require.NoError(t, err)
		require.Len(t, configuration.Users, 2)
		require.Equal(t, "first", configuration.Users[0].Subject)
		require.Equal(t, "second", configuration.Users[1].Subject)
	})

	t.Run("loads a relative glob selector", func(t *testing.T) {
		root := t.TempDir()
		writeConfigFile(t, filepath.Join(root, "config", "instance.yaml"), instanceYAML)
		t.Chdir(root)

		configuration, err := Load(filepath.Join("config", "**", "*.yaml"))
		require.NoError(t, err)
		require.Equal(t, "https://auth.example.com", configuration.Issuer)
	})

	t.Run("identifies the file that introduces a merge conflict", func(t *testing.T) {
		directory := t.TempDir()
		writeConfigFile(
			t,
			filepath.Join(directory, "00-first.yaml"),
			"config:\n  issuer: https://first.example.com\n",
		)
		writeConfigFile(
			t,
			filepath.Join(directory, "10-second.yaml"),
			"config:\n  issuer: https://second.example.com\n",
		)

		configuration, err := Load(directory)

		require.Nil(t, configuration)
		require.ErrorContains(t, err, "10-second.yaml")
		require.ErrorContains(t, err, "merge configuration file")
	})

	tests := map[string]struct {
		content   string
		errorText string
	}{
		"empty document": {
			content:   "",
			errorText: "decode configuration file",
		},
		"non-mapping root": {
			content:   "- item\n",
			errorText: "root must be a mapping",
		},
		"multiple documents": {
			content:   "config: {}\n---\nusers: []\n",
			errorText: "multiple YAML documents",
		},
		"malformed document": {
			content:   "config: [\n",
			errorText: "decode configuration file",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			filePath := filepath.Join(t.TempDir(), "broken.yaml")
			writeConfigFile(t, filePath, test.content)

			configuration, err := Load(filePath)

			require.Nil(t, configuration)
			require.ErrorContains(t, err, test.errorText)
			require.ErrorContains(t, err, "broken.yaml")
		})
	}
}

func writeConfigFile(t *testing.T, filePath, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(filePath), 0o700))
	require.NoError(t, os.WriteFile(filePath, []byte(content), 0o600))
}
