package main

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/varavelio/zen-idp/internal/config"
	"github.com/varavelio/zen-idp/internal/runtimeconfig"
)

func TestRunValidateConfig(t *testing.T) {
	t.Run("validates configuration without loading full runtime", func(t *testing.T) {
		dependencies := testDependencies(t)
		dependencies.loadRuntime = func(string) (runtimeconfig.RuntimeConfig, error) {
			t.Fatal("full runtime must not be loaded")
			return runtimeconfig.RuntimeConfig{}, nil
		}
		dependencies.loadConfigPath = func(envFile string) (string, error) {
			require.Equal(t, "runtime.env", envFile)
			return "config", nil
		}
		var selected string
		dependencies.loadConfiguration = func(selector string) (*config.Config, error) {
			selected = selector
			return nil, nil
		}
		var stdout bytes.Buffer
		var stderr bytes.Buffer

		exitCode := run(
			[]string{"validate-config", "--env-file", "runtime.env"},
			&stdout,
			&stderr,
			dependencies,
		)

		require.Zero(t, exitCode)
		require.Equal(t, "config", selected)
		require.Equal(t, "configuration is valid\n", stdout.String())
		require.Empty(t, stderr.String())
	})

	t.Run("reports environment failures", func(t *testing.T) {
		dependencies := testDependencies(t)
		dependencies.loadConfigPath = func(string) (string, error) {
			return "", errors.New("environment unavailable")
		}
		var stdout bytes.Buffer
		var stderr bytes.Buffer

		exitCode := run([]string{"validate-config"}, &stdout, &stderr, dependencies)

		require.Equal(t, 1, exitCode)
		require.Contains(t, stderr.String(), "environment unavailable")
	})
}
