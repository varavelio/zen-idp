package cli

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	t.Run("parses help requests", func(t *testing.T) {
		for _, args := range [][]string{
			{"help"},
			{"--help"},
			{"-h"},
			{"serve", "--help"},
			{"serve", "-h"},
			{"validate-config", "--help"},
			{"generate-secrets", "--help"},
		} {
			invocation, err := Parse(args)
			require.NoError(t, err, "args: %v", args)
			require.Equal(t, Help, invocation.Command, "args: %v", args)
		}
	})

	t.Run("parses serve invocations", func(t *testing.T) {
		invocation, err := Parse([]string{"serve"})
		require.NoError(t, err)
		require.Equal(t, Serve, invocation.Command)
		require.Empty(t, invocation.EnvFile)

		invocation, err = Parse([]string{"serve", "--env-file", "runtime.env"})
		require.NoError(t, err)
		require.Equal(t, Serve, invocation.Command)
		require.Equal(t, "runtime.env", invocation.EnvFile)
	})

	t.Run("parses validate-config invocations", func(t *testing.T) {
		invocation, err := Parse([]string{"validate-config", "--env-file=runtime.env"})
		require.NoError(t, err)
		require.Equal(t, ValidateConfig, invocation.Command)
		require.Equal(t, "runtime.env", invocation.EnvFile)

		invocation, err = Parse([]string{"validate-config"})
		require.NoError(t, err)
		require.Equal(t, ValidateConfig, invocation.Command)
		require.Empty(t, invocation.EnvFile)
	})

	t.Run("parses generate-secrets invocations", func(t *testing.T) {
		invocation, err := Parse([]string{"generate-secrets"})
		require.NoError(t, err)
		require.Equal(t, GenerateSecrets, invocation.Command)
		require.Empty(t, invocation.EnvFile)
	})

	t.Run("rejects malformed invocations", func(t *testing.T) {
		tests := map[string][]string{
			"no arguments":               {},
			"unknown command":            {"unknown"},
			"serve unknown flag":         {"serve", "--unknown"},
			"serve empty env file":       {"serve", "--env-file="},
			"serve positional argument":  {"serve", "extra"},
			"validate-config positional": {"validate-config", "extra"},
			"generate-secrets argument":  {"generate-secrets", "extra"},
			"generate-secrets env flag":  {"generate-secrets", "--env-file", "x"},
			"serve help with extra args": {"serve", "--help", "extra"},
			"empty env file with spaces": {"validate-config", "--env-file=  "},
		}
		for name, args := range tests {
			t.Run(name, func(t *testing.T) {
				_, err := Parse(args)

				require.Error(t, err)
				var usageErr *UsageError
				require.ErrorAs(t, err, &usageErr)
				require.Contains(t, usageErr.Error(), usage)
			})
		}
	})
}

func TestUsage(t *testing.T) {
	t.Run("describes every command", func(t *testing.T) {
		text := Usage()

		require.Contains(t, text, "zen-idp serve")
		require.Contains(t, text, "zen-idp validate-config")
		require.Contains(t, text, "zen-idp generate-secrets")
	})
}
