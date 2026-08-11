package main

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRunGenerateSecrets(t *testing.T) {
	t.Run("writes the complete secret bundle to stdout", func(t *testing.T) {
		dependencies := testDependencies(t)
		var stdout bytes.Buffer
		var stderr bytes.Buffer

		exitCode := run([]string{"generate-secrets"}, &stdout, &stderr, dependencies)

		require.Zero(t, exitCode)
		require.Empty(t, stderr.String())
		output := stdout.String()
		require.Contains(t, output, "Root secret\nZEN_IDP_SECRET=ROOT")
		require.Contains(t, output, "Administrator\nplain: ADMIN\nhash: \"ADMIN_HASH\"")
		require.Contains(t, output, "OIDC client\nplain: CLIENT\nhash: \"CLIENT_HASH\"")
	})
}
