//go:build e2e

package harness

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"testing"
)

// binaryPath is the compiled zen-idp executable used by the whole suite. It
// is hardcoded because the suite always runs inside the devcontainer, where
// the e2e task builds the binary to this exact location before running the
// tests, so the harness never compiles it itself.
const binaryPath = "/workspaces/zen-idp/dist/zen-idp"

// BinaryPath returns the path of the compiled zen-idp executable, failing
// the test when the pre-built binary is missing.
func BinaryPath(t *testing.T) string {
	t.Helper()
	if _, err := os.Stat(binaryPath); err != nil {
		t.Fatalf(
			"harness: compiled binary not found at %s (run `task build` first): %v",
			binaryPath, err,
		)
	}
	return binaryPath
}

// Run executes the compiled binary with the given environment additions and
// command-line arguments, returning its separate standard output, standard
// error, and exit code. It fails the test when the process cannot start.
func Run(t *testing.T, env []string, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), BinaryPath(t), args...)
	cmd.Env = append(os.Environ(), env...)
	var stdoutBuffer, stderrBuffer bytes.Buffer
	cmd.Stdout = &stdoutBuffer
	cmd.Stderr = &stderrBuffer
	err := cmd.Run()
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("run %v: %v", args, err)
		}
		exitCode = exitErr.ExitCode()
	}
	return stdoutBuffer.String(), stderrBuffer.String(), exitCode
}
