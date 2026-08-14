//go:build e2e

package harness

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

// buildTimeout bounds how long the one-time binary build may take.
const buildTimeout = 5 * time.Minute

// binaryPath is the compiled zen-idp executable shared by the whole suite.
var (
	buildOnce sync.Once
	builtPath string
	buildErr  error
)

// moduleRoot returns the repository root that contains this package, derived
// from the compiled location of this source file.
func moduleRoot() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		panic("harness: locate module root")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

// buildBinary compiles the zen-idp executable once per test run and returns
// its path. Concurrent callers share the same build.
func buildBinary() (string, error) {
	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "zen-idp-e2e-*")
		if err != nil {
			buildErr = fmt.Errorf("create e2e binary directory: %w", err)
			return
		}
		builtPath = filepath.Join(dir, "zen-idp")
		ctx, cancel := context.WithTimeout(context.Background(), buildTimeout)
		defer cancel()
		cmd := exec.CommandContext(ctx, "go", "build", "-o", builtPath, "./cmd/zen-idp")
		cmd.Dir = moduleRoot()
		if output, err := cmd.CombinedOutput(); err != nil {
			buildErr = fmt.Errorf("build zen-idp binary: %w: %s", err, output)
			builtPath = ""
		}
	})
	return builtPath, buildErr
}

// BinaryPath returns the path of the compiled zen-idp executable, building
// it on first use.
func BinaryPath(t *testing.T) string {
	t.Helper()
	path, err := buildBinary()
	if err != nil {
		t.Fatal(err)
	}
	return path
}

// Cleanup removes the shared compiled binary and must run after the last
// test of the suite finishes.
func Cleanup() {
	if builtPath != "" {
		_ = os.RemoveAll(filepath.Dir(builtPath))
	}
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
