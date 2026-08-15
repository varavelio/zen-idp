//go:build e2e

package e2e

import (
	"os"
	"testing"

	"github.com/varavelio/zen-idp/e2e/http/harness"
)

// TestMain runs the whole suite and then removes the compiled binary shared
// by every test.
func TestMain(m *testing.M) {
	code := m.Run()
	harness.Cleanup()
	os.Exit(code)
}
