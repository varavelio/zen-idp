//go:build e2e

package harness

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// readinessTimeout bounds how long a spawned server may take to answer its
// first discovery request.
const readinessTimeout = 15 * time.Second

// shutdownTimeout bounds how long a stopped server may take to exit after
// its termination signal before it is killed.
const shutdownTimeout = 10 * time.Second

// Harness drives one isolated black-box Zen IdP instance for a single test:
// a dedicated configuration and state database in a per-test directory, one
// loopback port, and one spawned server process.
type Harness struct {
	dir     string
	baseURL string
	cmd     *exec.Cmd
	logFile *os.File
	browser *Browser
	cfg     Config
}

// New starts a fresh Zen IdP instance for one test: it validates and writes
// the YAML configuration of cfg into a per-test directory, binds a free
// loopback port, spawns the compiled executable with the matching
// environment, and waits until the discovery endpoint answers. It registers
// the teardown that stops the server when the test finishes.
func New(t *testing.T, cfg Config) *Harness {
	t.Helper()
	cfg.validate(t)

	dir := t.TempDir()
	port := freePort(t)
	issuer := fmt.Sprintf("http://127.0.0.1:%d", port)
	cfg.WriteFile(t, dir, issuer, port)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	origin, err := url.Parse(issuer)
	if err != nil {
		t.Fatal(err)
	}
	harness := &Harness{
		dir:     dir,
		baseURL: issuer,
		cfg:     cfg,
	}
	harness.browser = &Browser{
		http: &http.Client{
			Jar: jar,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		jar:    jar,
		origin: origin,
	}
	harness.start(t)
	t.Cleanup(func() { harness.stop(t) })
	return harness
}

// Browser returns the HTTP client of this harness. Its cookie jar is
// created once and shared across restarts, so browser state observed before
// a restart survives it.
func (h *Harness) Browser() *Browser {
	return h.browser
}

// BaseURL returns the issuer origin of this harness.
func (h *Harness) BaseURL() string {
	return h.baseURL
}

// Restart stops the server and starts it again with the same configuration
// and state database, simulating an ordinary service restart.
func (h *Harness) Restart(t *testing.T) {
	t.Helper()
	h.stop(t)
	h.start(t)
}

// start spawns the server with this harness's configuration and waits until
// it is ready, failing the test when the server cannot start or does not
// become ready in time.
func (h *Harness) start(t *testing.T) {
	t.Helper()
	logFile, err := os.Create(filepath.Join(h.dir, "server.log"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), BinaryPath(t), "serve")
	cmd.Dir = h.dir
	cmd.Env = append(os.Environ(),
		"ZEN_IDP_CONFIG_PATH="+filepath.Join(h.dir, "config.yaml"),
		"ZEN_IDP_SECRET="+h.cfg.RootSecret,
		"ZEN_IDP_DB_PATH="+filepath.Join(h.dir, "state.db"),
	)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		t.Fatal(err)
	}
	h.cmd = cmd
	h.logFile = logFile
	if !waitReady(t, h.baseURL) {
		t.Fatalf("server did not become ready:\n%s", h.serverLog())
	}
}

// stop terminates the server gracefully and waits for it to exit, killing
// it when it does not stop in time. It reports the server's own output when
// the surrounding test failed, so failures can be diagnosed from the
// process side.
func (h *Harness) stop(t *testing.T) {
	t.Helper()
	if h.cmd == nil {
		return
	}
	_ = h.cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan error, 1)
	go func() { done <- h.cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(shutdownTimeout):
		_ = h.cmd.Process.Kill()
		<-done
	}
	h.cmd = nil
	if t.Failed() {
		t.Logf("server output:\n%s", h.serverLog())
	}
	_ = h.logFile.Close()
	h.logFile = nil
}

// serverLog returns the captured output of the server process.
func (h *Harness) serverLog() string {
	contents, err := os.ReadFile(filepath.Join(h.dir, "server.log"))
	if err != nil {
		return fmt.Sprintf("(read server log: %v)", err)
	}
	return string(contents)
}

// freePort returns a free loopback TCP port for the server to bind.
func freePort(t *testing.T) int {
	t.Helper()
	var listenConfig net.ListenConfig
	listener, err := listenConfig.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

// waitReady polls the discovery endpoint until it answers with 200 or the
// readiness timeout elapses.
func waitReady(t *testing.T, baseURL string) bool {
	t.Helper()
	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(readinessTimeout)
	for time.Now().Before(deadline) {
		ready, err := probeReady(client, baseURL)
		if err == nil && ready {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

// probeReady reports whether the discovery endpoint of the given origin
// answers with 200.
func probeReady(client *http.Client, baseURL string) (bool, error) {
	request, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		baseURL+"/.well-known/openid-configuration",
		nil,
	)
	if err != nil {
		return false, err
	}
	response, err := client.Do(request)
	if err != nil {
		return false, err
	}
	defer func() { _ = response.Body.Close() }()
	return response.StatusCode == http.StatusOK, nil
}
