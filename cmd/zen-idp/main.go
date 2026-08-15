// Command zen-idp is the Zen IdP executable: a declarative, zero-maintenance
// OIDC Identity Provider.
package main

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/varavelio/zen-idp/internal/cli"
	"github.com/varavelio/zen-idp/internal/clockcheck"
	"github.com/varavelio/zen-idp/internal/config"
	"github.com/varavelio/zen-idp/internal/configloader"
	"github.com/varavelio/zen-idp/internal/crypto"
	"github.com/varavelio/zen-idp/internal/jwk"
	"github.com/varavelio/zen-idp/internal/rsakeygen"
	"github.com/varavelio/zen-idp/internal/runtimeconfig"
	"github.com/varavelio/zen-idp/internal/statestore"
)

// dependencies wires every capability the commands need, so tests can replace
// each piece individually.
type dependencies struct {
	checkClock        func(time.Time) error
	loadRuntime       func(string) (runtimeconfig.RuntimeConfig, error)
	loadConfigPath    func(string) (string, error)
	loadConfiguration func(string) (*config.Config, error)
	openStateStore    func(context.Context, string) (*sql.DB, error)
	migrateStateStore func(context.Context, *sql.DB) error
	deriveSigningKey  func([sha256.Size]byte) (*rsa.PrivateKey, error)
	derivePublicJWK   func(*rsa.PublicKey) (jwk.PublicJWK, error)
	listen            func(string, string) (net.Listener, error)
	serve             func(net.Listener, *http.Server) error
	generateSecrets   func() (crypto.SecretBundle, error)
	checkHealth       func(context.Context, string) (int, error)
}

func main() {
	dependencies := dependencies{
		checkClock:        clockcheck.Check,
		loadRuntime:       runtimeconfig.Load,
		loadConfigPath:    runtimeconfig.LoadConfigPath,
		loadConfiguration: configloader.Load,
		openStateStore:    statestore.Connect,
		migrateStateStore: statestore.Migrate,
		deriveSigningKey:  rsakeygen.GeneratePrivateKey,
		derivePublicJWK:   jwk.FromPublicKey,
		listen:            net.Listen,
		serve:             serveWithGracefulShutdown,
		generateSecrets:   crypto.GenerateSecretBundle,
		checkHealth:       checkHealthEndpoint,
	}
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, dependencies))
}

// run dispatches one parsed invocation and reports its outcome as an exit code.
func run(args []string, stdout, stderr io.Writer, dependencies dependencies) int {
	const (
		exitCodeSuccess = iota
		exitCodeOperationalFailure
		exitCodeUsageFailure
	)

	invocation, err := cli.Parse(args)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return exitCodeUsageFailure
	}

	if invocation.Command == cli.Help {
		_, _ = fmt.Fprintln(stdout, cli.Usage())
		return exitCodeSuccess
	}

	var runErr error
	switch invocation.Command {
	case cli.Serve:
		runErr = runServe(invocation.EnvFile, dependencies)
	case cli.ValidateConfig:
		runErr = runValidateConfig(invocation.EnvFile, stdout, dependencies)
	case cli.GenerateSecrets:
		runErr = runGenerateSecrets(stdout, dependencies)
	case cli.Health:
		runErr = runHealth(invocation.EnvFile, stdout, dependencies)
	}
	if runErr == nil {
		return exitCodeSuccess
	}

	_, _ = fmt.Fprintln(stderr, runErr)
	return exitCodeOperationalFailure
}
