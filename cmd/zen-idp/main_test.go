package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"database/sql"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/varavelio/zen-idp/internal/config"
	"github.com/varavelio/zen-idp/internal/crypto"
	"github.com/varavelio/zen-idp/internal/jwk"
	"github.com/varavelio/zen-idp/internal/runtimeconfig"
)

const instanceYAML = `
config:
  issuer: https://auth.example.com
  security:
    admin_password_hash: "$argon2id$v=19$m=19456,t=2,p=1$YWRtaW5TYWx0$MDEyMzQ1Njc4OWFiY2RlZg"
`

func TestRun(t *testing.T) {
	t.Run("returns usage failures for invalid commands and flags", func(t *testing.T) {
		tests := [][]string{
			nil,
			{"unknown"},
			{"serve", "--unknown"},
			{"serve", "--env-file="},
			{"validate-config", "positional"},
			{"generate-secrets", "extra"},
		}
		for _, args := range tests {
			var stdout bytes.Buffer
			var stderr bytes.Buffer

			exitCode := run(args, &stdout, &stderr, testDependencies(t))

			require.Equal(t, 2, exitCode, "args: %v", args)
			require.NotEmpty(t, stderr.String())
		}
	})

	t.Run("returns help successfully", func(t *testing.T) {
		for _, args := range [][]string{{"--help"}, {"serve", "--help"}} {
			var stdout bytes.Buffer
			var stderr bytes.Buffer

			exitCode := run(args, &stdout, &stderr, testDependencies(t))

			require.Zero(t, exitCode)
			require.Contains(t, stdout.String(), "zen-idp serve")
			require.Empty(t, stderr.String())
		}
	})
}

func testDependencies(t *testing.T) dependencies {
	t.Helper()
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.DiscardHandler))
	t.Cleanup(func() { slog.SetDefault(previous) })
	t.Setenv("ZEN_IDP_CONFIG_PATH", "config")
	t.Setenv("ZEN_IDP_SECRET", "0123456789abcdefghijklmnopqrstuvwxyzABCDEFG")
	t.Setenv("ZEN_IDP_DB_PATH", filepath.Join(t.TempDir(), "state.db"))
	runtime, err := runtimeconfig.Load("")
	require.NoError(t, err)
	return dependencies{
		checkClock: func(time.Time) error { return nil },
		loadRuntime: func(string) (runtimeconfig.RuntimeConfig, error) {
			return runtime, nil
		},
		loadConfigPath: func(string) (string, error) { return "config", nil },
		loadConfiguration: func(string) (*config.Config, error) {
			return config.Parse([]byte(instanceYAML))
		},
		openStateStore: func(_ context.Context, path string) (*sql.DB, error) {
			return sql.Open("sqlite", "file:"+path)
		},
		migrateStateStore: func(context.Context, *sql.DB) error {
			return nil
		},
		deriveSigningKey: func([sha256.Size]byte) (*rsa.PrivateKey, error) {
			return rsa.GenerateKey(rand.Reader, 1024)
		},
		derivePublicJWK: func(*rsa.PublicKey) (jwk.PublicJWK, error) {
			return jwk.PublicJWK{Kid: "18o8WQf60YOSXryGuVEqiEWfO80TcNyB3FLCRWyLzsE"}, nil
		},
		listen: func(network, address string) (net.Listener, error) {
			var listenConfig net.ListenConfig
			return listenConfig.Listen(context.Background(), network, address)
		},
		serve: func(net.Listener, *http.Server) error {
			return nil
		},
		generateSecrets: func() (crypto.SecretBundle, error) {
			return crypto.SecretBundle{
				RootSecret:            "ROOT",
				AdministratorPlain:    "ADMIN",
				AdministratorHash:     "ADMIN_HASH",
				OIDCClientSecretPlain: "CLIENT",
				OIDCClientSecretHash:  "CLIENT_HASH",
			}, nil
		},
	}
}
