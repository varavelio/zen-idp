//go:build e2e

package harness

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

// Config describes one black-box Zen IdP instance: its root secret, its
// administrator credential hash, and the users and clients declared in its
// YAML source. Every field maps to the smallest configuration surface the
// tests need; omitted optional settings let the service apply its defaults.
type Config struct {
	// RootSecret is the ZEN_IDP_SECRET value of the instance.
	RootSecret string
	// AdminHash is the Argon2id PHC hash of the administrator password.
	AdminHash string
	// UIName is the optional display name shown on the pages.
	UIName string
	// Users lists every declared identity.
	Users []User
	// Clients lists every declared OIDC client.
	Clients []Client
}

// User declares one identity in the instance configuration.
type User struct {
	// Sub is the stable OIDC subject.
	Sub string
	// Login is the optional additional login identifier.
	Login string
	// TOTPRev is the optional TOTP credential revision.
	TOTPRev uint64
	// ExpiresAt is the optional absolute expiration as a quoted RFC3339
	// timestamp.
	ExpiresAt string
	// Claims carries the optional custom OIDC claims of the user.
	Claims map[string]any
}

// Client declares one OIDC client in the instance configuration. An empty
// SecretHash declares a public client.
type Client struct {
	// ID is the unique OIDC client identifier.
	ID string
	// Name is the optional human-readable display name.
	Name string
	// SecretHash is the optional Argon2id PHC hash that declares a
	// confidential client.
	SecretHash string
	// RedirectURIs lists the registered exact callback URIs.
	RedirectURIs []string
}

// WriteFile writes the YAML configuration of this Config into the given
// directory with the given issuer and listener port and returns its path.
func (cfg Config) WriteFile(t *testing.T, dir, issuer string, port int) string {
	t.Helper()
	document := configDocument{
		Config: configSection{
			Issuer: issuer,
			Server: serverSection{
				Host: "127.0.0.1",
				Port: port,
			},
			Security: securitySection{
				AdminPasswordHash: cfg.AdminHash,
			},
		},
		Clients: make([]clientSection, 0, len(cfg.Clients)),
		Users:   make([]userSection, 0, len(cfg.Users)),
	}
	if cfg.UIName != "" {
		document.Config.UI = &uiSection{Name: cfg.UIName}
	}
	for _, client := range cfg.Clients {
		document.Clients = append(document.Clients, clientSection(client))
	}
	for _, user := range cfg.Users {
		document.Users = append(document.Users, userSection(user))
	}
	contents, err := yaml.Marshal(document)
	if err != nil {
		t.Fatalf("marshal e2e configuration: %v", err)
	}
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatalf("write e2e configuration: %v", err)
	}
	return path
}

// validate fails the test early when the Config cannot produce a usable
// instance, so failures point at the test data instead of the server.
func (cfg Config) validate(t *testing.T) {
	t.Helper()
	if cfg.RootSecret == "" {
		t.Fatal("harness: configuration root secret must not be empty")
	}
	if cfg.AdminHash == "" {
		t.Fatal("harness: configuration admin hash must not be empty")
	}
	for _, client := range cfg.Clients {
		if client.ID == "" || len(client.RedirectURIs) == 0 {
			t.Fatalf("harness: client %q needs an id and at least one redirect URI", client.ID)
		}
	}
	for _, user := range cfg.Users {
		if user.Sub == "" {
			t.Fatal("harness: every user needs a sub")
		}
	}
}

// configDocument mirrors the composed YAML document the service accepts.
type configDocument struct {
	Config  configSection   `yaml:"config"`
	Clients []clientSection `yaml:"clients"`
	Users   []userSection   `yaml:"users"`
}

type configSection struct {
	Issuer   string          `yaml:"issuer"`
	Server   serverSection   `yaml:"server"`
	UI       *uiSection      `yaml:"ui,omitempty"`
	Security securitySection `yaml:"security"`
}

type serverSection struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
}

type uiSection struct {
	Name string `yaml:"name"`
}

type securitySection struct {
	AdminPasswordHash string `yaml:"admin_password_hash"`
}

type clientSection struct {
	ID           string   `yaml:"id"`
	Name         string   `yaml:"name,omitempty"`
	SecretHash   string   `yaml:"secret_hash,omitempty"`
	RedirectURIs []string `yaml:"redirect_uris"`
}

type userSection struct {
	Sub       string         `yaml:"sub"`
	Login     string         `yaml:"idp_login,omitempty"`
	TOTPRev   uint64         `yaml:"idp_totp_rev,omitempty"`
	ExpiresAt string         `yaml:"idp_expires_at,omitempty"`
	Claims    map[string]any `yaml:",inline"`
}
