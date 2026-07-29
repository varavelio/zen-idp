package config

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	t.Run("returns a flat resolved configuration", func(t *testing.T) {
		contents := []byte(`
config:
  issuer: https://auth.example.com
  server:
    host: 0.0.0.0
    port: 9090
  ui:
    name: Example Auth
    logo_url: https://example.com/logo.png
    favicon_url: https://example.com/favicon.ico
  security:
    admin_password_hash: admin-hash
    rate_limits:
      max_user_login_attempts: 8
      user_login_attempts_window_seconds: 120
    session:
      max_age_hours: 24
    oidc:
      authorization_code_max_age_seconds: 60
      id_token_max_age_seconds: 600
      access_token_max_age_seconds: 300
clients:
  - id: grafana
    name: Grafana
    secret_hash: client-hash
    redirect_uris: [https://grafana.example.com/callback]
users:
  - sub: auditor@example.com
  - sub: employee-42
    idp_login: employee@example.com
    idp_totp_rev: 2
    idp_expires_at: "2030-01-02T03:04:05Z"
    name: Example Person
    groups: [engineering, operators]
    profile:
      active: true
`)

		configuration, err := Parse(contents)
		require.NoError(t, err)

		require.Equal(t, "https://auth.example.com", configuration.Issuer)
		require.Equal(t, Server{Host: "0.0.0.0", Port: 9090}, configuration.Server)
		require.Equal(t, UI{
			Name:       "Example Auth",
			LogoURL:    "https://example.com/logo.png",
			FaviconURL: "https://example.com/favicon.ico",
		}, configuration.UI)
		require.Equal(t, 8, configuration.Security.RateLimits.MaxUserLoginAttempts)
		require.Equal(
			t,
			2*time.Minute,
			configuration.Security.RateLimits.UserLoginAttemptsWindow,
		)
		require.Equal(t, 24*time.Hour, configuration.Security.Session.MaxAge)
		require.Equal(t, time.Minute, configuration.Security.OIDC.AuthorizationCodeMaxAge)
		require.Equal(t, 10*time.Minute, configuration.Security.OIDC.IDTokenMaxAge)
		require.Equal(t, 5*time.Minute, configuration.Security.OIDC.AccessTokenMaxAge)
		require.Equal(t, []Client{{
			ID:           "grafana",
			Name:         "Grafana",
			SecretHash:   "client-hash",
			RedirectURIs: []string{"https://grafana.example.com/callback"},
		}}, configuration.Clients)
		require.Equal(t, User{
			Subject: "auditor@example.com",
			Login:   "auditor@example.com",
			Claims:  map[string]any{},
		}, configuration.Users[0])
		require.True(t, configuration.Users[0].ExpiresAt.IsZero())
		require.Equal(t, "employee-42", configuration.Users[1].Subject)
		require.Equal(t, "employee@example.com", configuration.Users[1].Login)
		require.Equal(t, uint64(2), configuration.Users[1].TOTPRevision)
		require.Equal(
			t,
			time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC),
			configuration.Users[1].ExpiresAt,
		)
		require.Equal(t, "Example Person", configuration.Users[1].Claims["name"])
		require.Equal(t, []any{"engineering", "operators"}, configuration.Users[1].Claims["groups"])
		require.Equal(t, map[string]any{"active": true}, configuration.Users[1].Claims["profile"])
		require.NotContains(t, configuration.Users[1].Claims, "idp_login")
		require.NotContains(t, configuration.Users[1].Claims, "idp_totp_rev")
		require.NotContains(t, configuration.Users[1].Claims, "idp_expires_at")
	})

	t.Run("applies defaults to omitted optional settings", func(t *testing.T) {
		configuration, err := Parse(validConfigurationYAML("users: []"))
		require.NoError(t, err)

		require.Equal(
			t,
			defaultMaxUserLoginAttempts,
			configuration.Security.RateLimits.MaxUserLoginAttempts,
		)
		require.Equal(
			t,
			defaultUserLoginAttemptsWindow,
			configuration.Security.RateLimits.UserLoginAttemptsWindow,
		)
		require.Equal(t, defaultSessionMaxAge, configuration.Security.Session.MaxAge)
		require.Equal(
			t,
			defaultAuthorizationCodeMaxAge,
			configuration.Security.OIDC.AuthorizationCodeMaxAge,
		)
		require.Equal(t, defaultIDTokenMaxAge, configuration.Security.OIDC.IDTokenMaxAge)
		require.Equal(t, defaultAccessTokenMaxAge, configuration.Security.OIDC.AccessTokenMaxAge)
		require.Equal(
			t,
			Server{Host: defaultServerHost, Port: defaultServerPort},
			configuration.Server,
		)
		require.NotNil(t, configuration.Clients)
		require.NotNil(t, configuration.Users)
	})

	t.Run("resolves public client names from their IDs", func(t *testing.T) {
		configuration, err := Parse(validConfigurationYAML(`
clients:
  - id: mobile-app
    redirect_uris: [com.example.app:/oauth/callback]
  - id: browser-app
    name: ""
    redirect_uris: [https://app.example.com/callback]
`))
		require.NoError(t, err)

		require.Equal(t, []Client{{
			ID:           "mobile-app",
			Name:         "mobile-app",
			RedirectURIs: []string{"com.example.app:/oauth/callback"},
		}, {
			ID:           "browser-app",
			Name:         "browser-app",
			RedirectURIs: []string{"https://app.example.com/callback"},
		}}, configuration.Clients)
	})

	t.Run("does not replace an explicit insecure zero with a default", func(t *testing.T) {
		configuration, err := Parse([]byte(`
config:
  issuer: https://auth.example.com
  security:
    admin_password_hash: admin-hash
    rate_limits:
      max_user_login_attempts: 0
`))

		require.Nil(t, configuration)
		require.ErrorContains(t, err, "max_user_login_attempts must be positive")
	})

	t.Run("rejects a zero user login attempts window", func(t *testing.T) {
		configuration, err := Parse([]byte(`
config:
  issuer: https://auth.example.com
  security:
    admin_password_hash: admin-hash
    rate_limits:
      user_login_attempts_window_seconds: 0
`))

		require.Nil(t, configuration)
		require.ErrorContains(t, err, "user_login_attempts_window_seconds must be positive")
	})

	t.Run("treats the former prefix as a custom claim", func(t *testing.T) {
		configuration, err := Parse(validConfigurationYAML(`
users:
  - sub: user
    zi_legacy: retained
`))
		require.NoError(t, err)

		require.Equal(t, "retained", configuration.Users[0].Claims["zi_legacy"])
	})

	t.Run("allows one user to use its subject as its explicit login", func(t *testing.T) {
		configuration, err := Parse(validConfigurationYAML(`
users:
  - sub: same-identifier
    idp_login: same-identifier
`))
		require.NoError(t, err)

		require.Equal(t, "same-identifier", configuration.Users[0].Subject)
		require.Equal(t, "same-identifier", configuration.Users[0].Login)
	})

	t.Run("rejects shorthand user declarations", func(t *testing.T) {
		configuration, err := Parse(validConfigurationYAML(`
users:
  - auditor@example.com
`))

		require.Nil(t, configuration)
		require.ErrorContains(t, err, "declaration must be a mapping")
	})
}

func TestParseExampleConfiguration(t *testing.T) {
	contents, err := os.ReadFile("../../config.example.yaml")
	require.NoError(t, err)

	configuration, err := Parse(contents)
	require.NoError(t, err)
	require.Equal(t, Server{Host: defaultServerHost, Port: defaultServerPort}, configuration.Server)
}

func TestParseErrors(t *testing.T) {
	tests := map[string]struct {
		contents  []byte
		errorText string
	}{
		"empty document": {
			contents:  nil,
			errorText: "decode configuration",
		},
		"multiple documents": {
			contents:  []byte("config: {}\n---\nusers: []\n"),
			errorText: "multiple YAML documents are not supported",
		},
		"unknown typed setting": {
			contents: []byte(`
config:
  issuer: https://auth.example.com
  unknown: value
  security:
    admin_password_hash: admin-hash
`),
			errorText: "field unknown not found",
		},
		"missing issuer": {
			contents: []byte(`
config:
  security:
    admin_password_hash: admin-hash
`),
			errorText: "config.issuer is required",
		},
		"empty server host": {
			contents: []byte(`
config:
  issuer: https://auth.example.com
  server:
    host: ""
  security:
    admin_password_hash: admin-hash
`),
			errorText: "config.server.host must not be empty",
		},
		"zero server port": {
			contents: []byte(`
config:
  issuer: https://auth.example.com
  server:
    port: 0
  security:
    admin_password_hash: admin-hash
`),
			errorText: "config.server.port must be between 1 and 65535",
		},
		"invalid server port": {
			contents: []byte(`
config:
  issuer: https://auth.example.com
  server:
    host: 127.0.0.1
    port: 65536
  security:
    admin_password_hash: admin-hash
`),
			errorText: "config.server.port must be between 1 and 65535",
		},
		"fractional server port": {
			contents: []byte(`
config:
  issuer: https://auth.example.com
  server:
    host: 127.0.0.1
    port: 8080.5
  security:
    admin_password_hash: admin-hash
`),
			errorText: "must be an integer",
		},
		"legacy server interface field": {
			contents: []byte(`
config:
  issuer: https://auth.example.com
  server:
    interface: 127.0.0.1
  security:
    admin_password_hash: admin-hash
`),
			errorText: "field interface not found",
		},
		"missing administrator hash": {
			contents: []byte(`
config:
  issuer: https://auth.example.com
`),
			errorText: "admin_password_hash is required",
		},
		"removed primary color field": {
			contents: []byte(`
config:
  issuer: https://auth.example.com
  ui:
    primary_color: "#123456"
  security:
    admin_password_hash: admin-hash
`),
			errorText: "field primary_color not found",
		},
		"removed theme field": {
			contents: []byte(`
config:
  issuer: https://auth.example.com
  ui:
    theme: dark
  security:
    admin_password_hash: admin-hash
`),
			errorText: "field theme not found",
		},
		"removed support email field": {
			contents: []byte(`
config:
  issuer: https://auth.example.com
  ui:
    support_email: support@example.com
  security:
    admin_password_hash: admin-hash
`),
			errorText: "field support_email not found",
		},
		"removed trusted proxies field": {
			contents: validConfigurationYAML(`
config:
  issuer: https://auth.example.com
  server:
    host: 127.0.0.1
    port: 8080
  security:
    admin_password_hash: admin-hash
    trusted_proxies: []
`),
			errorText: "field trusted_proxies not found",
		},
		"removed enrollment settings": {
			contents: validConfigurationYAML(`
config:
  issuer: https://auth.example.com
  server:
    host: 127.0.0.1
    port: 8080
  security:
    admin_password_hash: admin-hash
    enrollment:
      link_max_age_seconds: 300
`),
			errorText: "field enrollment not found",
		},
		"fractional TOTP revision": {
			contents:  validConfigurationYAML("users:\n  - sub: user\n    idp_totp_rev: 1.5\n"),
			errorText: "decode user idp_totp_rev",
		},
		"reserved Zen IdP field": {
			contents:  validConfigurationYAML("users:\n  - sub: user\n    idp_unknown: value\n"),
			errorText: `unsupported reserved field "idp_unknown"`,
		},
		"expiration is not a string": {
			contents: validConfigurationYAML(
				"users:\n  - sub: user\n    idp_expires_at: 2030-01-02\n",
			),
			errorText: "idp_expires_at",
		},
		"expiration is not RFC3339": {
			contents: validConfigurationYAML(
				"users:\n  - sub: user\n    idp_expires_at: \"2030-01-02\"\n",
			),
			errorText: "value must use RFC3339 format",
		},
		"reserved protocol claim": {
			contents:  validConfigurationYAML("users:\n  - sub: user\n    iss: attacker\n"),
			errorText: `claim "iss" is reserved`,
		},
		"non-JSON claim": {
			contents: validConfigurationYAML(
				"users:\n  - sub: user\n    created_at: 2026-07-28\n",
			),
			errorText: "is not JSON-compatible",
		},
		"colliding login namespace": {
			contents: validConfigurationYAML(`
users:
  - sub: first
    idp_login: second
  - sub: second
`),
			errorText: `user identifier "second" conflicts`,
		},
		"login collides with an earlier subject": {
			contents: validConfigurationYAML(`
users:
  - sub: shared
  - sub: second
    idp_login: shared
`),
			errorText: `user login "shared" conflicts`,
		},
		"duplicate explicit logins": {
			contents: validConfigurationYAML(`
users:
  - sub: first
    idp_login: shared
  - sub: second
    idp_login: shared
`),
			errorText: `user login "shared" conflicts`,
		},
		"duplicate user subjects": {
			contents: validConfigurationYAML(`
users:
  - sub: duplicate
  - sub: duplicate
`),
			errorText: `user identifier "duplicate" conflicts`,
		},
		"duplicate client IDs": {
			contents: validConfigurationYAML(`
clients:
  - id: duplicate
    secret_hash: first
    redirect_uris: [https://first.example.com/callback]
  - id: duplicate
    secret_hash: second
    redirect_uris: [https://second.example.com/callback]
`),
			errorText: `client id "duplicate" duplicates`,
		},
		"legacy client ID field": {
			contents: validConfigurationYAML(`
clients:
  - client_id: grafana
    secret_hash: client-hash
    redirect_uris: [https://grafana.example.com/callback]
`),
			errorText: "field client_id not found",
		},
		"client without redirect URI": {
			contents: validConfigurationYAML(`
clients:
  - id: grafana
    secret_hash: client-hash
`),
			errorText: "requires at least one redirect_uri",
		},
		"client with empty secret hash": {
			contents: validConfigurationYAML(`
clients:
  - id: browser-app
    secret_hash: ""
    redirect_uris: [https://app.example.com/callback]
`),
			errorText: "secret_hash must not be empty when provided",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			configuration, err := Parse(test.contents)

			require.Nil(t, configuration)
			require.ErrorContains(t, err, test.errorText)
		})
	}
}

func TestReservedProtocolClaims(t *testing.T) {
	require.Equal(t, map[string]struct{}{
		"iss":       {},
		"sub":       {},
		"aud":       {},
		"exp":       {},
		"iat":       {},
		"nbf":       {},
		"jti":       {},
		"nonce":     {},
		"auth_time": {},
		"azp":       {},
		"at_hash":   {},
		"c_hash":    {},
		"acr":       {},
		"amr":       {},
	}, reservedProtocolClaims)
}

func validConfigurationYAML(fragment string) []byte {
	base := `
config:
  issuer: https://auth.example.com
  security:
    admin_password_hash: admin-hash
`
	if fragment != "" {
		base = fragment
		if !strings.Contains(fragment, "config:") {
			base = `
config:
  issuer: https://auth.example.com
  security:
    admin_password_hash: admin-hash
` + fragment
		}
	}
	return []byte(base)
}
