package config

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const validArgon2idHash = "$argon2id$v=19$m=19456,t=2,p=1$YWRtaW5TYWx0$MDEyMzQ1Njc4OWFiY2RlZg"

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

		configuration, err := Parse(withValidHashes(contents))
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
		require.Equal(t, []Client{{
			ID:           "grafana",
			Name:         "Grafana",
			SecretHash:   validArgon2idHash,
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
		configuration, err := Parse(withValidHashes([]byte(`
config:
  issuer: https://auth.example.com
  security:
    admin_password_hash: admin-hash
    rate_limits:
      max_user_login_attempts: 0
`)))

		require.Nil(t, configuration)
		require.ErrorContains(t, err, "max_user_login_attempts must be between 1 and 100")
	})

	t.Run("rejects a zero user login attempts window", func(t *testing.T) {
		configuration, err := Parse(withValidHashes([]byte(`
config:
  issuer: https://auth.example.com
  security:
    admin_password_hash: admin-hash
    rate_limits:
      user_login_attempts_window_seconds: 0
`)))

		require.Nil(t, configuration)
		require.ErrorContains(
			t,
			err,
			"user_login_attempts_window_seconds must be between 1 and 86400",
		)
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

	t.Run("allows a local HTTP issuer for development", func(t *testing.T) {
		configuration, err := Parse(validConfigurationYAML(`
config:
  issuer: http://127.0.0.1:8080
  security:
    admin_password_hash: admin-hash
`))
		require.NoError(t, err)

		require.Equal(t, "http://127.0.0.1:8080", configuration.Issuer)
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
		"issuer is not a string": {
			contents: []byte(`
config:
  issuer: true
  security:
    admin_password_hash: admin-hash
`),
			errorText: "must be a string",
		},
		"issuer is not an absolute URL": {
			contents: validConfigurationYAML(`
config:
  issuer: auth.example.com
  security:
    admin_password_hash: admin-hash
`),
			errorText: "must be an absolute URL",
		},
		"issuer uses external HTTP": {
			contents: validConfigurationYAML(`
config:
  issuer: http://auth.example.com
  security:
    admin_password_hash: admin-hash
`),
			errorText: "must use HTTPS",
		},
		"issuer contains a query": {
			contents: validConfigurationYAML(`
config:
  issuer: https://auth.example.com?tenant=example
  security:
    admin_password_hash: admin-hash
`),
			errorText: "must not contain userinfo, a query, or a fragment",
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
		"null server host": {
			contents: []byte(`
config:
  issuer: https://auth.example.com
  server:
    host: null
  security:
    admin_password_hash: admin-hash
`),
			errorText: "must not be null",
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
		"null server port": {
			contents: []byte(`
config:
  issuer: https://auth.example.com
  server:
    port: null
  security:
    admin_password_hash: admin-hash
`),
			errorText: "must not be null",
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
		"invalid administrator hash": {
			contents: []byte(`
config:
  issuer: https://auth.example.com
  security:
    admin_password_hash: invalid-hash
`),
			errorText: "must use the Argon2id PHC format with version 19",
		},
		"UI name is whitespace": {
			contents: validConfigurationYAML(`
config:
  issuer: https://auth.example.com
  ui:
    name: "   "
  security:
    admin_password_hash: admin-hash
`),
			errorText: "config.ui.name must not be blank",
		},
		"UI name is explicitly empty": {
			contents: validConfigurationYAML(`
config:
  issuer: https://auth.example.com
  ui:
    name: ""
  security:
    admin_password_hash: admin-hash
`),
			errorText: "config.ui.name must not be blank",
		},
		"UI logo is explicitly empty": {
			contents: validConfigurationYAML(`
config:
  issuer: https://auth.example.com
  ui:
    logo_url: ""
  security:
    admin_password_hash: admin-hash
`),
			errorText: "config.ui.logo_url must not be empty",
		},
		"UI logo is not HTTPS": {
			contents: validConfigurationYAML(`
config:
  issuer: https://auth.example.com
  ui:
    logo_url: http://example.com/logo.png
  security:
    admin_password_hash: admin-hash
`),
			errorText: "config.ui.logo_url",
		},
		"UI name is not a string": {
			contents: []byte(`
config:
  issuer: https://auth.example.com
  ui:
    name: 42
  security:
    admin_password_hash: admin-hash
`),
			errorText: "must be a string",
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
		"removed OIDC lifetime settings": {
			contents: validConfigurationYAML(`
config:
  issuer: https://auth.example.com
  security:
    admin_password_hash: admin-hash
    oidc:
      id_token_max_age_seconds: 900
`),
			errorText: "field oidc not found",
		},
		"excessive login attempts": {
			contents: validConfigurationYAML(`
config:
  issuer: https://auth.example.com
  security:
    admin_password_hash: admin-hash
    rate_limits:
      max_user_login_attempts: 101
`),
			errorText: "must be between 1 and 100",
		},
		"null login attempts": {
			contents: []byte(`
config:
  issuer: https://auth.example.com
  security:
    admin_password_hash: admin-hash
    rate_limits:
      max_user_login_attempts: null
`),
			errorText: "must not be null",
		},
		"excessive login window": {
			contents: validConfigurationYAML(`
config:
  issuer: https://auth.example.com
  security:
    admin_password_hash: admin-hash
    rate_limits:
      user_login_attempts_window_seconds: 86401
`),
			errorText: "must be between 1 and 86400",
		},
		"excessive session lifetime": {
			contents: validConfigurationYAML(`
config:
  issuer: https://auth.example.com
  security:
    admin_password_hash: admin-hash
    session:
      max_age_hours: 8761
`),
			errorText: "must be between 1 and 8760",
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
		"explicit login is empty": {
			contents:  validConfigurationYAML("users:\n  - sub: user\n    idp_login: \"\"\n"),
			errorText: "empty effective login",
		},
		"user field key is not a string": {
			contents:  validConfigurationYAML("users:\n  - sub: user\n    1: value\n"),
			errorText: "key must be a string",
		},
		"duplicate user field": {
			contents:  validConfigurationYAML("users:\n  - sub: first\n    sub: second\n"),
			errorText: `field "sub" is duplicated`,
		},
		"subject exceeds OIDC limit": {
			contents: validConfigurationYAML(
				"users:\n  - sub: \"" + strings.Repeat("a", 256) + "\"\n",
			),
			errorText: "at most 255 ASCII characters",
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
    secret_hash: client-hash
    redirect_uris: [https://first.example.com/callback]
  - id: duplicate
    secret_hash: client-hash
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
		"client with null secret hash": {
			contents: []byte(`
config:
  issuer: https://auth.example.com
  security:
    admin_password_hash: admin-hash
clients:
  - id: browser-app
    secret_hash: null
    redirect_uris: [https://app.example.com/callback]
`),
			errorText: "must not be null",
		},
		"client secret aliases null": {
			contents: []byte(`
config:
  issuer: https://auth.example.com
  security:
    admin_password_hash: admin-hash
users:
  - sub: user
    optional_claim: &nullable null
clients:
  - id: browser-app
    secret_hash: *nullable
    redirect_uris: [https://app.example.com/callback]
`),
			errorText: "must not be null",
		},
		"client with malformed secret hash": {
			contents: validConfigurationYAML(`
clients:
  - id: browser-app
    secret_hash: invalid-hash
    redirect_uris: [https://app.example.com/callback]
`),
			errorText: "must use the Argon2id PHC format with version 19",
		},
		"client ID is whitespace": {
			contents: validConfigurationYAML(`
clients:
  - id: "   "
    redirect_uris: [https://app.example.com/callback]
`),
			errorText: "clients[0].id is required",
		},
		"client name is whitespace": {
			contents: validConfigurationYAML(`
clients:
  - id: browser-app
    name: "   "
    redirect_uris: [https://app.example.com/callback]
`),
			errorText: "name must not be blank",
		},
		"redirect URI is not a string": {
			contents: []byte(`
config:
  issuer: https://auth.example.com
  security:
    admin_password_hash: admin-hash
clients:
  - id: browser-app
    redirect_uris: [42]
`),
			errorText: "must be a string",
		},
		"duplicate redirect URI": {
			contents: validConfigurationYAML(`
clients:
  - id: browser-app
    redirect_uris:
      - https://app.example.com/callback
      - https://app.example.com/callback
`),
			errorText: "redirect URI",
		},
		"external HTTP redirect URI": {
			contents: validConfigurationYAML(`
clients:
  - id: browser-app
    redirect_uris: [http://app.example.com/callback]
`),
			errorText: "HTTP redirect URI is allowed only",
		},
		"confidential client private-use redirect URI": {
			contents: validConfigurationYAML(`
clients:
  - id: native-app
    secret_hash: client-hash
    redirect_uris: [com.example.app:/oauth/callback]
`),
			errorText: "confidential clients must use HTTPS",
		},
		"public client invalid private-use scheme": {
			contents: validConfigurationYAML(`
clients:
  - id: native-app
    redirect_uris: [javascript:callback]
`),
			errorText: "must use reverse-domain notation",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			configuration, err := Parse(withValidHashes(test.contents))

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
	return withValidHashes([]byte(base))
}

func withValidHashes(contents []byte) []byte {
	replacer := strings.NewReplacer(
		"admin-hash", validArgon2idHash,
		"client-hash", validArgon2idHash,
	)
	return []byte(replacer.Replace(string(contents)))
}
