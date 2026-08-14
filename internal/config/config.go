package config

import "time"

// Config is the fully parsed and resolved Zen IdP configuration.
// Fields nested below the YAML config key are promoted here so consumers do not
// need to know about the configuration file's composition envelope.
type Config struct {
	// Issuer is the externally visible OIDC issuer URL.
	Issuer string
	// Server contains the HTTP listener settings.
	Server Server
	// UI contains the authentication interface presentation settings.
	UI UI
	// Security contains authentication and session policy settings.
	Security Security
	// Maintenance contains periodic state-cleanup settings.
	Maintenance Maintenance
	// Clients contains every OIDC client from the composed source.
	Clients []Client
	// Users contains every normalized user from the composed source.
	Users []User
}

// Server contains the HTTP listener settings managed by Zen IdP.
type Server struct {
	// Host is the network host or address on which the server listens.
	Host string
	// Port is the TCP port on which the server listens.
	Port int
}

// UI contains presentation settings that do not affect identity semantics.
type UI struct {
	// Name is the product or organization name shown to users.
	Name string
	// LogoLightURL is the HTTPS URL of the logo shown in light mode.
	LogoLightURL string
	// LogoDarkURL is the HTTPS URL of the logo shown in dark mode.
	LogoDarkURL string
	// FaviconURL is the URL of the icon associated with authentication pages.
	FaviconURL string
}

// Security contains resolved authentication and session policy settings.
type Security struct {
	// AdminPasswordHash is the Argon2id hash used for administrator authentication.
	AdminPasswordHash string
	// RateLimits contains brute-force protection settings.
	RateLimits RateLimits
	// Session contains browser SSO session settings.
	Session Session
}

// RateLimits contains resolved brute-force protection settings.
type RateLimits struct {
	// MaxUserLoginAttempts is the maximum number of failed login attempts allowed
	// for one user during the configured window.
	MaxUserLoginAttempts int
	// UserLoginAttemptsWindow is the period over which one user's failed login
	// attempts are counted.
	UserLoginAttemptsWindow time.Duration
	// MaxClientAuthAttempts is the maximum number of failed client
	// authentication attempts allowed for one client during the configured
	// window.
	MaxClientAuthAttempts int
	// ClientAuthAttemptsWindow is the period over which one client's failed
	// authentication attempts are counted.
	ClientAuthAttemptsWindow time.Duration
}

// Session contains resolved Zen IdP browser session settings.
type Session struct {
	// MaxAge is the absolute maximum lifetime of an SSO session.
	MaxAge time.Duration
}

// Maintenance contains resolved periodic state-cleanup settings.
type Maintenance struct {
	// CleanupInterval is the period between automatic cleanup passes over
	// the disposable state database.
	CleanupInterval time.Duration
	// AuditRetention is how long audit records are kept before cleanup
	// removes them. A zero value keeps audit records indefinitely.
	AuditRetention time.Duration
}

// Client is a configured OIDC client.
type Client struct {
	// ID is the unique protocol identifier presented by the client.
	ID string
	// Name is the human-readable client name, defaulting to ID.
	Name string
	// SecretHash is the Argon2id hash of the client secret. An empty value marks
	// the client as public.
	SecretHash string
	// RedirectURIs contains the exact callback URIs accepted for the client.
	RedirectURIs []string
}

// User is a normalized human identity declaration.
type User struct {
	// Subject is the stable, case-sensitive OIDC subject identifier.
	Subject string
	// Login is the optional additional login identifier, defaulting to Subject.
	Login string
	// TOTPRevision selects the deterministic TOTP credential revision.
	TOTPRevision uint64
	// ExpiresAt is the time after which the user is expired. Its zero value means
	// that the user has no configured expiration.
	ExpiresAt time.Time
	// Claims contains the custom JSON-compatible claims emitted for the user.
	Claims map[string]any
}

// MatchesLoginIdentifier reports whether identifier belongs to the user.
func (user User) MatchesLoginIdentifier(identifier string) bool {
	return identifier == user.Subject || (user.Login != "" && identifier == user.Login)
}
