package config

import "time"

// Configuration is the fully parsed and resolved Zen IdP configuration.
// Fields nested below the YAML config key are promoted here so consumers do not
// need to know about the configuration file's composition envelope.
type Configuration struct {
	// Issuer is the externally visible OIDC issuer URL.
	Issuer string
	// UI contains the authentication interface presentation settings.
	UI UI
	// Security contains authentication and artifact lifetime settings.
	Security Security
	// Clients contains every OIDC client from the composed source.
	Clients []Client
	// Users contains every normalized user from the composed source.
	Users []User
}

// UI contains presentation settings that do not affect identity semantics.
type UI struct {
	// Name is the product or organization name shown to users.
	Name string
	// LogoURL is the HTTPS URL of the logo shown on authentication pages.
	LogoURL string
	// FaviconURL is the URL of the icon associated with authentication pages.
	FaviconURL string
}

// Security contains resolved security policy and lifetime settings.
type Security struct {
	// AdminPasswordHash is the Argon2id hash used for administrator authentication.
	AdminPasswordHash string
	// RateLimits contains brute-force protection settings.
	RateLimits RateLimits
	// Session contains browser SSO session settings.
	Session Session
	// OIDC contains authorization code and token lifetime settings.
	OIDC OIDC
	// Enrollment contains enrollment link lifetime settings.
	Enrollment Enrollment
	// TrustedProxies lists proxies whose forwarded client addresses may be trusted.
	TrustedProxies []string
}

// RateLimits contains resolved user login rate-limit settings.
type RateLimits struct {
	// MaxUserLoginAttempts is the maximum number of failed login attempts allowed
	// for one user during the configured window.
	MaxUserLoginAttempts int
	// UserLoginAttemptsWindow is the period over which one user's failed login
	// attempts are counted.
	UserLoginAttemptsWindow time.Duration
}

// Session contains resolved Zen IdP browser session settings.
type Session struct {
	// MaxAge is the absolute maximum lifetime of an SSO session.
	MaxAge time.Duration
}

// OIDC contains resolved lifetimes for OIDC artifacts.
type OIDC struct {
	// AuthorizationCodeMaxAge is the maximum lifetime of an authorization code.
	AuthorizationCodeMaxAge time.Duration
	// IDTokenMaxAge is the maximum lifetime of an ID token.
	IDTokenMaxAge time.Duration
	// AccessTokenMaxAge is the maximum lifetime of a UserInfo access token.
	AccessTokenMaxAge time.Duration
}

// Enrollment contains resolved enrollment workflow settings.
type Enrollment struct {
	// LinkMaxAge is the maximum lifetime of an enrollment link.
	LinkMaxAge time.Duration
}

// Client is a configured confidential OIDC client.
type Client struct {
	// ID is the unique protocol identifier presented by the client.
	ID string
	// Name is the optional human-readable client name.
	Name string
	// SecretHash is the Argon2id hash of the client secret.
	SecretHash string
	// RedirectURIs contains the exact callback URIs accepted for the client.
	RedirectURIs []string
}

// User is a normalized human identity declaration.
type User struct {
	// Subject is the stable, case-sensitive OIDC subject identifier.
	Subject string
	// Login is the resolved identifier entered during authentication.
	Login string
	// TOTPRevision selects the deterministic TOTP credential revision.
	TOTPRevision uint64
	// ExpiresAt is the time after which the user is expired. Its zero value means
	// that the user has no configured expiration.
	ExpiresAt time.Time
	// Claims contains the custom JSON-compatible claims emitted for the user.
	Claims map[string]any
}
