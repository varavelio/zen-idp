package session

import (
	"crypto/hmac"
	"crypto/sha256"
	"strings"
)

// tokenPrefix introduces every browser session token.
const tokenPrefix = "sess_"

// secretHashDomainPrefix is the shared ASCII domain-separation prefix of the
// session secret digests. Each session kind appends its own label after it,
// so a secret digested for one kind can never validate as the other. The
// prefixes must not change within v1; changing them would invalidate every
// outstanding session after a restart.
const secretHashDomainPrefix = "zen-idp:session:v1:"

// userHashDomainPrefix digests regular SSO session secrets.
const userHashDomainPrefix = secretHashDomainPrefix + "user:"

// adminHashDomainPrefix digests administrator session secrets.
const adminHashDomainPrefix = secretHashDomainPrefix + "admin:"

// formatToken assembles the browser credential token from its parts.
func formatToken(id, secret string) string {
	return tokenPrefix + id + "_" + secret
}

// parseToken splits a browser credential token into its record identifier
// and secret halves. Tokens with a wrong prefix, a missing separator, empty
// parts, extra separators, or whitespace are rejected: the format is
// machine-generated, so any of those marks tampering or corruption.
func parseToken(token string) (id, secret string, err error) {
	if !strings.HasPrefix(token, tokenPrefix) {
		return "", "", ErrMalformedToken
	}
	remainder := strings.TrimPrefix(token, tokenPrefix)

	id, remainder, ok := strings.Cut(remainder, "_")
	if !ok || id == "" {
		return "", "", ErrMalformedToken
	}
	if strings.ContainsAny(remainder, " \t\r\n") {
		return "", "", ErrMalformedToken
	}
	if strings.Contains(remainder, "_") {
		return "", "", ErrMalformedToken
	}
	if remainder == "" {
		return "", "", ErrMalformedToken
	}

	return id, remainder, nil
}

// hashSecret returns the persisted digest of a session secret: the
// HMAC-SHA-256 of the domain-separated message zen-idp:session:v1:{kind}:secret
// keyed by the normalized root secret.
func hashSecret(rootSecret [sha256.Size]byte, secret string, kind Kind) []byte {
	domain := userHashDomainPrefix
	if kind == KindAdmin {
		domain = adminHashDomainPrefix
	}
	mac := hmac.New(sha256.New, rootSecret[:])
	_, _ = mac.Write([]byte(domain + secret))
	return mac.Sum(nil)
}
