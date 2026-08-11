package onetoken

import (
	"crypto/hmac"
	"crypto/sha256"
	"strings"
)

// tokenPrefix introduces every one-use token.
const tokenPrefix = "tok_"

// secretHashDomainPrefix is the exact ASCII domain-separation prefix of the
// one-use token secret digest. It must not change within v1; changing it
// would invalidate every outstanding token after a restart.
const secretHashDomainPrefix = "zen-idp:onetoken:v1:"

// formatToken assembles the redeemable token from its parts.
func formatToken(id, secret string) string {
	return tokenPrefix + id + "_" + secret
}

// parseToken splits a redeemable token into its record identifier and
// secret halves. Tokens with a wrong prefix, a missing separator, empty
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

// hashSecret returns the persisted digest of a token secret: the
// HMAC-SHA-256 of the domain-separated message zen-idp:onetoken:v1:secret
// keyed by the normalized root secret.
func hashSecret(rootSecret [sha256.Size]byte, secret string) []byte {
	mac := hmac.New(sha256.New, rootSecret[:])
	_, _ = mac.Write([]byte(secretHashDomainPrefix + secret))
	return mac.Sum(nil)
}
