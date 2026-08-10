package totp

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"strconv"
	"unicode/utf8"
)

// domainPrefix is the exact 13-byte ASCII domain-separation prefix of the
// Zen IdP TOTP derivation. It must not change within v1.
const domainPrefix = "zen-idp:totp:"

// DeriveSharedSecret returns the deterministic TOTP shared secret for one
// user, derived from the normalized root secret, the exact configured sub,
// and the effective non-negative TOTP revision.
//
// The returned value is the 52-character uppercase RFC 4648 Base32 encoding,
// without padding, of the full 32-byte HMAC-SHA-256 digest. It is suitable
// for direct use as the secret of a standard RFC 6238 authenticator and for
// the authorized otpauth:// enrollment URI.
//
// The derivation is byte-exact: sub is used as supplied, without case
// conversion, normalization, trimming, or substitution, and revision is
// encoded as unsigned decimal ASCII with no sign, whitespace, or leading
// zeros (zero is encoded as "0").
//
// sub must be a non-empty US-ASCII string, as guaranteed by configuration
// validation; an empty or non-ASCII sub is rejected because it is outside
// the derivation contract.
func DeriveSharedSecret(rootSecret [sha256.Size]byte, sub string, revision uint64) (string, error) {
	if sub == "" {
		return "", errors.New("sub must not be empty")
	}
	if !isASCII(sub) {
		return "", errors.New("sub must contain only US-ASCII characters")
	}

	revisionASCII := strconv.FormatUint(revision, 10)
	message := []byte(domainPrefix + sub + ":" + revisionASCII)

	mac := hmac.New(sha256.New, rootSecret[:])
	_, _ = mac.Write(message)
	digest := mac.Sum(nil)

	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(digest), nil
}

// isASCII reports whether text contains only bytes in the US-ASCII range.
func isASCII(text string) bool {
	for index := 0; index < len(text); index++ {
		if text[index] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}
