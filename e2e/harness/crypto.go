//go:build e2e

package harness

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"
)

// totpDomainPrefix is the exact domain-separation prefix of the Zen IdP TOTP
// derivation, reproduced here so the suite validates the contract
// independently of the implementation under test.
const totpDomainPrefix = "zen-idp:totp:"

// DeriveTOTPSecret reproduces the deterministic TOTP shared secret of a
// subject: the unpadded Base32 encoding of HMAC-SHA256 over the
// domain-separated subject and revision, keyed by the SHA-256 digest of the
// root secret.
func DeriveTOTPSecret(rootSecret, sub string, revision uint64) string {
	key := sha256.Sum256([]byte(rootSecret))
	message := totpDomainPrefix + sub + ":" + strconv.FormatUint(revision, 10)
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte(message))
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(mac.Sum(nil))
}

// TOTPCode computes the RFC 6238 code of the given secret at the given
// instant: HMAC-SHA1 over the 30-second counter, truncated to six decimal
// digits.
func TOTPCode(secret string, at time.Time) string {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		panic("harness: invalid TOTP secret: " + err.Error())
	}
	var message [8]byte
	binary.BigEndian.PutUint64(message[:], uint64(at.Unix()/30))
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(message[:])
	digest := mac.Sum(nil)
	offset := digest[len(digest)-1] & 0x0f
	value := binary.BigEndian.Uint32(digest[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1_000_000)
}

// PKCEVerifier is a fixed, syntactically valid PKCE S256 verifier of 43
// characters from the unreserved URL alphabet.
const PKCEVerifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"

// PKCEChallenge returns the S256 code challenge of the fixed verifier.
func PKCEChallenge() string {
	digest := sha256.Sum256([]byte(PKCEVerifier))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

// BasicAuth builds the Authorization header value of HTTP Basic
// authentication with the given credentials.
func BasicAuth(username, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
}

// DecodeJWT splits a compact JWS token and decodes its header and payload
// into claim maps, failing the test on any malformed token.
func DecodeJWT(t *testing.T, token string) (header, claims map[string]any) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("malformed JWT: %d segments", len(parts))
	}
	header = decodeJSONSegment(t, parts[0], "header")
	claims = decodeJSONSegment(t, parts[1], "payload")
	return header, claims
}

// decodeJSONSegment decodes one base64url JWT segment as a JSON object.
func decodeJSONSegment(t *testing.T, segment, name string) map[string]any {
	t.Helper()
	decoded, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		t.Fatalf("decode JWT %s: %v", name, err)
	}
	var value map[string]any
	if err := json.Unmarshal(decoded, &value); err != nil {
		t.Fatalf("parse JWT %s: %v", name, err)
	}
	return value
}
