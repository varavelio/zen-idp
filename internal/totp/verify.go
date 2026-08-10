package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// timeStepSeconds is the RFC 6238 time step of the authenticator profile.
const timeStepSeconds = 30

// codeDigits is the number of decimal digits of an accepted TOTP code.
const codeDigits = 6

// skewSteps is the number of adjacent time steps accepted in each direction
// to tolerate clock skew.
const skewSteps = 1

// VerifyCode reports whether code is a valid TOTP code for secret at the
// instant at.
//
// secret must be the unpadded RFC 4648 Base32 value produced by
// DeriveSharedSecret, and code must be exactly six decimal digits, including
// any leading zeros. Verification uses the RFC 6238 authenticator profile of
// HMAC-SHA-1 with a 30-second step, accepting the current time step and one
// adjacent step in either direction for clock skew. Codes are compared in
// constant time.
//
// A malformed secret or code yields a non-nil error; a well-formed but
// incorrect code yields false with a nil error.
func VerifyCode(secret, code string, at time.Time) (bool, error) {
	decoded, err := decodeSecret(secret)
	if err != nil {
		return false, err
	}
	if !isValidCode(code) {
		return false, fmt.Errorf("code must be exactly %d decimal digits", codeDigits)
	}

	step := at.Unix() / timeStepSeconds
	for counter := step - skewSteps; counter <= step+skewSteps; counter++ {
		expected := hotp(decoded, uint64(counter))
		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
			return true, nil
		}
	}
	return false, nil
}

// decodeSecret decodes the unpadded RFC 4648 Base32 shared secret.
func decodeSecret(secret string) ([]byte, error) {
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		return nil, fmt.Errorf("decode base32 secret: %w", err)
	}
	if len(decoded) == 0 {
		return nil, errors.New("secret must not be empty")
	}
	return decoded, nil
}

// isValidCode reports whether code is exactly codeDigits decimal digits.
func isValidCode(code string) bool {
	if len(code) != codeDigits {
		return false
	}
	for index := 0; index < len(code); index++ {
		if code[index] < '0' || code[index] > '9' {
			return false
		}
	}
	return true
}

// hotp computes the RFC 4226 HOTP value for secret and counter, truncated to
// codeDigits decimal digits with leading zeros preserved.
func hotp(secret []byte, counter uint64) string {
	var message [8]byte
	binary.BigEndian.PutUint64(message[:], counter)
	mac := hmac.New(sha1.New, secret)
	_, _ = mac.Write(message[:])
	digest := mac.Sum(nil)

	offset := digest[len(digest)-1] & 0x0f
	code := binary.BigEndian.Uint32(digest[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", code%1_000_000)
}
