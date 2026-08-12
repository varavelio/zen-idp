package csrf

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// tokenBytes is the length in bytes of the random anti-forgery token,
// providing 256 bits of entropy encoded as 43 unpadded Base64url
// characters.
const tokenBytes = 32

// generateToken returns a fresh anti-forgery token: 32 cryptographically
// secure random bytes encoded as unpadded Base64url.
func generateToken() (string, error) {
	bytes := make([]byte, tokenBytes)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generate CSRF token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// validToken reports whether token is a well-formed anti-forgery token: an
// unpadded Base64url encoding of exactly tokenBytes bytes.
func validToken(token string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	return err == nil && len(decoded) == tokenBytes
}
