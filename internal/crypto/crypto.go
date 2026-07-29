package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
)

// rootSecretLength is the number of random bytes used to create a root secret.
// It provides 256 bits of entropy.
const rootSecretLength = 32

// GenerateRootSecret returns a root secret generated with 256 bits of
// operating-system entropy. The secret uses lowercase hexadecimal encoding,
// making it easy to copy into environment variables and command-line input.
//
// GenerateRootSecret returns an error if the operating system cannot provide
// enough secure random data.
func GenerateRootSecret() (string, error) {
	return generateRootSecret(rand.Reader)
}

// generateRootSecret returns a root secret using randomness as its entropy
// source. The source must provide rootSecretLength bytes or return an error.
func generateRootSecret(randomness io.Reader) (string, error) {
	var randomBytes [rootSecretLength]byte
	defer clear(randomBytes[:])

	if _, err := io.ReadFull(randomness, randomBytes[:]); err != nil {
		return "", fmt.Errorf("generate root secret: read random bytes: %w", err)
	}

	return hex.EncodeToString(randomBytes[:]), nil
}
