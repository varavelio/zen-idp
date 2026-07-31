package crypto

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/alexedwards/argon2id"
)

const (
	base62Alphabet            = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	administratorSecretLength = 14
	machineSecretLength       = 43
	unbiasedByteLimit         = byte(256 - 256%len(base62Alphabet))
)

// https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
const (
	argon2Memory      = 64 * 1024
	argon2Iterations  = 2
	argon2Parallelism = 2
	argon2SaltLength  = 16
	argon2KeyLength   = 32
)

// SecretBundle contains one independent set of bootstrap credentials.
type SecretBundle struct {
	RootSecret            string
	AdministratorPlain    string
	AdministratorHash     string
	OIDCClientSecretPlain string
	OIDCClientSecretHash  string
}

// GenerateSecretBundle creates a root secret, administrator credential, and
// OIDC client credential from operating-system randomness.
func GenerateSecretBundle() (SecretBundle, error) {
	return generateSecretBundle(rand.Reader, HashCredential)
}

// HashCredential returns an Argon2id PHC hash using the Zen IdP credential
// profile and a fresh cryptographically secure salt.
func HashCredential(plain string) (string, error) {
	hash, err := argon2id.CreateHash(plain, &argon2id.Params{
		Memory:      argon2Memory,
		Iterations:  argon2Iterations,
		Parallelism: argon2Parallelism,
		SaltLength:  argon2SaltLength,
		KeyLength:   argon2KeyLength,
	})
	if err != nil {
		return "", fmt.Errorf("create Argon2id hash: %w", err)
	}
	return hash, nil
}

// ValidateCredentialHash checks the PHC structure and minimum salt and key
// lengths accepted by Zen IdP configuration.
func ValidateCredentialHash(hash string) error {
	params, salt, key, err := argon2id.DecodeHash(hash)
	if err != nil {
		return fmt.Errorf("invalid Argon2id PHC hash: %w", err)
	}
	if params.Memory == 0 || params.Iterations == 0 || params.Parallelism == 0 {
		return fmt.Errorf("Argon2id m, t, and p parameters must be positive")
	}
	if len(salt) < 8 {
		return fmt.Errorf("Argon2id salt must contain at least 8 bytes")
	}
	if len(key) < 16 {
		return fmt.Errorf("Argon2id hash must contain at least 16 bytes")
	}
	return nil
}

func generateSecretBundle(
	randomness io.Reader,
	hashCredential func(string) (string, error),
) (SecretBundle, error) {
	rootSecret, err := generateSecret(randomness, machineSecretLength)
	if err != nil {
		return SecretBundle{}, fmt.Errorf("generate root secret: %w", err)
	}
	administratorPlain, err := generateSecret(randomness, administratorSecretLength)
	if err != nil {
		return SecretBundle{}, fmt.Errorf("generate administrator password: %w", err)
	}
	administratorHash, err := hashCredential(administratorPlain)
	if err != nil {
		return SecretBundle{}, fmt.Errorf("hash administrator password: %w", err)
	}
	clientPlain, err := generateSecret(randomness, machineSecretLength)
	if err != nil {
		return SecretBundle{}, fmt.Errorf("generate OIDC client secret: %w", err)
	}
	clientHash, err := hashCredential(clientPlain)
	if err != nil {
		return SecretBundle{}, fmt.Errorf("hash OIDC client secret: %w", err)
	}

	return SecretBundle{
		RootSecret:            rootSecret,
		AdministratorPlain:    administratorPlain,
		AdministratorHash:     administratorHash,
		OIDCClientSecretPlain: clientPlain,
		OIDCClientSecretHash:  clientHash,
	}, nil
}

func generateSecret(randomness io.Reader, length int) (string, error) {
	secret := make([]byte, length)
	randomBytes := make([]byte, length)
	defer clear(randomBytes)

	for offset := 0; offset < length; {
		remaining := length - offset
		if _, err := io.ReadFull(randomness, randomBytes[:remaining]); err != nil {
			return "", fmt.Errorf("read random bytes: %w", err)
		}
		for _, value := range randomBytes[:remaining] {
			if value >= unbiasedByteLimit {
				continue
			}
			secret[offset] = base62Alphabet[int(value)%len(base62Alphabet)]
			offset++
		}
	}

	return string(secret), nil
}
