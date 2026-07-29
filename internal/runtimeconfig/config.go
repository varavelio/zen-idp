package runtimeconfig

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/caarlos0/env/v11"
	"github.com/joho/godotenv"
)

const (
	dotEnvPath                  = ".env"
	minimumSecretCharacterCount = 32
	secretGeneratorURL          = "https://zen-idp.varavel.com/secret-generator"
)

// RuntimeConfig contains every validated environment-backed setting required
// by Zen IdP.
type RuntimeConfig struct {
	// RootSecret contains the SHA-256 digest of ZEN_IDP_SECRET.
	RootSecret [sha256.Size]byte
	// StateDBPath is the path of the embedded SQLite state database.
	StateDBPath string
}

// environment contains the raw values read from environment variables.
type environment struct {
	Secret      string `env:"ZEN_IDP_SECRET,required,notEmpty"`
	StateDBPath string `env:"ZEN_IDP_STATE_DB_PATH,required,notEmpty"`
}

// Load reads an optional .env file, parses the process environment, and returns
// validated runtime configuration ready for use.
func Load() (RuntimeConfig, error) {
	if err := loadDotEnvIfPresent(); err != nil {
		return RuntimeConfig{}, err
	}

	return parseEnvironment(env.ToMap(os.Environ()))
}

// parseEnvironment validates environment values and resolves their runtime
// representation.
func parseEnvironment(values map[string]string) (RuntimeConfig, error) {
	loaded, err := env.ParseAsWithOptions[environment](env.Options{Environment: values})
	if err != nil {
		return RuntimeConfig{}, fmt.Errorf("parse environment: %w", err)
	}

	if !utf8.ValidString(loaded.Secret) ||
		utf8.RuneCountInString(loaded.Secret) < minimumSecretCharacterCount {
		return RuntimeConfig{}, fmt.Errorf(
			"validate environment: ZEN_IDP_SECRET must contain at least %d valid UTF-8 characters; you can generate one at %s",
			minimumSecretCharacterCount,
			secretGeneratorURL,
		)
	}

	if strings.TrimSpace(loaded.StateDBPath) == "" {
		return RuntimeConfig{}, errors.New(
			"validate environment: ZEN_IDP_STATE_DB_PATH must not be blank",
		)
	}

	if strings.ContainsRune(loaded.StateDBPath, '\x00') {
		return RuntimeConfig{}, errors.New(
			"validate environment: ZEN_IDP_STATE_DB_PATH must not contain null bytes",
		)
	}

	return RuntimeConfig{
		RootSecret:  sha256.Sum256([]byte(loaded.Secret)),
		StateDBPath: loaded.StateDBPath,
	}, nil
}

// loadDotEnvIfPresent adds dotenv values to the process environment without
// overriding variables that are already set.
func loadDotEnvIfPresent() error {
	if _, err := os.Stat(dotEnvPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("inspect %s file: %w", dotEnvPath, err)
	}

	if err := godotenv.Load(dotEnvPath); err != nil {
		return fmt.Errorf("load %s file: %w", dotEnvPath, err)
	}
	return nil
}
