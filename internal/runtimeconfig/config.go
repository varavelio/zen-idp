package runtimeconfig

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/caarlos0/env/v11"
	"github.com/joho/godotenv"
)

const (
	configPathVariable          = "ZEN_IDP_CONFIG_PATH"
	secretVariable              = "ZEN_IDP_SECRET"
	stateDBPathVariable         = "ZEN_IDP_DB_PATH"
	minimumSecretCharacterCount = 32
)

// RuntimeConfig contains the validated environment-backed settings required to
// start Zen IdP.
type RuntimeConfig struct {
	// ConfigPath is the file, directory, or glob selector for business YAML.
	ConfigPath string
	// RootSecret contains the SHA-256 digest of ZEN_IDP_SECRET.
	RootSecret [sha256.Size]byte
	// StateDBPath is the path of the embedded SQLite state database.
	StateDBPath string
}

type runtimeEnvironment struct {
	ConfigPath  string `env:"ZEN_IDP_CONFIG_PATH"`
	Secret      string `env:"ZEN_IDP_SECRET"`
	StateDBPath string `env:"ZEN_IDP_DB_PATH"`
}

type configEnvironment struct {
	ConfigPath string `env:"ZEN_IDP_CONFIG_PATH"`
}

// Load returns validated runtime settings from an optional explicitly selected
// dotenv file and the process environment. Process values take precedence by
// presence.
func Load(envFilePath string) (RuntimeConfig, error) {
	var source runtimeEnvironment
	if err := parseEnvironment(envFilePath, &source); err != nil {
		return RuntimeConfig{}, err
	}

	if err := validatePath(configPathVariable, source.ConfigPath); err != nil {
		return RuntimeConfig{}, err
	}
	rootSecret, err := normalizeSecret(source.Secret)
	if err != nil {
		return RuntimeConfig{}, err
	}
	if err := validatePath(stateDBPathVariable, source.StateDBPath); err != nil {
		return RuntimeConfig{}, err
	}
	if err := validateStateDBLocation(source.StateDBPath); err != nil {
		return RuntimeConfig{}, err
	}

	return RuntimeConfig{
		ConfigPath:  source.ConfigPath,
		RootSecret:  rootSecret,
		StateDBPath: source.StateDBPath,
	}, nil
}

// LoadConfigPath returns the validated YAML selector without requiring the
// secret or state database settings used only by the running service.
func LoadConfigPath(envFilePath string) (string, error) {
	var source configEnvironment
	if err := parseEnvironment(envFilePath, &source); err != nil {
		return "", err
	}
	if err := validatePath(configPathVariable, source.ConfigPath); err != nil {
		return "", err
	}
	return source.ConfigPath, nil
}

func parseEnvironment(envFilePath string, target any) error {
	values := make(map[string]string)
	if envFilePath != "" {
		loaded, err := godotenv.Read(envFilePath)
		if err != nil {
			return fmt.Errorf("load env file %q: %w", envFilePath, err)
		}
		values = loaded
	}
	maps.Copy(values, env.ToMap(os.Environ()))
	if err := env.ParseWithOptions(target, env.Options{Environment: values}); err != nil {
		return fmt.Errorf("parse environment: %w", err)
	}
	return nil
}

func normalizeSecret(secret string) ([sha256.Size]byte, error) {
	if !utf8.ValidString(secret) || utf8.RuneCountInString(secret) < minimumSecretCharacterCount {
		return [sha256.Size]byte{}, fmt.Errorf(
			"validate environment: %s must contain at least %d valid UTF-8 characters; use `zen-idp generate-secrets` to create one",
			secretVariable,
			minimumSecretCharacterCount,
		)
	}
	return sha256.Sum256([]byte(secret)), nil
}

func validatePath(name, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("validate environment: %s must not be blank", name)
	}
	if strings.ContainsRune(value, '\x00') {
		return errors.New("validate environment: " + name + " must not contain null bytes")
	}
	return nil
}

// validateStateDBLocation verifies that SQLite can open an existing file or
// create the exact configured path.
func validateStateDBLocation(path string) error {
	info, err := os.Stat(path)
	if err == nil {
		if err := validateStateDBFile(info); err != nil {
			return err
		}
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("validate environment: inspect %s %q: %w", stateDBPathVariable, path, err)
	}

	flags := os.O_RDWR
	creating := errors.Is(err, os.ErrNotExist)
	if creating {
		flags |= os.O_CREATE | os.O_EXCL
	}
	file, err := os.OpenFile(path, flags, 0o600)
	if err != nil {
		if !creating {
			return fmt.Errorf(
				"validate environment: open %s %q: %w",
				stateDBPathVariable,
				path,
				err,
			)
		}
		return fmt.Errorf(
			"validate environment: %s %q cannot be created: %w",
			stateDBPathVariable,
			path,
			err,
		)
	}
	openedInfo, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return fmt.Errorf(
			"validate environment: inspect open %s %q: %w",
			stateDBPathVariable,
			path,
			err,
		)
	}
	if err := validateStateDBFile(openedInfo); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("validate environment: close %s %q: %w", stateDBPathVariable, path, err)
	}
	return nil
}

// validateStateDBFile checks the type and permissions of the exact file opened
// for SQLite state.
func validateStateDBFile(info fs.FileInfo) error {
	if !info.Mode().IsRegular() {
		return fmt.Errorf(
			"validate environment: %s must identify a regular file",
			stateDBPathVariable,
		)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf(
			"validate environment: %s must not grant group or world permissions",
			stateDBPathVariable,
		)
	}
	return nil
}
