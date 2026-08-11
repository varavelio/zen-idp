package cli

import (
	"flag"
	"fmt"
	"io"
	"strings"
)

// Command identifies one of the v1 commands.
type Command int

const (
	// Help prints the usage text.
	Help Command = iota
	// Serve runs the OIDC service.
	Serve
	// ValidateConfig validates the configured YAML source.
	ValidateConfig
	// GenerateSecrets produces an independent bootstrap secret bundle.
	GenerateSecrets
)

// Invocation is one parsed command-line invocation.
type Invocation struct {
	// Command is the selected command.
	Command Command
	// EnvFile is the explicitly selected dotenv file, empty when absent.
	EnvFile string
}

// Usage returns the command-line usage text.
func Usage() string {
	return usage
}

// UsageError describes an invalid invocation.
type UsageError struct {
	// Message describes what made the invocation invalid.
	Message string
}

// Error returns the message followed by the usage text.
func (err *UsageError) Error() string {
	return err.Message + "\n" + usage
}

// Parse interprets args as one Zen IdP command-line invocation.
//
// A help request is not an error: "help", "--help", "-h", and any known
// command followed by "--help" or "-h" produce a Help invocation. Every other
// malformed invocation returns a *UsageError.
func Parse(args []string) (Invocation, error) {
	if len(args) == 0 {
		return Invocation{}, &UsageError{Message: "a command is required"}
	}

	commandName := args[0]
	switch commandName {
	case "help", "--help", "-h":
		return Invocation{Command: Help}, nil
	case "serve", "validate-config", "generate-secrets":
		if len(args) == 2 && (args[1] == "--help" || args[1] == "-h") {
			return Invocation{Command: Help}, nil
		}
	default:
		return Invocation{}, &UsageError{Message: fmt.Sprintf("unknown command %q", commandName)}
	}

	if commandName == "generate-secrets" {
		if len(args) != 1 {
			return Invocation{}, &UsageError{Message: "generate-secrets does not accept arguments"}
		}
		return Invocation{Command: GenerateSecrets}, nil
	}

	envFile, err := parseEnvFile(commandName, args[1:])
	if err != nil {
		return Invocation{}, err
	}

	command := Serve
	if commandName == "validate-config" {
		command = ValidateConfig
	}

	return Invocation{Command: command, EnvFile: envFile}, nil
}

// parseEnvFile parses the --env-file flag of serve and validate-config.
func parseEnvFile(command string, args []string) (string, error) {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var envFile string
	flags.StringVar(&envFile, "env-file", "", "load runtime variables from PATH")
	if err := flags.Parse(args); err != nil {
		return "", &UsageError{Message: command + ": " + err.Error()}
	}

	envFileWasSet := false
	flags.Visit(func(selected *flag.Flag) {
		envFileWasSet = envFileWasSet || selected.Name == "env-file"
	})

	if envFileWasSet && strings.TrimSpace(envFile) == "" {
		return "", &UsageError{Message: command + ": --env-file must not be empty"}
	}

	if flags.NArg() != 0 {
		return "", &UsageError{Message: command + " does not accept positional arguments"}
	}

	return envFile, nil
}

const usage = `usage:
  zen-idp serve [--env-file PATH]
  zen-idp validate-config [--env-file PATH]
  zen-idp generate-secrets`
