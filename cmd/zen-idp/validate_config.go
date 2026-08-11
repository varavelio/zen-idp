package main

import (
	"fmt"
	"io"
)

// runValidateConfig validates the configured YAML source and reports the
// result on stdout.
func runValidateConfig(envFile string, stdout io.Writer, dependencies dependencies) error {
	configPath, err := dependencies.loadConfigPath(envFile)
	if err != nil {
		return fmt.Errorf("load configuration path: %w", err)
	}
	if _, err := dependencies.loadConfiguration(configPath); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(stdout, "configuration is valid"); err != nil {
		return fmt.Errorf("write validation result: %w", err)
	}
	return nil
}
