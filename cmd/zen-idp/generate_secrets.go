package main

import (
	"fmt"
	"io"
)

const secretsTemplate = `
WARNING: This output contains plaintext credentials. Store it securely.

Root secret
ZEN_IDP_SECRET=%s

Administrator
plain: %s
hash: %q

OIDC client
plain: %s
hash: %q

Important:
- Store plaintext values securely.
- Put only hashes in YAML.
- Never reuse one OIDC client secret or its hash across different clients.
- Each execution creates a completely independent credential bundle.
- When adding another client, use only the new OIDC client section.
- Do not replace the root secret or administrator credentials unless intentionally rotating them.

`

// runGenerateSecrets writes an independent bootstrap secret bundle to stdout.
func runGenerateSecrets(stdout io.Writer, dependencies dependencies) error {
	bundle, err := dependencies.generateSecrets()
	if err != nil {
		return fmt.Errorf("generate secrets: %w", err)
	}
	if _, err := fmt.Fprintf(
		stdout,
		secretsTemplate,
		bundle.RootSecret,
		bundle.AdministratorPlain,
		bundle.AdministratorHash,
		bundle.OIDCClientSecretPlain,
		bundle.OIDCClientSecretHash,
	); err != nil {
		return fmt.Errorf("write generated secrets: %w", err)
	}
	return nil
}
