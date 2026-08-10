# Agent Context for Zen IdP

## Summary

Zen IdP is a declarative, zero-maintenance OIDC Identity Provider.

## How to Maintain This Document

Keep this file current and minimal. Update it only when repository-wide workflow, structure, or agent guidance changes. Do not turn it into a changelog. Use it exclusively to indicate truly relevant things in the codebase; don't include any minor details that are obvious or don't warrant documentation.

## Required Agent Behavior

- Always check available Skills and MCPs before acting so you know what capabilities are available for you to use.
- Always read `Taskfile.yml` to understand available `task` commands for the project; do not list those commands here.
- When assigned a task, do not respond or stop until the requested task is complete.
- Run `task ci` for code checks. If it fails, fix failures caused by your own changes until it passes; stay within the scope of your changes and ignore pre-existing unrelated failures.
- All code, code comments, inline documentation, commit messages, and any other text in the project MUST be written in English.

## Testing

Whenever possible, write tests that verify the expected behavior of the code being implemented. You must follow the following rules regarding testing:

- Write the unit tests close to the code they are testing; for example, if you have the file foo.go, you have to put all the unit tests inside foo_test.go.
- When creating tests for Go, use the testify package which is already installed in the project. Prioritize using "require" whenever possible instead of "assert" so that the tests fail quickly when something is wrong.
- Write high-value tests, focus on critical logic and relevant edge cases. Quality beats quantity; don't write tests just to inflate coverage; make sure every test adds real value.
- Treat tests as our primary tool to catch regressions. Write every test to guarantee long-term stability, correctness, functionality, and maintainability as the codebase evolves.
- Group test cases with subtests (Go): Keep all test cases for a given function inside a single top-level Test function using subtests (t.Run). This maintains a clean structure and avoids file clutter when testing multiple functions in the same file.

## Project structure

This is a Go project with a structure that aims to remain flat, simple, and idiomatic; here's a summary:

- cmd/zen-idp: The entry point of the program
- internal/config: Parses, defaults, and validates a unified YAML document into typed configuration
- internal/configloader: Discovers, composes, parses, and validates the configured YAML source
- internal/crypto: Provides cryptographic primitives and utilities
- internal/jwk: Derives the public RSA JWK and the stable RFC 7638 key identifier of the signing identity
- internal/jwt: Signs and verifies RS256 JSON Web Tokens with the deterministic signing identity
- internal/rsakeygen: Derives the deterministic RSA-2048 signing key pair from the normalized root secret
- internal/runtimeconfig: Loads and validates environment-backed runtime configuration, including an explicitly selected env file
- internal/totp: Derives the deterministic per-user TOTP shared secrets from the normalized root secret and verifies authenticator codes
- internal/yamlmerge: Merges YAML documents into one unified document
- internal/yamlsource: Discovers and reads YAML files from filesystem paths, directories, and glob patterns
