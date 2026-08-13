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

## Data Storage

- Generated record identifiers used as SQLite primary keys MUST be TypeID values stored as TEXT.
- Operator-declared natural keys, such as the YAML `sub` identifier, remain as declared and are not converted to TypeIDs.

## Project structure

This is a Go project with a structure that aims to remain flat, simple, and idiomatic; here's a summary:

- cmd/zen-idp: The entry point of the program
- internal/admin: Authenticates the administrator, creates the distinct administrator sessions that gate the administrative interfaces, and records authentication and rate-limit events
- internal/audit: Records security-relevant operational events as disposable SQLite-backed audit records and enforces their retention by purging records older than the configured deadline
- internal/cli: Parses Zen IdP command-line invocations into typed commands
- internal/clock: Formats and parses the canonical UTC RFC 3339 timestamps used by the state database
- internal/clockcheck: Rejects implausible system clock conditions at startup so the service fails safely
- internal/cleanup: Periodically removes disposable state that can never become usable again (expired rate-limit counters, one-use tokens, sessions, and retained audit records), never touching locks
- internal/config: Parses, defaults, and validates a unified YAML document into typed configuration
- internal/configloader: Discovers, composes, parses, and validates the configured YAML source
- internal/crypto: Provides cryptographic primitives and utilities
- internal/csrf: Protects state-changing browser actions from cross-site request forgery with double-submit anti-forgery tokens
- internal/id: Generates prefix-less TypeID identifiers for state records
- internal/jwk: Derives the public RSA JWK and the stable RFC 7638 key identifier of the signing identity
- internal/jwt: Signs and verifies RS256 JSON Web Tokens with the deterministic signing identity
- internal/lock: Manages the disposable panic and administrative locks that gate login and SSO use; administrative locking and the user panic action atomically revoke the subject's sessions with the lock creation
- internal/login: Orchestrates identifier resolution, rate limiting, lock enforcement, TOTP verification, authoritative session creation, and rate-limit audit events
- internal/onetoken: Creates and atomically consumes disposable SQLite-backed one-use tokens, covering enrollment tokens and OIDC authorization-code bindings
- internal/qr: Renders QR codes as inline PNG data URIs for the enrollment interaction
- internal/rsakeygen: Derives the deterministic RSA-2048 signing key pair from the normalized root secret
- internal/ratelimit: Enforces per-key failed-attempt limits over fixed windows with SQLite-backed atomic counters
- internal/runtimeconfig: Loads and validates environment-backed runtime configuration, including an explicitly selected env file
- internal/server: Exposes Zen IdP's HTTP endpoints with injected dependencies and centralized error handling
- internal/session: Creates, validates, revokes, and purges authoritative SQLite-backed SSO sessions and distinct administrator sessions from sess_{id}_{secret} browser tokens, with per-kind domain-separated secret digests
- internal/statestore: Opens and migrates the embedded SQLite state database with goose migrations and sqlc-generated queries, and runs sqlc functions inside database transactions with WithTx; SQL migrations live in internal/statestore/migrations and query sources in internal/statestore/queries
- internal/token: Issues the RS256-signed ID and access tokens of the deterministic signing identity with fixed 900-second lifetimes
- internal/totp: Derives the deterministic per-user TOTP shared secrets from the normalized root secret, builds their otpauth enrollment URIs, and verifies authenticator codes
- internal/ui: Renders the HTML pages served by Zen IdP with NodX and embeds the static assets (compiled stylesheet, vendored fonts, and scripts)
- internal/userinfo: Validates access tokens and resolves the current claims of their subject from the active configuration
- internal/yamlmerge: Merges YAML documents into one unified document
- internal/yamlsource: Discovers and reads YAML files from filesystem paths, directories, and glob patterns
