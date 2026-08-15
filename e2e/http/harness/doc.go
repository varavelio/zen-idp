//go:build e2e

// Package harness drives black-box Zen IdP instances for the end-to-end
// test suite in the parent directory.
//
// A Harness writes an isolated YAML configuration into a per-test directory,
// binds a free loopback port, spawns the pre-built zen-idp executable with a
// dedicated state database, and waits until the discovery endpoint answers.
// Every test interacts with the instance exclusively through its HTTP
// surface with a browser-like cookie jar that never follows redirects, so
// tests can inspect every redirect target.
//
// The package intentionally never imports Zen IdP internal packages: its
// cryptographic helpers reproduce the TOTP, PKCE, and JWT contracts
// independently, so the suite validates them as a black box exactly like an
// external relying party would.
//
// The suite is opt-in and compiled only under the e2e build tag:
//
//	go test -tags e2e -count=1 -timeout 10m ./e2e/...
package harness
