//go:build e2e

// Package e2e contains the black-box end-to-end test suite of Zen IdP.
//
// Every test drives the compiled zen-idp executable exclusively through its
// command line and HTTP surface: no internal package is ever imported, and
// every cryptographic expectation is computed with the independent helpers
// of the e2e/harness package. Each test file covers one complete product
// scenario, and each test runs against its own isolated instance with a
// dedicated configuration, state database, and loopback port.
//
// The suite is opt-in and compiled only under the e2e build tag:
//
//	go test -tags e2e -count=1 -timeout 10m ./e2e/
package e2e
