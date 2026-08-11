// Package server exposes Zen IdP's HTTP endpoints.
//
// The package connects the HTTP world to domain and infrastructure packages
// through values and interfaces injected at construction; handlers stay thin
// and hold no domain logic. Every handler reports failures as errors so one
// adapter can turn them into a generic response and an operational log entry.
package server
