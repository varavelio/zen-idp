// Package statestore opens and migrates the embedded SQLite database that
// holds Zen IdP's disposable operational state: sessions, panic and
// administrative locks, one-use tokens, rate-limit counters, and audit
// records. It never stores identity declarations, credentials, or derived
// keys.
//
// Timestamps in the state schema use the canonical UTC RFC 3339 format with
// second precision defined by internal/clock.
package statestore
