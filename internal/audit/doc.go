// Package audit records security-relevant operational events in SQLite.
//
// A recorder appends one immutable record per event: an opaque identifier,
// the canonical event instant, a category from the package's vocabulary, an
// optional affected subject or administrator, and a JSON object with
// event-specific details. The vocabulary covers the v1 administrative and
// security events: administrator authentication, enrollment-token creation
// and consumption, lock changes, panic actions, session revocation, and
// rate-limit events.
//
// Records are ephemeral operational diagnostics, not durable compliance
// history: they live in the disposable state database and disappear when
// the state file is lost. Details must never carry credentials, TOTP shared
// secrets or codes, complete cookies, complete tokens, or derived keys;
// callers are responsible for keeping recorded facts free of sensitive
// material.
//
// The recorder persists events through SQLite-backed queries and lists them
// newest first for administration.
package audit
