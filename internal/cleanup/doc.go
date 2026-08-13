// Package cleanup periodically removes disposable state records that can
// never become usable again, keeping the SQLite state database bounded.
//
// One cleanup pass purges four kinds of records, each through the domain
// package that owns it:
//
//   - rate-limit counters whose window has ended;
//   - one-use tokens whose absolute expiration has passed;
//   - sessions whose absolute expiration has passed; and
//   - audit records older than the configured retention, when a retention
//     is configured.
//
// Locks are never touched: only an authenticated administrator may clear a
// panic or administrative lock, and no cleanup pass may remove them.
//
// The package only orchestrates: every purge is delegated to the owning
// domain package through a consumer-side interface, so cleanup never depends
// on a concrete persistence implementation.
package cleanup
