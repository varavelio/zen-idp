// Package clockcheck rejects implausible system clock conditions before Zen
// IdP becomes ready, so the service fails safely instead of operating with a
// broken clock.
//
// Every time-dependent behavior of the service — TOTP verification, session
// and token lifetimes, authorization codes, enrollment links, and user
// expiration — assumes a correct system clock. A clock set in the past keeps
// expired artifacts alive and delays user-expiration enforcement; a clock
// set far in the future invalidates everything immediately. Both conditions
// are cheaper to prevent at startup than to diagnose at runtime.
//
// The check is deliberately coarse: it only rejects instants that no real
// deployment can legitimately observe, before 2025-01-01T00:00:00Z or after
// 2100-01-01T00:00:00Z. It is a sanity gate, not a time-synchronization
// substitute; operators remain responsible for keeping the clock
// synchronized and correcting ordinary drift.
package clockcheck
