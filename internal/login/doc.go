// Package login orchestrates TOTP authentication and authoritative session
// creation.
//
// A login attempt starts from a case-sensitive identifier and a strictly
// formatted six-digit TOTP code. The service resolves the identifier across
// the shared sub and idp_login namespace, applies per-identifier rate limits
// before any expensive work, enforces user expiration and disposable locks,
// verifies the deterministic TOTP credential with bounded clock skew, and
// finally records an authoritative SQLite-backed session whose browser token
// is returned to the caller.
//
// Rate-limit counters are keyed by the resolved user's stable subject, so
// attempts through sub and idp_login share one counter; an identifier that
// resolves to no user is keyed by the exact identifier, which keeps unknown
// identifiers bounded. Every denied attempt returns the same ErrDenied
// regardless of cause, so unknown users, wrong or malformed codes, expired
// users, locked users, and throttling cannot be told apart.
package login
