// Package session manages authoritative SQLite-backed active SSO sessions.
//
// A session is created after successful authentication and grants its holder
// SSO access until its absolute expiration. The browser credential is a
// single opaque token of the form sess_{id}_{secret}: id is the record's
// lookup key and secret is a high-entropy machine-generated value. Only the
// secret half is persisted, as an HMAC-SHA-256 digest keyed by the normalized
// root secret with a dedicated domain-separated prefix, so a stolen database
// is insufficient to impersonate a session.
//
// Validation authenticates the token against the authoritative SQLite record
// with a constant-time comparison and enforces the absolute expiration.
//
// Revocation removes one session or every session of a subject; the latter
// is the primitive behind administrative and panic lock actions.
package session
