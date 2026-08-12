// Package session manages authoritative SQLite-backed active sessions: the
// regular SSO sessions users obtain after TOTP authentication, and the
// distinct administrator sessions obtained after administrator
// authentication.
//
// A session is created after successful authentication and grants its holder
// access until its absolute expiration. The browser credential is a single
// opaque token of the form sess_{id}_{secret}: id is the record's lookup key
// and secret is a high-entropy machine-generated value. Only the secret half
// is persisted, as an HMAC-SHA-256 digest keyed by the normalized root
// secret with a dedicated domain-separated prefix per session kind, so a
// stolen database is insufficient to impersonate a session and a credential
// of one kind can never validate as the other.
//
// Validation authenticates the token against the authoritative SQLite record
// with a constant-time comparison, enforces the record's kind and its
// absolute expiration, and rejects administrator credentials in user flows
// and user credentials in administrator flows.
//
// Revocation removes one session or every session of a subject; the latter
// is the primitive behind administrative and panic lock actions.
package session
