// Package userinfo resolves the authenticated identity of an access token
// into the current claims of its subject, backing the /userinfo endpoint.
//
// A resolution starts from a compact access token of the signing identity.
// The token must be authentic, must carry the stable key identifier and the
// RS256 algorithm, must be stamped with the configured issuer and the
// dedicated /userinfo audience, and must not be expired. The subject must
// still be declared in the active in-memory YAML configuration, must not be
// expired, and must not be gated by a panic or administrative lock. Where
// the token is bound to a session through its jti claim, the session record
// must still exist, must belong to the token's subject, and must carry the
// subject's current TOTP revision.
//
// The returned claim set is sub plus every current custom claim from the
// active configuration. SQLite may prove session and lock state but never
// supplies identity claims. Every rejected resolution returns the same
// ErrDenied regardless of cause, so unauthentic or expired tokens, removed
// or expired users, locked users, and revoked or stale sessions cannot be
// told apart.
package userinfo
