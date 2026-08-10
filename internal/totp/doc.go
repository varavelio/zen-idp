// Package totp derives the deterministic per-user TOTP shared secrets used by
// Zen IdP authentication.
//
// # Scope
//
// This package implements only the deterministic per-user shared-secret
// derivation. It does not generate or verify TOTP codes; the derived secret
// is a standard RFC 4648 Base32 value that any RFC 6238 authenticator
// (HMAC-SHA-1, 30-second step, six digits) consumes directly.
//
// # Derivation contract
//
// For the normalized 32-byte root secret, the exact configured sub, and the
// effective non-negative TOTP revision, the shared secret is:
//
//	message      = "zen-idp:totp:" || sub || ":" || revision
//	digest       = HMAC-SHA-256(key = rootSecret, message = message)
//	sharedSecret = uppercase RFC 4648 Base32 of digest, without padding
//
// The revision is encoded as unsigned decimal ASCII with no sign, whitespace,
// or leading zeros; revision zero is encoded as "0". The sub bytes are used
// exactly as configured, without case conversion, normalization, trimming, or
// substitution.
//
// The derivation is deterministic and independent of any state store: the
// same root secret, sub, and revision reproduce the same shared secret across
// restarts and Go versions.
package totp
