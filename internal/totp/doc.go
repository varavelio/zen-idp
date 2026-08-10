// Package totp derives the deterministic per-user TOTP shared secrets used by
// Zen IdP authentication and verifies authenticator codes against them.
//
// # Scope
//
// The package implements both halves of the TOTP credential domain:
//
//   - DeriveSharedSecret derives the deterministic per-user shared secret
//     from the normalized root secret, the exact sub, and the effective
//     TOTP revision.
//   - VerifyCode checks a submitted code against a derived secret using the
//     RFC 6238 authenticator profile: HMAC-SHA-1, a 30-second step, six
//     decimal digits, and at most one adjacent step in either direction
//     for clock skew.
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
