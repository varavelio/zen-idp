// Package rsakeygen deterministically derives the RSA-2048 key pair that Zen
// IdP uses for RS256 JWT signatures from the normalized 32-byte root secret.
//
// The derivation is a pure function of the root secret: the same input always
// reproduces the same key pair, across processes, restarts, and supported Go
// versions. It is versioned and domain-separated from every other root-secret
// derivation, so that exposing one derived value never reveals another.
//
// The returned key is fully validated, including a sign-and-verify
// self-test, before it is returned. The key and all intermediate material
// exist only in process memory and must never be persisted, logged, or
// otherwise exposed.
package rsakeygen
