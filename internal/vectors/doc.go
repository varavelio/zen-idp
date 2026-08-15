// Package vectors verifies the frozen v1 deterministic derivation
// vectors: the source root secret must normalize to the stored digest,
// derive the stored RSA-2048 signing identity and RFC 7638 kid, produce
// the stored representative RS256 signature over the stored input bytes,
// and derive the stored TOTP shared secrets.
//
// The embedded v1.json file is the immutable anchor of the v1 derivation
// contract. Every test in this package reproduces the derivation with the
// exact entry points the service wires and compares against the frozen
// values, so any refactor or Go upgrade that changes the contract fails
// here without touching the file. A deliberate contract change must be
// published as a new versioned file and verified by a new test; the v1
// vectors are never edited.
package vectors
