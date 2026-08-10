// Package jwt signs and verifies RS256 JSON Web Tokens (JWT) with the Zen
// IdP signing identity.
//
// # Scope
//
// This package produces the compact JWS serialization of a signed JWT: three
// unpadded Base64url segments — header, payload, and signature — joined by
// dots, and verifies such tokens back to their claims. It implements only
// what the signing identity needs: RSASSA-PKCS1-v1_5 with SHA-256 (RS256).
// It does not enforce claim semantics such as expiration, issuer, or
// audience, and it does not manage keys.
//
// # Token contract
//
// Every token issued by a Signer carries the same JOSE header for the
// lifetime of that signer:
//
//	{"alg":"RS256","kid":"<RFC 7638 thumbprint>"}
//
// The payload is the JSON encoding of the claims supplied to Sign, and the
// signature covers the exact UTF-8 bytes of header + "." + payload.
//
// Signing is deterministic: the same claims always reproduce the same token,
// and any RS256 verifier holding the corresponding public key can validate
// the result.
//
// # Verification contract
//
// Verify accepts only tokens of the signing identity: exactly three compact
// segments, a JOSE header whose alg member is exactly "RS256" and whose kid
// member matches the verifier's, and a signature that validates against the
// verifier's public key. The header algorithm is matched exactly and never
// trusted from the token, so tokens that omit the algorithm or declare any
// other one are rejected before any claim is returned.
//
// The private key and all intermediate signed material exist only in process
// memory and must never be persisted, logged, or otherwise exposed.
package jwt
