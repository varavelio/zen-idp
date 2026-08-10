// Package jwt signs RS256 JSON Web Tokens (JWT) with the Zen IdP signing
// identity.
//
// # Scope
//
// This package produces the compact JWS serialization of a signed JWT: three
// unpadded Base64url segments — header, payload, and signature — joined by
// dots. It implements only what the signing identity needs:
// RSASSA-PKCS1-v1_5 with SHA-256 (RS256). It does not parse, verify, or
// decode tokens, interpret claims, or manage keys.
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
// The private key and all intermediate signed material exist only in process
// memory and must never be persisted, logged, or otherwise exposed.
package jwt
