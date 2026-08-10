// Package jwk derives the public RSA JSON Web Key (JWK) and the stable key
// identifier (kid) of the Zen IdP RS256 signing identity.
//
// # Scope
//
// This package converts the deterministic RSA-2048 signing key pair into the
// public JWK published by the JWKS endpoint. It handles only public material:
// it accepts an rsa.PublicKey, never sees private parameters, and can
// therefore never serialize or leak them.
//
// # JWK contract
//
// The derived JWK is fixed for v1:
//
//	kty: "RSA"
//	n:   unpadded Base64urlUInt encoding of the modulus
//	e:   unpadded Base64urlUInt encoding of the public exponent (65537, "AQAB")
//	alg: "RS256"
//	use: "sig"
//	kid: RFC 7638 thumbprint of the key
//
// The kid is the unpadded Base64url encoding of SHA-256 over the UTF-8 bytes
// of the canonical member object {"e":"AQAB","kty":"RSA","n":"MODULUS"},
// whose members are in lexicographic order and contain no whitespace.
//
// The derivation is a pure function of the public key: the same signing key
// always reproduces the same JWK and kid across processes, restarts, and
// supported Go versions.
//
// The JWK is public data and is safe to publish; it must never contain
// private RSA parameters.
package jwk
