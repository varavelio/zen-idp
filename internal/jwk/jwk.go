package jwk

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
)

// Fixed JWK member values of the v1 signing identity. They are part of the
// JWK contract and must never change.
const (
	keyTypeRSA         = "RSA"
	signatureAlgorithm = "RS256"
	keyUse             = "sig"
)

// PublicJWK is the public RSA JSON Web Key of the Zen IdP signing identity,
// ready to be published as a JWKS entry.
//
// The standard JSON serialization of this struct is the JWKS member object:
// every field is emitted with its JWK member name. Kid is the RFC 7638
// thumbprint of the key and is derived, never supplied.
type PublicJWK struct {
	// Kty is the key type, always "RSA".
	Kty string `json:"kty"`
	// N is the unpadded Base64urlUInt encoding of the modulus.
	N string `json:"n"`
	// E is the unpadded Base64urlUInt encoding of the public exponent.
	E string `json:"e"`
	// Alg is the JWS algorithm, always "RS256".
	Alg string `json:"alg"`
	// Use is the public key use, always "sig".
	Use string `json:"use"`
	// Kid is the stable RFC 7638 thumbprint of the key.
	Kid string `json:"kid"`
}

// FromPublicKey derives the public JWK and RFC 7638 key identifier of the
// given RSA public key.
//
// The result is a pure function of the key: the same key always reproduces
// the same JWK and kid, and different keys derive different kids with
// overwhelming probability. The key is used as supplied; only its public
// modulus and exponent are read.
//
// The key must be a valid RSA public key: a non-nil, odd, positive modulus
// and a positive public exponent. Anything else is rejected because it is
// outside the JWK contract.
func FromPublicKey(key *rsa.PublicKey) (PublicJWK, error) {
	if key == nil {
		return PublicJWK{}, errors.New("jwk: public key must not be nil")
	}
	if key.N == nil || key.N.Sign() <= 0 {
		return PublicJWK{}, errors.New("jwk: modulus must be a positive integer")
	}
	if key.N.Bit(0) == 0 {
		return PublicJWK{}, errors.New("jwk: modulus must be odd")
	}
	if key.E <= 0 {
		return PublicJWK{}, errors.New("jwk: public exponent must be positive")
	}

	modulus := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	exponent := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())
	return PublicJWK{
		Kty: keyTypeRSA,
		N:   modulus,
		E:   exponent,
		Alg: signatureAlgorithm,
		Use: keyUse,
		Kid: thumbprint(keyTypeRSA, modulus, exponent),
	}, nil
}

// thumbprint computes the RFC 7638 thumbprint of an RSA public key: the
// unpadded Base64url encoding of SHA-256 over the UTF-8 bytes of the
// canonical member object {"e":...,"kty":...,"n":...}, whose members are in
// lexicographic order and contain no whitespace. The Base64url alphabet of
// the member values needs no JSON escaping, so the canonical object is
// assembled literally.
func thumbprint(kty, modulus, exponent string) string {
	var canonical strings.Builder
	canonical.WriteString(`{"e":"`)
	canonical.WriteString(exponent)
	canonical.WriteString(`","kty":"`)
	canonical.WriteString(kty)
	canonical.WriteString(`","n":"`)
	canonical.WriteString(modulus)
	canonical.WriteString(`"}`)

	digest := sha256.Sum256([]byte(canonical.String()))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}
