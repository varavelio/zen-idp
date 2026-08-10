package jwt

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Verifier validates tokens of the Zen IdP signing identity and returns
// their claims.
//
// A Verifier is immutable after construction: it accepts only tokens whose
// JOSE header declares RS256 and the verifier's kid, and whose signature
// validates against the verifier's public key. It never sees private key
// material.
type Verifier struct {
	key *rsa.PublicKey
	kid string
}

// NewVerifier returns a Verifier that accepts only tokens signed by the key
// identified by the given kid.
//
// The key must be a valid RSA public key. The kid must be the RFC 7638
// thumbprint of the key: the unpadded Base64url encoding of a 32-byte value.
// Anything else is rejected because it is outside the token contract.
func NewVerifier(key *rsa.PublicKey, kid string) (*Verifier, error) {
	if key == nil {
		return nil, errors.New("jwt: public key must not be nil")
	}
	if key.N == nil || key.N.Sign() <= 0 {
		return nil, errors.New("jwt: modulus must be a positive integer")
	}
	if key.N.Bit(0) == 0 {
		return nil, errors.New("jwt: modulus must be odd")
	}
	if key.E <= 0 {
		return nil, errors.New("jwt: public exponent must be positive")
	}
	if err := validateKid(kid); err != nil {
		return nil, err
	}
	return &Verifier{key: key, kid: kid}, nil
}

// Verify returns the claims of a token of the signing identity, or an error
// if the token is not authentic.
//
// A token is accepted only when it has exactly three compact segments, its
// JOSE header declares alg "RS256" and the verifier's kid, and its signature
// validates against the verifier's public key. The header algorithm is
// matched exactly and never trusted from the token: anything other than
// RS256 is rejected. Claim semantics (expiration, issuer, audience) are not
// evaluated here.
func (verifier *Verifier) Verify(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("jwt: token must have exactly three segments")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("jwt: invalid header encoding")
	}
	var header headerDocument
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, errors.New("jwt: invalid header")
	}
	if header.Alg != algorithm {
		return nil, fmt.Errorf("jwt: unsupported algorithm %q", header.Alg)
	}
	if header.Kid != verifier.kid {
		return nil, errors.New("jwt: kid mismatch")
	}

	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("jwt: invalid signature encoding")
	}
	if err := rsa.VerifyPKCS1v15(verifier.key, crypto.SHA256, digest[:], signature); err != nil {
		return nil, errors.New("jwt: invalid signature")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("jwt: invalid payload encoding")
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("jwt: decode token payload: %w", err)
	}
	if claims == nil {
		return nil, errors.New("jwt: token payload must be a JSON object")
	}
	return claims, nil
}

// headerDocument is the JOSE header shape accepted by Verify: only the alg
// and kid members are read; any other members are ignored.
type headerDocument struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}
