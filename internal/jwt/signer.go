package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// Signer signs RS256 JSON Web Tokens with the Zen IdP signing identity.
//
// A Signer is immutable after construction: the private key and the kid
// published in the JOSE header are fixed for its lifetime, so the same
// claims always reproduce the same token.
type Signer struct {
	key    *rsa.PrivateKey
	header string
}

// NewSigner returns a Signer that signs with the given private key and
// publishes the given kid in the JOSE header of every token.
//
// The key must be a valid RSA private key. The kid must be the RFC 7638
// thumbprint of the key's public part: the unpadded Base64url encoding of a
// 32-byte value. Anything else is rejected because it is outside the token
// contract.
func NewSigner(key *rsa.PrivateKey, kid string) (*Signer, error) {
	if key == nil {
		return nil, errors.New("jwt: private key must not be nil")
	}
	if err := key.Validate(); err != nil {
		return nil, fmt.Errorf("jwt: invalid private key: %w", err)
	}
	if err := validateKid(kid); err != nil {
		return nil, err
	}
	header := base64.RawURLEncoding.EncodeToString(
		[]byte(`{"alg":"` + algorithm + `","kid":"` + kid + `"}`),
	)
	return &Signer{key: key, header: header}, nil
}

// Sign returns the compact JWS serialization of a token carrying the given
// claims: the JOSE header, the unpadded Base64url encoding of the JSON
// claims, and the RS256 signature over the exact bytes of
// header + "." + payload, joined by dots.
//
// The claims are encoded with their keys in sorted order, so the same claims
// always produce the same token. nil claims are rejected, as are claims that
// cannot be represented as JSON.
func (signer *Signer) Sign(claims map[string]any) (string, error) {
	if claims == nil {
		return "", errors.New("jwt: claims must not be nil")
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("jwt: encode claims: %w", err)
	}

	signingInput := signer.header + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, signer.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("jwt: sign token: %w", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}
