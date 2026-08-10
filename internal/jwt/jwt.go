package jwt

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

// algorithm is the fixed JWS signature algorithm of every token issued by
// this package. It is part of the token contract and must never change. It
// is used both to build the JOSE header of signed tokens and to require the
// algorithm of verified tokens.
const algorithm = "RS256"

// validateKid requires kid to be the unpadded Base64url encoding of exactly
// 32 bytes, the shape of an RFC 7638 thumbprint. It is the shared kid
// contract of the Signer and Verifier constructors.
func validateKid(kid string) error {
	if kid == "" {
		return errors.New("jwt: kid must not be empty")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(kid)
	if err != nil {
		return errors.New("jwt: kid must be unpadded Base64url")
	}
	if len(decoded) != sha256.Size {
		return fmt.Errorf("jwt: kid must decode to %d bytes", sha256.Size)
	}
	return nil
}
