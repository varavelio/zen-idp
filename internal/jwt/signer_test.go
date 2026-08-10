package jwt

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"maps"
	"math/big"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/varavelio/zen-idp/internal/rsakeygen"
)

// TestNewSigner covers signer construction and its input validation.
func TestNewSigner(t *testing.T) {
	t.Run("builds a signer for the reference identity", func(t *testing.T) {
		_, signer := referenceIdentity(t)
		require.NotNil(t, signer)
	})

	key, err := rsakeygen.GeneratePrivateKey(referenceRootSecret)
	require.NoError(t, err)

	invalidSigners := map[string]struct {
		key       *rsa.PrivateKey
		kid       string
		errorText string
	}{
		"nil key": {
			key:       nil,
			kid:       referenceKid,
			errorText: "private key must not be nil",
		},
		"invalid key": {
			key: &rsa.PrivateKey{
				PublicKey: rsa.PublicKey{N: big.NewInt(21), E: 65537},
				D:         big.NewInt(1),
				Primes:    []*big.Int{big.NewInt(3), big.NewInt(5)},
			},
			kid:       referenceKid,
			errorText: "invalid private key",
		},
		"empty kid": {
			key:       key,
			errorText: "kid must not be empty",
		},
		"kid is not base64url": {
			key:       key,
			kid:       "not base64!",
			errorText: "kid must be unpadded Base64url",
		},
		"kid is not a 32-byte thumbprint": {
			key:       key,
			kid:       "AQAB",
			errorText: "kid must decode to 32 bytes",
		},
	}

	for name, test := range invalidSigners {
		t.Run(name, func(t *testing.T) {
			_, err := NewSigner(test.key, test.kid)
			require.ErrorContains(t, err, test.errorText)
		})
	}
}

// TestSign covers token signing against the reference vector and the
// structural properties of the produced tokens.
func TestSign(t *testing.T) {
	key, signer := referenceIdentity(t)

	t.Run("matches the reference vector", func(t *testing.T) {
		token, err := signer.Sign(referenceClaims)
		require.NoError(t, err)
		require.Equal(t, referenceToken, token)
	})

	t.Run("is deterministic", func(t *testing.T) {
		first, err := signer.Sign(referenceClaims)
		require.NoError(t, err)
		second, err := signer.Sign(referenceClaims)
		require.NoError(t, err)
		require.Equal(t, first, second)
	})

	t.Run("changes with the claims", func(t *testing.T) {
		base, err := signer.Sign(referenceClaims)
		require.NoError(t, err)

		otherClaims := maps.Clone(referenceClaims)
		otherClaims["sub"] = "contractor-23"
		changed, err := signer.Sign(otherClaims)
		require.NoError(t, err)
		require.NotEqual(t, base, changed)
	})

	t.Run("carries the expected header and a verifiable signature", func(t *testing.T) {
		token, err := signer.Sign(referenceClaims)
		require.NoError(t, err)

		parts := strings.Split(token, ".")
		require.Len(t, parts, 3)

		header, err := base64.RawURLEncoding.DecodeString(parts[0])
		require.NoError(t, err)
		require.Equal(t, referenceHeader, string(header))

		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		require.NoError(t, err)
		require.Equal(t, referencePayload, string(payload))

		signature, err := base64.RawURLEncoding.DecodeString(parts[2])
		require.NoError(t, err)
		digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		require.NoError(t, rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], signature))
	})

	t.Run("rejects nil claims", func(t *testing.T) {
		_, err := signer.Sign(nil)
		require.ErrorContains(t, err, "claims must not be nil")
	})

	t.Run("rejects claims that are not JSON serializable", func(t *testing.T) {
		_, err := signer.Sign(map[string]any{"bad": make(chan int)})
		require.ErrorContains(t, err, "encode claims")
	})
}
