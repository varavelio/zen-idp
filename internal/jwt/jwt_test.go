package jwt

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"maps"
	"math/big"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/varavelio/zen-idp/internal/jwk"
	"github.com/varavelio/zen-idp/internal/rsakeygen"
)

// referenceRootSecret is the fixed root secret anchored by the rsakeygen
// reference vector, so that this package tests the same signing identity.
var referenceRootSecret = func() (secret [sha256.Size]byte) {
	decoded, err := hex.DecodeString(
		"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
	)
	if err != nil {
		panic(err)
	}
	copy(secret[:], decoded)
	return secret
}()

// referenceKid is the RFC 7638 thumbprint anchored by the jwk reference
// vector.
const referenceKid = "18o8WQf60YOSXryGuVEqiEWfO80TcNyB3FLCRWyLzsE"

// referenceClaims are the claims signed by the reference token vector.
var referenceClaims = map[string]any{
	"iss":   "https://auth.example.com",
	"sub":   "dev-01",
	"aud":   "grafana-prod",
	"iat":   int64(1700000000),
	"exp":   int64(1700000900),
	"nonce": "abc123XYZ_-",
}

// The reference vectors below were computed with an independent
// implementation of RSASSA-PKCS1-v1_5 with SHA-256 and anchor the v1 token
// contract: the signing identity of the reference root secret must always
// reproduce the same header, payload, and signature for the reference
// claims.
const (
	referenceHeader  = `{"alg":"RS256","kid":"` + referenceKid + `"}`
	referencePayload = `{"aud":"grafana-prod","exp":1700000900,"iat":1700000000,"iss":"https://auth.example.com","nonce":"abc123XYZ_-","sub":"dev-01"}`
	referenceToken   = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjE4bzhXUWY2MFlPU1hyeUd1VkVxaUVXZk84MFRjTnlCM0ZMQ1JXeUx6c0UifQ." +
		"eyJhdWQiOiJncmFmYW5hLXByb2QiLCJleHAiOjE3MDAwMDA5MDAsImlhdCI6MTcwMDAwMDAwMCwiaXNzIjoiaHR0cHM6Ly9hdXRoLmV4YW1wbGUuY29tIiwibm9uY2UiOiJhYmMxMjNYWVpfLSIsInN1YiI6ImRldi0wMSJ9." +
		"I0WO2A7bMjuv1hjAp1-FRLCiBeEdfbfWGXZa30rCLbBDKJlQ5HCduJqEdvHMzb_gOVt8fUcHEB89yNzHx66fEdkfc7rsmZc5pMfs3h1LSnKWRJF-CeWtxsGMYYebscS_uyMI7Z2oZlImiNe1MOILy2y6y3nH-DTEjeXEmFW5wgAwbYAPzHBSTiUywqSifdH_1dv6TZLu9Cj3NBmRuk39NFtoyl0JFocM0iMBfGs0zewrLCbtvh0QF0e1AHS_VYIUeLK-4h0S5sL-PWzm_tuhAHc1SiTjiTxZj7yb_51cuzV1_9rh4hhr3_hTbVgTQVbXRHWJWeN8xGk7p_T7LSbxaw"
)

// referenceIdentity derives the reference signing identity: the private key
// of the reference root secret and the signer built from that key and its
// RFC 7638 thumbprint.
func referenceIdentity(t *testing.T) (*rsa.PrivateKey, *Signer) {
	t.Helper()
	key, err := rsakeygen.GeneratePrivateKey(referenceRootSecret)
	require.NoError(t, err)
	publicJWK, err := jwk.FromPublicKey(&key.PublicKey)
	require.NoError(t, err)
	require.Equal(t, referenceKid, publicJWK.Kid)
	signer, err := NewSigner(key, publicJWK.Kid)
	require.NoError(t, err)
	return key, signer
}

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
