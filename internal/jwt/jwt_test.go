package jwt

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
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
// RFC 7638 thumbprint. It is shared by the signer and verifier tests.
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
