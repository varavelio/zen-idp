package jwk

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
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

// referenceModulusHex is the modulus anchored by the rsakeygen reference
// vector, reproduced here to bind both vectors to the same key.
const referenceModulusHex = "d3e839e4834639b02445bc0cd10fd2c9534f600ffa8e849d34bdf0d96676a5eb6197abc83a8b08eca47252abc2f3" +
	"cc1cca434023fb63f90ed49f5824abd63332ce9b9d8f2767fe926a590151ba9524bc46e6b56a3ce320ac6a73f434" +
	"9914aa7ac5bbe95a8c6c95d842d72dda29aa0d3d2d475dfcb4c738ac52d58b53ab4b660623b310a6992626911a7c" +
	"51d909a4478df2b90431dcc2b02a80a5344f980769765ecab2f763bc5955f8dc60b5b8f466cf19dbce15e6ec9b4b" +
	"5ae0526bb9622c113f563ecd0a2c44aa502785f52a13868612b5788a33a7b06f20def0233ca5dfa4df74e4432486" +
	"417c197374bf149fad097507a8bce9db37bcfe0d8cf5f62b3633"

// The reference vectors below were computed with an independent
// implementation of the RFC 7638 thumbprint and anchor the v1 JWK contract:
// the signing identity of the reference root secret must always reproduce
// the same modulus encoding, exponent encoding, and kid.
const (
	referenceModulusBase64URL = "0-g55INGObAkRbwM0Q_SyVNPYA_6joSdNL3w2WZ2pethl6vIOosI7KRyUqvC88wcykNAI_tj-Q7Un1gkq9YzMs6bnY8nZ_6SalkBUbqVJLxG5rVqPOMgrGpz9DSZFKp6xbvpWoxsldhC1y3aKaoNPS1HXfy0xzisUtWLU6tLZgYjsxCmmSYmkRp8UdkJpEeN8rkEMdzCsCqApTRPmAdpdl7KsvdjvFlV-Nxgtbj0Zs8Z284V5uybS1rgUmu5YiwRP1Y-zQosRKpQJ4X1KhOGhhK1eIozp7BvIN7wIzyl36TfdORDJIZBfBlzdL8Un60JdQeovOnbN7z-DYz19is2Mw"
	referenceKid              = "18o8WQf60YOSXryGuVEqiEWfO80TcNyB3FLCRWyLzsE"

	// referenceJWKJSON is the exact JSON serialization of the reference JWK
	// in declaration order, i.e. the JWKS entry published for the identity.
	referenceJWKJSON = `{"kty":"RSA","n":"0-g55INGObAkRbwM0Q_SyVNPYA_6joSdNL3w2WZ2pethl6vIOosI7KRyUqvC88wcykNAI_tj-Q7Un1gkq9YzMs6bnY8nZ_6SalkBUbqVJLxG5rVqPOMgrGpz9DSZFKp6xbvpWoxsldhC1y3aKaoNPS1HXfy0xzisUtWLU6tLZgYjsxCmmSYmkRp8UdkJpEeN8rkEMdzCsCqApTRPmAdpdl7KsvdjvFlV-Nxgtbj0Zs8Z284V5uybS1rgUmu5YiwRP1Y-zQosRKpQJ4X1KhOGhhK1eIozp7BvIN7wIzyl36TfdORDJIZBfBlzdL8Un60JdQeovOnbN7z-DYz19is2Mw","e":"AQAB","alg":"RS256","use":"sig","kid":"18o8WQf60YOSXryGuVEqiEWfO80TcNyB3FLCRWyLzsE"}`
)

// rfc7638ExampleModulus is the RSA modulus of the published RFC 7638
// section 3.1 example key, and rfc7638ExampleThumbprint is the thumbprint
// published for it. Together they anchor RFC 7638 conformance independently
// of the Zen IdP derivation.
const (
	rfc7638ExampleModulus    = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
	rfc7638ExampleThumbprint = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
)

// TestFromPublicKey covers the public JWK derivation.
func TestFromPublicKey(t *testing.T) {
	t.Run("matches the reference vector", func(t *testing.T) {
		key, err := rsakeygen.GeneratePrivateKey(referenceRootSecret)
		require.NoError(t, err)

		publicJWK, err := FromPublicKey(&key.PublicKey)
		require.NoError(t, err)

		require.Equal(t, referenceModulusHex, key.N.Text(16))
		require.Equal(t, referenceModulusBase64URL, publicJWK.N)
		require.Equal(t, "AQAB", publicJWK.E)
		require.Equal(t, "RSA", publicJWK.Kty)
		require.Equal(t, "RS256", publicJWK.Alg)
		require.Equal(t, "sig", publicJWK.Use)
		require.Equal(t, referenceKid, publicJWK.Kid)
	})

	t.Run("is deterministic", func(t *testing.T) {
		key, err := rsakeygen.GeneratePrivateKey(referenceRootSecret)
		require.NoError(t, err)

		first, err := FromPublicKey(&key.PublicKey)
		require.NoError(t, err)
		second, err := FromPublicKey(&key.PublicKey)
		require.NoError(t, err)

		require.Equal(t, first, second)
	})

	t.Run("derives a different JWK from a different key", func(t *testing.T) {
		var otherSecret [sha256.Size]byte
		otherSecret[0] = 0xab

		key, err := rsakeygen.GeneratePrivateKey(otherSecret)
		require.NoError(t, err)

		publicJWK, err := FromPublicKey(&key.PublicKey)
		require.NoError(t, err)

		require.NotEqual(t, referenceModulusBase64URL, publicJWK.N)
		require.NotEqual(t, referenceKid, publicJWK.Kid)
	})

	t.Run("matches the RFC 7638 published example", func(t *testing.T) {
		modulus, err := base64.RawURLEncoding.DecodeString(rfc7638ExampleModulus)
		require.NoError(t, err)

		publicJWK, err := FromPublicKey(&rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: 65537})
		require.NoError(t, err)

		require.Equal(t, "AQAB", publicJWK.E)
		require.Equal(t, rfc7638ExampleThumbprint, publicJWK.Kid)
	})

	t.Run("encodes a non-contract public exponent", func(t *testing.T) {
		publicJWK, err := FromPublicKey(&rsa.PublicKey{N: big.NewInt(3), E: 3})
		require.NoError(t, err)
		require.Equal(t, "Aw", publicJWK.E)
	})

	invalidKeys := map[string]struct {
		key       *rsa.PublicKey
		errorText string
	}{
		"nil key": {
			key:       nil,
			errorText: "public key must not be nil",
		},
		"nil modulus": {
			key:       &rsa.PublicKey{E: 65537},
			errorText: "modulus must be a positive integer",
		},
		"zero modulus": {
			key:       &rsa.PublicKey{N: big.NewInt(0), E: 65537},
			errorText: "modulus must be a positive integer",
		},
		"even modulus": {
			key:       &rsa.PublicKey{N: big.NewInt(4), E: 65537},
			errorText: "modulus must be odd",
		},
		"zero exponent": {
			key:       &rsa.PublicKey{N: big.NewInt(3)},
			errorText: "public exponent must be positive",
		},
	}

	for name, test := range invalidKeys {
		t.Run(name, func(t *testing.T) {
			_, err := FromPublicKey(test.key)
			require.ErrorContains(t, err, test.errorText)
		})
	}
}

// TestPublicJWKJSON covers the JWKS entry serialization of the reference JWK.
func TestPublicJWKJSON(t *testing.T) {
	t.Run("marshals to the exact reference JWKS entry", func(t *testing.T) {
		key, err := rsakeygen.GeneratePrivateKey(referenceRootSecret)
		require.NoError(t, err)
		publicJWK, err := FromPublicKey(&key.PublicKey)
		require.NoError(t, err)

		encoded, err := json.Marshal(publicJWK)
		require.NoError(t, err)
		require.Equal(t, referenceJWKJSON, string(encoded))
	})

	t.Run("contains only public members", func(t *testing.T) {
		key, err := rsakeygen.GeneratePrivateKey(referenceRootSecret)
		require.NoError(t, err)
		publicJWK, err := FromPublicKey(&key.PublicKey)
		require.NoError(t, err)

		encoded, err := json.Marshal(publicJWK)
		require.NoError(t, err)

		var members map[string]any
		require.NoError(t, json.Unmarshal(encoded, &members))
		require.Equal(
			t,
			map[string]any{
				"kty": "RSA",
				"n":   referenceModulusBase64URL,
				"e":   "AQAB",
				"alg": "RS256",
				"use": "sig",
				"kid": referenceKid,
			},
			members,
		)
	})
}
