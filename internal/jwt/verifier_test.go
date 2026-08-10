package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/varavelio/zen-idp/internal/rsakeygen"
)

// TestNewVerifier covers verifier construction and its input validation.
func TestNewVerifier(t *testing.T) {
	t.Run("builds a verifier for the reference identity", func(t *testing.T) {
		key, _ := referenceIdentity(t)
		verifier, err := NewVerifier(&key.PublicKey, referenceKid)
		require.NoError(t, err)
		require.NotNil(t, verifier)
	})

	invalidVerifiers := map[string]struct {
		key       *rsa.PublicKey
		kid       string
		errorText string
	}{
		"nil key": {
			key:       nil,
			kid:       referenceKid,
			errorText: "public key must not be nil",
		},
		"nil modulus": {
			key:       &rsa.PublicKey{E: 65537},
			kid:       referenceKid,
			errorText: "modulus must be a positive integer",
		},
		"even modulus": {
			key:       &rsa.PublicKey{N: big.NewInt(4), E: 65537},
			kid:       referenceKid,
			errorText: "modulus must be odd",
		},
		"zero exponent": {
			key:       &rsa.PublicKey{N: big.NewInt(3)},
			kid:       referenceKid,
			errorText: "public exponent must be positive",
		},
		"empty kid": {
			key:       &rsa.PublicKey{N: big.NewInt(3), E: 65537},
			errorText: "kid must not be empty",
		},
	}

	for name, test := range invalidVerifiers {
		t.Run(name, func(t *testing.T) {
			_, err := NewVerifier(test.key, test.kid)
			require.ErrorContains(t, err, test.errorText)
		})
	}
}

// TestVerify covers token verification against the reference vector and the
// rejection of inauthentic tokens.
func TestVerify(t *testing.T) {
	key, signer := referenceIdentity(t)
	verifier, err := NewVerifier(&key.PublicKey, referenceKid)
	require.NoError(t, err)

	t.Run("verifies the reference token", func(t *testing.T) {
		claims, err := verifier.Verify(referenceToken)
		require.NoError(t, err)

		encoded, err := json.Marshal(claims)
		require.NoError(t, err)
		require.Equal(t, referencePayload, string(encoded))
	})

	t.Run("round-trips a token signed by the signer", func(t *testing.T) {
		token, err := signer.Sign(referenceClaims)
		require.NoError(t, err)

		claims, err := verifier.Verify(token)
		require.NoError(t, err)
		require.Equal(t, "dev-01", claims["sub"])
		require.Equal(t, "https://auth.example.com", claims["iss"])
		require.Equal(t, float64(1700000900), claims["exp"])
	})

	t.Run("rejects a token signed by another key", func(t *testing.T) {
		var otherSecret [sha256.Size]byte
		otherSecret[0] = 0xab
		otherKey, err := rsakeygen.GeneratePrivateKey(otherSecret)
		require.NoError(t, err)

		// Sign with the other key while publishing the reference kid: only
		// the signature check can catch the forgery.
		forger, err := NewSigner(otherKey, referenceKid)
		require.NoError(t, err)
		token, err := forger.Sign(referenceClaims)
		require.NoError(t, err)

		_, err = verifier.Verify(token)
		require.ErrorContains(t, err, "invalid signature")
	})

	referenceParts := strings.Split(referenceToken, ".")
	payloadSegment := base64.RawURLEncoding.EncodeToString([]byte(`{}`))
	noneHeader := base64.RawURLEncoding.EncodeToString(
		[]byte(`{"alg":"none","kid":"` + referenceKid + `"}`),
	)
	rs256Header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))
	wrongKidHeader := base64.RawURLEncoding.EncodeToString(
		[]byte(`{"alg":"RS256","kid":"` + strings.Repeat("A", 43) + `"}`),
	)

	invalidTokens := map[string]struct {
		token     string
		errorText string
	}{
		"wrong segment count": {
			token:     "a.b",
			errorText: "exactly three segments",
		},
		"invalid header encoding": {
			token:     "!!!." + payloadSegment + "." + payloadSegment,
			errorText: "invalid header encoding",
		},
		"unsupported algorithm": {
			token:     noneHeader + "." + payloadSegment + "." + payloadSegment,
			errorText: `unsupported algorithm "none"`,
		},
		"missing kid": {
			token:     rs256Header + "." + payloadSegment + "." + payloadSegment,
			errorText: "kid mismatch",
		},
		"wrong kid": {
			token:     wrongKidHeader + "." + payloadSegment + "." + payloadSegment,
			errorText: "kid mismatch",
		},
		"invalid signature encoding": {
			token:     referenceParts[0] + "." + referenceParts[1] + ".!!!",
			errorText: "invalid signature encoding",
		},
		"tampered payload": {
			token: referenceParts[0] + "." + tamperSegment(
				t,
				referenceParts[1],
			) + "." + referenceParts[2],
			errorText: "invalid signature",
		},
		"tampered signature": {
			token: referenceParts[0] + "." + referenceParts[1] + "." + tamperSegment(
				t,
				referenceParts[2],
			),
			errorText: "invalid signature",
		},
		"non-object payload": {
			token: signParts(
				t,
				key,
				referenceParts[0],
				base64.RawURLEncoding.EncodeToString([]byte(`[1,2]`)),
			),
			errorText: "decode token payload",
		},
		"null payload": {
			token: signParts(
				t,
				key,
				referenceParts[0],
				base64.RawURLEncoding.EncodeToString([]byte(`null`)),
			),
			errorText: "must be a JSON object",
		},
	}

	for name, test := range invalidTokens {
		t.Run(name, func(t *testing.T) {
			_, err := verifier.Verify(test.token)
			require.ErrorContains(t, err, test.errorText)
		})
	}
}

// tamperSegment flips one byte of the decoded segment and re-encodes it.
func tamperSegment(t *testing.T, segment string) string {
	t.Helper()
	decoded, err := base64.RawURLEncoding.DecodeString(segment)
	require.NoError(t, err)
	decoded[len(decoded)-1] ^= 0x01
	return base64.RawURLEncoding.EncodeToString(decoded)
}

// signParts signs the given header and payload segments with the reference
// key, producing a token whose signature is valid.
func signParts(t *testing.T, key *rsa.PrivateKey, header, payload string) string {
	t.Helper()
	signingInput := header + "." + payload
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	require.NoError(t, err)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}
