package vectors_test

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/varavelio/zen-idp/internal/jwk"
	"github.com/varavelio/zen-idp/internal/rsakeygen"
	"github.com/varavelio/zen-idp/internal/totp"
)

// v1JSON is the frozen vectors document embedded with the package, so the
// verification never depends on the working directory or repository
// layout.
//
//go:embed v1.json
var v1JSON []byte

// v1Document mirrors the frozen v1.json document. Unknown fields are
// rejected when the document is loaded, so it cannot drift from this
// schema unnoticed.
type v1Document struct {
	Version          int    `json:"version"`
	Description      string `json:"description"`
	RootSecret       string `json:"root_secret"`
	RootSecretSHA256 string `json:"root_secret_sha256"`
	Derivation       struct {
		Hash              string `json:"hash"`
		RSADomainLabel    string `json:"rsa_domain_label"`
		RSAModulusBits    int    `json:"rsa_modulus_bits"`
		RSAPublicExponent int    `json:"rsa_public_exponent"`
		TOTPDomainLabel   string `json:"totp_domain_label"`
		TOTPBase32        string `json:"totp_base32_encoding"`
	} `json:"derivation"`
	JWT struct {
		ModulusN  string `json:"modulus_n"`
		ExponentE string `json:"exponent_e"`
		Kid       string `json:"kid"`
	} `json:"jwt"`
	Signature struct {
		Input       string `json:"input"`
		Description string `json:"input_description"`
		RS256       string `json:"rs256"`
	} `json:"signature"`
	TOTP []struct {
		Sub      string `json:"sub"`
		Revision uint64 `json:"revision"`
		Secret   string `json:"secret"`
	} `json:"totp"`
}

// TestV1Vectors verifies that the current derivation reproduces the frozen
// v1 vectors byte for byte. The root secret is normalized once and every
// contract is checked in its own subtest against the exact entry points
// the service wires.
func TestV1Vectors(t *testing.T) {
	vectors := loadV1Vectors(t)
	require.Equal(t, 1, vectors.Version, "only the current version is verified")
	rootSecret := sha256.Sum256([]byte(vectors.RootSecret))

	t.Run("normalizes the source secret", func(t *testing.T) {
		require.Equal(
			t,
			vectors.RootSecretSHA256,
			hex.EncodeToString(rootSecret[:]),
		)
	})

	t.Run("derives the RSA signing identity", func(t *testing.T) {
		key, err := rsakeygen.GeneratePrivateKey(rootSecret)
		require.NoError(t, err)
		require.Equal(t, vectors.Derivation.RSAModulusBits, key.N.BitLen())
		require.Equal(t, vectors.Derivation.RSAPublicExponent, key.E)
		require.Equal(
			t,
			vectors.JWT.ModulusN,
			base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		)
	})

	t.Run("derives the public JWK and kid", func(t *testing.T) {
		key, err := rsakeygen.GeneratePrivateKey(rootSecret)
		require.NoError(t, err)
		public, err := jwk.FromPublicKey(&key.PublicKey)
		require.NoError(t, err)
		require.Equal(t, vectors.JWT.ModulusN, public.N)
		require.Equal(t, vectors.JWT.ExponentE, public.E)
		require.Equal(t, vectors.JWT.Kid, public.Kid)
	})

	t.Run("produces the representative RS256 signature", func(t *testing.T) {
		key, err := rsakeygen.GeneratePrivateKey(rootSecret)
		require.NoError(t, err)
		digest := sha256.Sum256([]byte(vectors.Signature.Input))
		signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
		require.NoError(t, err)
		require.Equal(
			t,
			vectors.Signature.RS256,
			base64.RawURLEncoding.EncodeToString(signature),
		)
	})

	t.Run("derives the TOTP shared secrets", func(t *testing.T) {
		require.NotEmpty(t, vectors.TOTP)
		for _, vector := range vectors.TOTP {
			secret, err := totp.DeriveSharedSecret(rootSecret, vector.Sub, vector.Revision)
			require.NoError(t, err)
			require.Equal(
				t,
				vector.Secret,
				secret,
				"sub %q revision %d",
				vector.Sub,
				vector.Revision,
			)
		}
	})
}

// loadV1Vectors decodes the embedded vectors document, rejecting unknown
// fields so the schema cannot drift.
func loadV1Vectors(t *testing.T) v1Document {
	t.Helper()
	var document v1Document
	decoder := json.NewDecoder(bytes.NewReader(v1JSON))
	decoder.DisallowUnknownFields()
	require.NoError(t, decoder.Decode(&document))
	return document
}
