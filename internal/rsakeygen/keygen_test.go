package rsakeygen

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

// referenceRootSecret is the fixed root secret anchored by the reference
// vectors below.
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

// The reference vectors below were computed with an independent
// implementation of the derivation and anchor the v1 contract: the same root
// secret must always reproduce the same primes, modulus, and signature.
const (
	referencePrimePHex = "dbb5d06598b2992c6075cfd401b4932d29698542ec8572a6dfd6a704bfc654a166f5d3df53fe306c8a5f7cd67595" +
		"d4a8b7276b757ceb493b6bab7987c3a1e60890d4367a01f7f927af510918f546071301b3765c64e0389c067dba95" +
		"ab9ec2313fe4512ec10ee7343c9d6f4efabda029815e15938563a31896306edf7279468f"

	referencePrimeQHex = "f6e877dba5869d9aee650633b11382498880f1b58d4caa543840556f8302518b5859b43f37132be9ad44cac7be1a" +
		"fd4e80eb0a780b01ad0e7c579c0e03bf35a4bd9cd1b366da6031c26f4f5f135bf0ad7996fd6b622766ca63e7775c" +
		"652e3adeff56be929453a42cdd29c5e68c9a08f2a4c594ad80dc46d61d39517f4f0a481d"

	referenceModulusHex = "d3e839e4834639b02445bc0cd10fd2c9534f600ffa8e849d34bdf0d96676a5eb6197abc83a8b08eca47252abc2f3" +
		"cc1cca434023fb63f90ed49f5824abd63332ce9b9d8f2767fe926a590151ba9524bc46e6b56a3ce320ac6a73f434" +
		"9914aa7ac5bbe95a8c6c95d842d72dda29aa0d3d2d475dfcb4c738ac52d58b53ab4b660623b310a6992626911a7c" +
		"51d909a4478df2b90431dcc2b02a80a5344f980769765ecab2f763bc5955f8dc60b5b8f466cf19dbce15e6ec9b4b" +
		"5ae0526bb9622c113f563ecd0a2c44aa502785f52a13868612b5788a33a7b06f20def0233ca5dfa4df74e4432486" +
		"417c197374bf149fad097507a8bce9db37bcfe0d8cf5f62b3633"

	referenceSignatureHex = "86c111c21bfaa014544d36b1d7b5e9430158a5b0e5ac59c5b5a23e17d9b3ed1b28de86d09feacd3dccfbde469a49" +
		"f59c894e8bc94f18c682d62ff010f23efeea03e9a7d7818f6c19f9af163aa472c743f23b77cf661cedf28f1fb725" +
		"b1e07ef738c88d9b6ce848a952bae396dcdae7b37c0ed42b51eda6ad7bc2644855d2371c601c1c17a428129a0290" +
		"b3f19abc4174e03f2966eb5afecbbf06d484f66b1fee6e54e315ba6fbb8179816ac3c5bffdf6f4bf44c8f3298d37" +
		"1b9c007ba458e8784f62da8130741ea5c75c2ac3fbf68089fe188e50cd877c4abc94c7563ef185ab07f7518c501c" +
		"c03ceb035e1fd484e3286f83cd04405c47cbd7866b5d25e0a15f"
)

// referenceVectorDigest is the fixed message digest signed by the reference
// signature vector.
var referenceVectorDigest = sha256.Sum256([]byte("zen-idp:rsakeygen:reference-vector"))

// TestGeneratePrivateKey covers the deterministic RSA-2048 key derivation.
func TestGeneratePrivateKey(t *testing.T) {
	t.Run("matches the reference vector", func(t *testing.T) {
		key, err := GeneratePrivateKey(referenceRootSecret)
		require.NoError(t, err)

		require.Equal(t, referenceModulusHex, key.N.Text(16))
		require.Equal(t, referencePrimePHex, key.Primes[0].Text(16))
		require.Equal(t, referencePrimeQHex, key.Primes[1].Text(16))

		signature, err := rsa.SignPKCS1v15(
			rand.Reader,
			key,
			crypto.SHA256,
			referenceVectorDigest[:],
		)
		require.NoError(t, err)
		require.Equal(t, referenceSignatureHex, hex.EncodeToString(signature))
	})

	t.Run("is deterministic", func(t *testing.T) {
		first, err := GeneratePrivateKey(referenceRootSecret)
		require.NoError(t, err)
		second, err := GeneratePrivateKey(referenceRootSecret)
		require.NoError(t, err)

		require.Zero(t, first.N.Cmp(second.N))
		require.Zero(t, first.D.Cmp(second.D))
		require.Zero(t, first.Primes[0].Cmp(second.Primes[0]))
		require.Zero(t, first.Primes[1].Cmp(second.Primes[1]))
	})

	t.Run("derives different keys from different root secrets", func(t *testing.T) {
		var otherSecret [sha256.Size]byte
		otherSecret[0] = 0xab

		first, err := GeneratePrivateKey(referenceRootSecret)
		require.NoError(t, err)
		second, err := GeneratePrivateKey(otherSecret)
		require.NoError(t, err)

		require.NotZero(t, first.N.Cmp(second.N))
	})

	t.Run("returns a validated key ready for RS256 use", func(t *testing.T) {
		key, err := GeneratePrivateKey(referenceRootSecret)
		require.NoError(t, err)

		require.Equal(t, 2048, key.N.BitLen())
		require.Equal(t, 65537, key.E)
		require.Len(t, key.Primes, 2)
		require.True(
			t,
			key.Primes[0].Cmp(key.Primes[1]) < 0,
			"primes must be ordered so that p < q",
		)
		require.NoError(t, key.Validate())
		require.NotNil(t, key.Precomputed.Dp)
		require.NotNil(t, key.Precomputed.Dq)
		require.NotNil(t, key.Precomputed.Qinv)

		digest := sha256.Sum256([]byte("a different message"))
		signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
		require.NoError(t, err)
		require.NoError(t, rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], signature))
	})
}
