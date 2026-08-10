package rsakeygen

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestHKDF pins the RFC 5869 HKDF primitives to the published test vectors
// of the standard.
func TestHKDF(t *testing.T) {
	t.Run("matches RFC 5869 test case 1", func(t *testing.T) {
		ikm := bytes.Repeat([]byte{0x0b}, 22)
		salt := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c}
		info := []byte{0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9}

		prk := hkdfExtract(salt, ikm)
		require.Equal(
			t,
			"077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
			hex.EncodeToString(prk),
		)

		okm := hkdfExpand(prk, info, sha256.Size)
		require.Equal(
			t,
			"3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf",
			hex.EncodeToString(okm),
		)
	})

	t.Run("matches RFC 5869 test case 3 with empty salt and info", func(t *testing.T) {
		ikm := bytes.Repeat([]byte{0x0b}, 22)

		prk := hkdfExtract(nil, ikm)
		require.Equal(
			t,
			"19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
			hex.EncodeToString(prk),
		)

		okm := hkdfExpand(prk, nil, sha256.Size)
		require.Equal(
			t,
			"8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d",
			hex.EncodeToString(okm),
		)
	})
}
