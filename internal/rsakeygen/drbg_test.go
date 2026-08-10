package rsakeygen

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestDRBG pins the HMAC-DRBG-SHA-256 stream to independently computed
// reference blocks, including the post-generation update between them.
func TestDRBG(t *testing.T) {
	seed, err := hex.DecodeString(
		"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
	)
	require.NoError(t, err)

	stream := newDRBG(seed)
	first := stream.generate(128)
	second := stream.generate(128)

	t.Run("matches the first reference block", func(t *testing.T) {
		require.Equal(
			t,
			"7f9533ad83d815a860dd8ef577f3b9b81178449bf35cdf581ef4ba92b718f041e29c91d582789c32a8f282adc9201941"+
				"419542852298651e1c1e2fbf4cb5cedf193d6ffcdf7fa25bf607d588fdae687bf353d1faf5af6d4380241937b53938c62"+
				"dad3497f36ddfe8bb674070eaaac491bc3d4015b2cb53e09a79f96ee7a10e69",
			hex.EncodeToString(first),
		)
	})

	t.Run("matches the second reference block", func(t *testing.T) {
		require.Equal(
			t,
			"8a6742a8d7daac02ea62a9ad3393857a8ada28985b03658d126f4be530c93cb1afff0567cc62afe77134d15e461d5ad3"+
				"258d2a75324b5ed7c28d929ce3135cb31931072af5e52af28fec728e0d1d1ea90b96dfe21e3d6e5f8b660492f82d968f"+
				"de125194f96fc2cede6dfad5d521d7ac50f534e33f00aa2a2bfa521d11a4214f",
			hex.EncodeToString(second),
		)
	})
}
