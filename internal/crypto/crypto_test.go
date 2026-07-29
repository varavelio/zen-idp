package crypto

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerateRootSecret(t *testing.T) {
	t.Run("returns a secret from operating-system randomness", func(t *testing.T) {
		secret, err := GenerateRootSecret()
		require.NoError(t, err)

		decoded, err := hex.DecodeString(secret)
		require.NoError(t, err)
		require.Len(t, decoded, rootSecretLength)
		require.Len(t, secret, hex.EncodedLen(rootSecretLength))
	})

	t.Run("encodes every byte from the randomness source", func(t *testing.T) {
		randomBytes := bytes.Repeat([]byte{0xff}, rootSecretLength)

		secret, err := generateRootSecret(bytes.NewReader(randomBytes))
		require.NoError(t, err)

		decoded, err := hex.DecodeString(secret)
		require.NoError(t, err)
		require.Equal(t, randomBytes, decoded)
		require.Equal(t, strings.Repeat("ff", rootSecretLength), secret)
	})

	t.Run("propagates a randomness source error", func(t *testing.T) {
		randomnessErr := errors.New("randomness unavailable")

		secret, err := generateRootSecret(failingReader{err: randomnessErr})

		require.Empty(t, secret)
		require.ErrorIs(t, err, randomnessErr)
		require.ErrorContains(t, err, "generate root secret: read random bytes")
	})

	t.Run("rejects insufficient randomness", func(t *testing.T) {
		secret, err := generateRootSecret(strings.NewReader("insufficient"))

		require.Empty(t, secret)
		require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	})
}

type failingReader struct {
	err error
}

func (reader failingReader) Read([]byte) (int, error) {
	return 0, reader.err
}
