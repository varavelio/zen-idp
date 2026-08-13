package qr

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// pngMagic is the fixed byte sequence that opens every PNG file.
var pngMagic = []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}

func TestEncode(t *testing.T) {
	t.Run("returns a PNG data URI", func(t *testing.T) {
		dataURI, err := Encode("otpauth://totp/Example:alice?secret=TEST")
		require.NoError(t, err)
		require.True(t, strings.HasPrefix(dataURI, dataURIPrefix))

		png, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(dataURI, dataURIPrefix))
		require.NoError(t, err)
		require.Equal(t, pngMagic, png[:len(pngMagic)])
	})

	t.Run("is deterministic", func(t *testing.T) {
		content := "otpauth://totp/Example:alice?secret=SECRET"

		first, err := Encode(content)
		require.NoError(t, err)
		second, err := Encode(content)
		require.NoError(t, err)

		require.Equal(t, first, second)
	})

	t.Run("differs across content", func(t *testing.T) {
		first, err := Encode("first content")
		require.NoError(t, err)
		second, err := Encode("second content")
		require.NoError(t, err)

		require.NotEqual(t, first, second)
	})

	t.Run("rejects empty content", func(t *testing.T) {
		_, err := Encode("")
		require.Error(t, err)
	})
}
