package session

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

// referenceRootSecret is the fixed normalized root secret anchored by the
// rsakeygen reference vector, so that every package tests the same identity.
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

// referenceSecret is the fixed machine secret hashed by the reference
// vector below.
const referenceSecret = "B4t3Rqp0lsFNb1r0Ws9xQx7Y8TfK7cH2mN5sV3uZ9aD"

func TestParseToken(t *testing.T) {
	valid := formatToken("01h2v8d9q3m5t7w0x2y4a6c8e", "aZ9kM2pQ7sW4xR8vT3nB6cD1fG5hJ0kL9mN2pQ4s")

	tests := map[string]struct {
		token string
	}{
		"wrong prefix":        {token: "other_01h2v8d9q3m5t7w0x2y4a6c8e_aZ9"},
		"missing prefix":      {token: "01h2v8d9q3m5t7w0x2y4a6c8e_aZ9"},
		"empty token":         {token: ""},
		"prefix only":         {token: "sess_"},
		"missing separator":   {token: "sess_01h2v8d9q3m5t7w0x2y4a6c8e"},
		"empty id":            {token: "sess__aZ9"},
		"empty secret":        {token: "sess_01h2v8d9q3m5t7w0x2y4a6c8e_"},
		"extra separator":     {token: "sess_01h2v8d9q3m5t7w0x2y4a6c8e_aZ9_more"},
		"trailing whitespace": {token: valid + " "},
		"leading whitespace":  {token: " " + valid},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			id, secret, err := parseToken(test.token)
			require.ErrorIs(t, err, ErrMalformedToken)
			require.Empty(t, id)
			require.Empty(t, secret)
		})
	}

	t.Run("splits a well-formed token", func(t *testing.T) {
		id, secret, err := parseToken(valid)
		require.NoError(t, err)
		require.Equal(t, "01h2v8d9q3m5t7w0x2y4a6c8e", id)
		require.Equal(t, "aZ9kM2pQ7sW4xR8vT3nB6cD1fG5hJ0kL9mN2pQ4s", secret)
	})
}

func TestHashSecret(t *testing.T) {
	t.Run("matches the independent reference vector", func(t *testing.T) {
		digest := hashSecret(referenceRootSecret, referenceSecret)
		require.Equal(t,
			"8e0c69b39fec2d0aecfb6385f00042e93351b43facf25310d62d938a51c3fab5",
			hex.EncodeToString(digest),
		)
	})

	t.Run("is deterministic", func(t *testing.T) {
		first := hashSecret(referenceRootSecret, referenceSecret)
		second := hashSecret(referenceRootSecret, referenceSecret)
		require.Equal(t, first, second)
	})

	t.Run("is domain-separated from the bare secret digest", func(t *testing.T) {
		digest := hashSecret(referenceRootSecret, referenceSecret)
		require.NotEqual(t,
			"8bce7c70eeaa85037d51114f6d9960fbee52c1a9314826709858fc51bbed43a4",
			hex.EncodeToString(digest),
		)
	})

	t.Run("differs across root secrets and secrets", func(t *testing.T) {
		var otherRoot [sha256.Size]byte
		otherRoot[0] = 0xff

		require.NotEqual(t,
			hashSecret(referenceRootSecret, referenceSecret),
			hashSecret(otherRoot, referenceSecret),
		)
		require.NotEqual(t,
			hashSecret(referenceRootSecret, referenceSecret),
			hashSecret(referenceRootSecret, referenceSecret+"x"),
		)
	})
}
