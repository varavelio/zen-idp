package crypto

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/alexedwards/argon2id"
	"github.com/stretchr/testify/require"
)

func TestGenerateSecret(t *testing.T) {
	tests := map[string]struct {
		length        int
		expectedValue string
	}{
		"administrator password": {
			length:        administratorSecretLength,
			expectedValue: "ZZZZZZZZZZZZZZ",
		},
		"machine secret": {
			length:        machineSecretLength,
			expectedValue: "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			secret, err := generateSecret(
				bytes.NewReader(bytes.Repeat([]byte{unbiasedByteLimit - 1}, test.length)),
				test.length,
			)
			require.NoError(t, err)
			require.Equal(t, test.expectedValue, secret)
			for _, character := range secret {
				require.Contains(t, base62Alphabet, string(character))
			}
		})
	}

	t.Run("discards bytes that would introduce modulo bias", func(t *testing.T) {
		secret, err := generateSecret(bytes.NewReader([]byte{248, 255, 0, 249, 61}), 2)

		require.NoError(t, err)
		require.Equal(t, "0Z", secret)
	})

	t.Run("propagates random source errors", func(t *testing.T) {
		randomnessErr := errors.New("randomness unavailable")

		secret, err := generateSecret(failingReader{err: randomnessErr}, 10)

		require.Empty(t, secret)
		require.ErrorIs(t, err, randomnessErr)
	})

	t.Run("rejects insufficient randomness", func(t *testing.T) {
		secret, err := generateSecret(strings.NewReader("short"), 10)

		require.Empty(t, secret)
		require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	})
}

func TestGenerateMachineSecret(t *testing.T) {
	secret, err := GenerateMachineSecret()
	require.NoError(t, err)
	require.Len(t, secret, machineSecretLength)
	for _, character := range secret {
		require.Contains(t, base62Alphabet, string(character))
	}

	other, err := GenerateMachineSecret()
	require.NoError(t, err)
	require.NotEqual(t, secret, other)
}

func TestGenerateSecretBundle(t *testing.T) {
	randomness := bytes.NewReader(bytes.Repeat(
		[]byte{0},
		machineSecretLength+administratorSecretLength+machineSecretLength,
	))
	hashCredential := func(plain string) (string, error) {
		return "hash:" + plain, nil
	}

	bundle, err := generateSecretBundle(randomness, hashCredential)
	require.NoError(t, err)

	require.Len(t, bundle.RootSecret, machineSecretLength)
	require.Len(t, bundle.AdministratorPlain, administratorSecretLength)
	require.Equal(t, "hash:"+bundle.AdministratorPlain, bundle.AdministratorHash)
	require.Len(t, bundle.OIDCClientSecretPlain, machineSecretLength)
	require.Equal(t, "hash:"+bundle.OIDCClientSecretPlain, bundle.OIDCClientSecretHash)
}

func TestHashCredential(t *testing.T) {
	hash, err := HashCredential("credential")
	require.NoError(t, err)

	params, salt, key, err := argon2id.DecodeHash(hash)
	require.NoError(t, err)
	require.Equal(t, uint32(argon2Memory), params.Memory)
	require.Equal(t, uint32(argon2Iterations), params.Iterations)
	require.Equal(t, uint8(argon2Parallelism), params.Parallelism)
	require.Len(t, salt, argon2SaltLength)
	require.Len(t, key, argon2KeyLength)

	match, err := argon2id.ComparePasswordAndHash("credential", hash)
	require.NoError(t, err)
	require.True(t, match)
	require.NoError(t, ValidateCredentialHash(hash))
}

type failingReader struct {
	err error
}

func (reader failingReader) Read([]byte) (int, error) {
	return 0, reader.err
}
