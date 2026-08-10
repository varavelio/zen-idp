package totp

import (
	"encoding/base32"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestVerifyCode(t *testing.T) {
	// RFC 6238 Appendix B publishes the SHA-1 values for the 20-byte
	// secret; the 32-byte and 64-byte values were computed with two
	// independent implementations (Python and Go) that also reproduce the
	// published 20-byte values.
	times := []int64{59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000}
	vectors := []struct {
		name  string
		ascii string
		codes []string
	}{
		{
			name:  "20-byte RFC 6238 secret",
			ascii: "12345678901234567890",
			codes: []string{"287082", "081804", "050471", "005924", "279037", "353130"},
		},
		{
			name:  "32-byte secret",
			ascii: "12345678901234567890123456789012",
			codes: []string{"599872", "138967", "201283", "012961", "931087", "573920"},
		},
		{
			name:  "64-byte secret",
			ascii: "1234567890123456789012345678901234567890123456789012345678901234",
			codes: []string{"779409", "110091", "372631", "973530", "155042", "487110"},
		},
	}

	for _, vector := range vectors {
		t.Run(vector.name, func(t *testing.T) {
			secret := base32.StdEncoding.WithPadding(base32.NoPadding).
				EncodeToString([]byte(vector.ascii))
			for index, at := range times {
				t.Run(fmt.Sprintf("time %d", at), func(t *testing.T) {
					valid, err := VerifyCode(secret, vector.codes[index], time.Unix(at, 0))
					require.NoError(t, err)
					require.True(t, valid)
				})
			}
		})
	}
}

func TestVerifyCodeClockSkew(t *testing.T) {
	// RFC 4226 Appendix D HOTP values for the 20-byte secret at counters
	// zero through three, reached at 30-second steps zero through three.
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(rfc6238Secret))
	at := time.Unix(59, 0) // step 1

	cases := []struct {
		name string
		code string
		want bool
	}{
		{"accepts the code of the current step", "287082", true},
		{"accepts the code of one step before", "755224", true},
		{"accepts the code of one step after", "359152", true},
		{"rejects the code of two steps after", "969429", false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			valid, err := VerifyCode(secret, test.code, at)
			require.NoError(t, err)
			require.Equal(t, test.want, valid)
		})
	}

	t.Run("accepts one code across its three-step lifetime", func(t *testing.T) {
		valid, err := VerifyCode(secret, "287082", time.Unix(29, 0)) // step 0
		require.NoError(t, err)
		require.True(t, valid)

		valid, err = VerifyCode(secret, "287082", time.Unix(89, 0)) // step 2
		require.NoError(t, err)
		require.True(t, valid)

		valid, err = VerifyCode(secret, "287082", time.Unix(119, 0)) // step 3
		require.NoError(t, err)
		require.False(t, valid)
	})
}

func TestVerifyCodeRejectsWrongCode(t *testing.T) {
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(rfc6238Secret))

	valid, err := VerifyCode(secret, "000000", time.Unix(59, 0))
	require.NoError(t, err)
	require.False(t, valid)
}

func TestVerifyCodeRejectsMalformedInput(t *testing.T) {
	validSecret := base32.StdEncoding.WithPadding(base32.NoPadding).
		EncodeToString([]byte(rfc6238Secret))

	tests := map[string]struct {
		secret string
		code   string
	}{
		"empty secret":    {"", "287082"},
		"invalid base32":  {"????", "287082"},
		"padded secret":   {validSecret + "=", "287082"},
		"empty code":      {validSecret, ""},
		"short code":      {validSecret, "28708"},
		"long code":       {validSecret, "2870821"},
		"non-digit code":  {validSecret, "28708a"},
		"code with space": {validSecret, "287 82"},
		"code with sign":  {validSecret, "-87082"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			valid, err := VerifyCode(test.secret, test.code, time.Unix(59, 0))
			require.Error(t, err)
			require.False(t, valid)
		})
	}
}

func TestVerifyCodeWithDerivedSecret(t *testing.T) {
	secret, err := DeriveSharedSecret(testRootSecret, "dev-01", 1)
	require.NoError(t, err)

	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	require.NoError(t, err)

	at := time.Unix(1_700_000_000, 0)
	code := totpCode(t, key, at.Unix())

	valid, err := VerifyCode(secret, code, at)
	require.NoError(t, err)
	require.True(t, valid)

	valid, err = VerifyCode(secret, "000000", at)
	require.NoError(t, err)
	require.False(t, valid)
}
