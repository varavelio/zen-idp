package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// testRootSecret is the normalized root secret used by the fixed reference
// vectors below; it is the SHA-256 of a fixed test secret.
var testRootSecret = sha256.Sum256([]byte("test-root-secret-0123456789abcdef"))

// alternateRootSecret is a second normalized root secret used to prove that
// derivations are separated by the root secret.
var alternateRootSecret = sha256.Sum256([]byte("another-root-secret-9876543210fedcba"))

// rfc6238Secret is the well-known RFC 6238 Appendix B test secret, used as
// raw ASCII key bytes.
const rfc6238Secret = "12345678901234567890"

func TestDeriveSharedSecret(t *testing.T) {
	t.Run("matches the v1 reference vectors", func(t *testing.T) {
		vectors := []struct {
			name       string
			rootSecret [sha256.Size]byte
			sub        string
			revision   uint64
			want       string
		}{
			{
				name:       "revision zero is encoded as zero",
				rootSecret: testRootSecret,
				sub:        "dev-01",
				revision:   0,
				want:       "SO2U266UF3SATW76PQ72ARUHSYB7HD3PDC7NQJ2XH7R6RIACZ5HQ",
			},
			{
				name:       "revision one",
				rootSecret: testRootSecret,
				sub:        "dev-01",
				revision:   1,
				want:       "GFGU4MDOT67X7YNSF47JJGPP6OLD42ENNL3GXLRVKDSZH3TDY2QQ",
			},
			{
				name:       "revision two",
				rootSecret: testRootSecret,
				sub:        "dev-01",
				revision:   2,
				want:       "LKWNLR26DYPTH37KKUJDVU7IU73RXOYVM7QCUTU7BP4GM2PJJJBQ",
			},
			{
				name:       "revision above the signed range",
				rootSecret: testRootSecret,
				sub:        "dev-01",
				revision:   uint64(1) << 63,
				want:       "JB6WEYGMDDZ5FNGNQEP6EGYZJ4RFZGVTSGWITW23J5PPJ3FGMR7A",
			},
			{
				name:       "maximum revision",
				rootSecret: testRootSecret,
				sub:        "dev-01",
				revision:   math.MaxUint64,
				want:       "WDFY46WTFEF5W234F3R3SGGPNOOX3Y3FXL5E34R624GQERUD4P3Q",
			},
			{
				name:       "different sub",
				rootSecret: testRootSecret,
				sub:        "roberto",
				revision:   0,
				want:       "63OZWR77LKVVN3MYPD33WBYELVALVKRRVYF4YGES6IOTAC2CPGWQ",
			},
			{
				name:       "sub is case-sensitive",
				rootSecret: testRootSecret,
				sub:        "DEV-01",
				revision:   1,
				want:       "C4DPCPXEQXMDZ3VPJEUHAJDY7K6QDHLO4BJEO6KXC3IDDJLMF3FA",
			},
			{
				name:       "sub is not trimmed",
				rootSecret: testRootSecret,
				sub:        " dev-01 ",
				revision:   1,
				want:       "DIPHBYBWIZIH3PGQH3YN62RWJARGQV7MGQ46SFDQDD46RGUHETCA",
			},
			{
				name:       "different root secret",
				rootSecret: alternateRootSecret,
				sub:        "dev-01",
				revision:   1,
				want:       "OMS447AC4CEAVUALB7AGB5ADY2YBZWXT7T4Z4Z4TYJIAIFXI5SIQ",
			},
		}

		for _, vector := range vectors {
			t.Run(vector.name, func(t *testing.T) {
				got, err := DeriveSharedSecret(vector.rootSecret, vector.sub, vector.revision)
				require.NoError(t, err)
				require.Equal(t, vector.want, got)
			})
		}
	})

	t.Run("is deterministic for identical inputs", func(t *testing.T) {
		first, err := DeriveSharedSecret(testRootSecret, "dev-01", 1)
		require.NoError(t, err)
		second, err := DeriveSharedSecret(testRootSecret, "dev-01", 1)
		require.NoError(t, err)
		require.Equal(t, first, second)
	})

	t.Run("changes when the revision changes", func(t *testing.T) {
		revisionZero, err := DeriveSharedSecret(testRootSecret, "dev-01", 0)
		require.NoError(t, err)
		revisionOne, err := DeriveSharedSecret(testRootSecret, "dev-01", 1)
		require.NoError(t, err)
		revisionTwo, err := DeriveSharedSecret(testRootSecret, "dev-01", 2)
		require.NoError(t, err)

		require.NotEqual(t, revisionZero, revisionOne)
		require.NotEqual(t, revisionOne, revisionTwo)
	})

	t.Run("changes when the root secret changes", func(t *testing.T) {
		first, err := DeriveSharedSecret(testRootSecret, "dev-01", 1)
		require.NoError(t, err)
		second, err := DeriveSharedSecret(alternateRootSecret, "dev-01", 1)
		require.NoError(t, err)
		require.NotEqual(t, first, second)
	})

	t.Run("changes when only the sub case changes", func(t *testing.T) {
		lower, err := DeriveSharedSecret(testRootSecret, "dev-01", 1)
		require.NoError(t, err)
		upper, err := DeriveSharedSecret(testRootSecret, "DEV-01", 1)
		require.NoError(t, err)
		require.NotEqual(t, lower, upper)
	})

	t.Run("rejects an empty sub", func(t *testing.T) {
		secret, err := DeriveSharedSecret(testRootSecret, "", 0)
		require.Error(t, err)
		require.ErrorContains(t, err, "sub must not be empty")
		require.Empty(t, secret)
	})

	t.Run("rejects a non-ASCII sub", func(t *testing.T) {
		secret, err := DeriveSharedSecret(testRootSecret, "caf\u00e9", 0)
		require.Error(t, err)
		require.ErrorContains(t, err, "US-ASCII")
		require.Empty(t, secret)
	})

	t.Run("accepts the maximum configured sub length", func(t *testing.T) {
		sub := strings.Repeat("a", 255)
		secret, err := DeriveSharedSecret(testRootSecret, sub, 0)
		require.NoError(t, err)
		require.Len(t, secret, 52)
	})

	t.Run("emits a valid RFC 4648 Base32 secret", func(t *testing.T) {
		secret, err := DeriveSharedSecret(testRootSecret, "dev-01", 1)
		require.NoError(t, err)

		require.Len(t, secret, 52)
		for _, character := range secret {
			require.Contains(t, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", string(character))
		}

		decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
		require.NoError(t, err)
		require.Len(t, decoded, sha256.Size)
	})

	t.Run("derived secret works with standard RFC 6238 TOTP", func(t *testing.T) {
		secret, err := DeriveSharedSecret(testRootSecret, "dev-01", 1)
		require.NoError(t, err)
		key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
		require.NoError(t, err)

		vectors := []struct {
			timeStep int64
			want     string
		}{
			{timeStep: 0, want: "537520"},
			{timeStep: 30, want: "736982"},
			{timeStep: 60, want: "516671"},
		}
		for _, vector := range vectors {
			t.Run(fmt.Sprintf("time step %d", vector.timeStep), func(t *testing.T) {
				require.Equal(t, vector.want, totpCode(t, key, vector.timeStep))
			})
		}
	})

	t.Run("test helper matches the RFC 6238 reference vectors", func(t *testing.T) {
		vectors := []struct {
			timeStep int64
			want     string
		}{
			{timeStep: 59, want: "287082"},
			{timeStep: 1111111109, want: "081804"},
			{timeStep: 1111111111, want: "050471"},
			{timeStep: 1234567890, want: "005924"},
			{timeStep: 2000000000, want: "279037"},
			{timeStep: 20000000000, want: "353130"},
		}
		for _, vector := range vectors {
			t.Run(fmt.Sprintf("time step %d", vector.timeStep), func(t *testing.T) {
				require.Equal(t, vector.want, totpCode(t, []byte(rfc6238Secret), vector.timeStep))
			})
		}
	})
}

// totpCode implements the RFC 6238 TOTP algorithm with the authenticator
// profile used by Zen IdP: HMAC-SHA-1, a 30-second step, and six digits. It
// exists only to prove that derived shared secrets are consumable by standard
// TOTP implementations and is not part of the package API.
func totpCode(t *testing.T, key []byte, timeStep int64) string {
	t.Helper()

	counter := make([]byte, 8)
	binary.BigEndian.PutUint64(counter, uint64(timeStep/30))
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(counter)
	digest := mac.Sum(nil)

	offset := digest[len(digest)-1] & 0x0f
	code := binary.BigEndian.Uint32(digest[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", code%1_000_000)
}
