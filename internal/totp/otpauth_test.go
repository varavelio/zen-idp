package totp

import (
	"crypto/sha256"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// referenceDerivedSecret is the deterministic shared secret of sub "alice"
// at revision 0 derived from the reference root secret anchored by the
// crypto derivation chain tests, computed with an independent Python
// implementation of the derivation.
const referenceDerivedSecret = "LQJ2MSFEHZMA4KVBU5SNJRDAJHEH7PCGYIADZIKUDNYNG4SD6XFQ"

// referenceRootSecret is the fixed normalized root secret anchored by the
// crypto derivation chain tests (bytes 0x01 through 0x20).
var referenceRootSecret = func() (secret [sha256.Size]byte) {
	for i := range secret {
		secret[i] = byte(i + 1)
	}
	return secret
}()

func TestOTPAuthLabel(t *testing.T) {
	t.Run("joins the issuer and the account name with a colon", func(t *testing.T) {
		require.Equal(t, "Example Auth:alice", OTPAuthLabel("Example Auth", "alice"))
	})

	t.Run("returns the account name alone when the issuer is empty", func(t *testing.T) {
		require.Equal(t, "alice", OTPAuthLabel("", "alice"))
	})

	t.Run("matches the label encoded by the enrollment URI", func(t *testing.T) {
		uri := OTPAuthURI(referenceDerivedSecret, "alice", "Example Auth")
		parsed, err := url.Parse(uri)
		require.NoError(t, err)
		require.Equal(
			t,
			OTPAuthLabel("Example Auth", "alice"),
			strings.TrimPrefix(parsed.Path, "/"),
		)
	})
}

func TestOTPAuthLabelPretty(t *testing.T) {
	t.Run("spaces the issuer and the account name", func(t *testing.T) {
		require.Equal(t, "Example Auth: alice", OTPAuthLabelPretty("Example Auth", "alice"))
	})

	t.Run("returns the account name alone when the issuer is empty", func(t *testing.T) {
		require.Equal(t, "alice", OTPAuthLabelPretty("", "alice"))
	})

	t.Run("only adds the space to the human-readable form", func(t *testing.T) {
		issuer, label := "Example Auth", "alice"
		require.NotEqual(t, OTPAuthLabel(issuer, label), OTPAuthLabelPretty(issuer, label))
		require.Contains(
			t,
			OTPAuthURI(referenceDerivedSecret, label, issuer),
			"Example%20Auth:alice",
		)
	})
}

func TestOTPAuthURI(t *testing.T) {
	t.Run("carries the full enrollment profile", func(t *testing.T) {
		uri := OTPAuthURI(referenceDerivedSecret, "alice", "Example Auth")
		require.Equal(t,
			"otpauth://totp/Example%20Auth:alice"+
				"?secret="+referenceDerivedSecret+
				"&issuer=Example%20Auth&algorithm=SHA1&digits=6&period=30",
			uri,
		)
	})

	t.Run("omits the issuer when empty", func(t *testing.T) {
		uri := OTPAuthURI(referenceDerivedSecret, "alice", "")
		require.Equal(t,
			"otpauth://totp/alice?secret="+referenceDerivedSecret+
				"&algorithm=SHA1&digits=6&period=30",
			uri,
		)
	})

	t.Run("percent-encodes every path and query segment", func(t *testing.T) {
		uri := OTPAuthURI("A/B+C=", "a b@c", "I&Co")
		require.Equal(t,
			"otpauth://totp/I%26Co:a%20b@c?secret=A%2FB%2BC%3D&issuer=I%26Co"+
				"&algorithm=SHA1&digits=6&period=30",
			uri,
		)
	})

	t.Run("matches the derived secret of the reference identity", func(t *testing.T) {
		secret, err := DeriveSharedSecret(referenceRootSecret, "alice", 0)
		require.NoError(t, err)
		require.Equal(t, referenceDerivedSecret, secret)
		require.Equal(t,
			"otpauth://totp/Example%20Auth:alice?secret="+referenceDerivedSecret+
				"&issuer=Example%20Auth&algorithm=SHA1&digits=6&period=30",
			OTPAuthURI(secret, "alice", "Example Auth"),
		)
	})
}
