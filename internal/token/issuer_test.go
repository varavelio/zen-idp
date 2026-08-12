package token

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/varavelio/zen-idp/internal/config"
	"github.com/varavelio/zen-idp/internal/jwk"
	"github.com/varavelio/zen-idp/internal/jwt"
	"github.com/varavelio/zen-idp/internal/rsakeygen"
)

// referenceRootSecret is the fixed normalized root secret anchored by the
// rsakeygen reference vector, so that this package tests the same signing
// identity.
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

// referenceKid is the RFC 7638 thumbprint anchored by the jwk reference
// vector.
const referenceKid = "18o8WQf60YOSXryGuVEqiEWfO80TcNyB3FLCRWyLzsE"

// referenceIssuer is the issuer origin stamped into every reference token.
const referenceIssuer = "https://auth.example.com"

// testNow is the fixed issuance instant of the reference vectors.
var testNow = time.Unix(1767366245, 0).UTC()

// testUsers covers a user with custom claims, one with an idp_-prefixed
// claim, an expired user, and an unknown subject.
var testUsers = []config.User{
	{
		Subject: "dev-01",
		Claims: map[string]any{
			"groups": []string{"ops", "oncall"},
			"title":  "SRE",
		},
	},
	{
		Subject: "leaky",
		Claims: map[string]any{
			"role":      "admin",
			"idp_login": "internal-only",
		},
	},
	{Subject: "expired", ExpiresAt: time.Date(2025, 12, 31, 23, 59, 59, 0, time.UTC)},
}

// The reference payloads below were computed with an independent Python
// implementation (json.dumps with sorted keys) and anchor the v1 token
// contract: the reference identity must always reproduce the exact same
// claims for the reference parameters.
const (
	referenceIDTokenPayload = `{"aud":"grafana-prod","exp":1767367145,` +
		`"groups":["ops","oncall"],"iat":1767366245,"iss":"https://auth.example.com",` +
		`"nonce":"abc123XYZ_-","sub":"dev-01","title":"SRE"}`
	referenceAccessTokenPayload = `{"aud":"https://auth.example.com/userinfo",` +
		`"exp":1767367145,"iat":1767366245,"iss":"https://auth.example.com",` +
		`"jti":"01JZ0T9QK5V2M7R8X9W4Q6A5B3C","sub":"dev-01"}`
)

// referenceIdentity derives the reference signing identity: the private key
// of the reference root secret, a signer built from that key and its RFC
// 7638 thumbprint, and a verifier for the same public material.
func referenceIdentity(t *testing.T) (*jwt.Signer, *jwt.Verifier) {
	t.Helper()
	key, err := rsakeygen.GeneratePrivateKey(referenceRootSecret)
	require.NoError(t, err)
	publicJWK, err := jwk.FromPublicKey(&key.PublicKey)
	require.NoError(t, err)
	require.Equal(t, referenceKid, publicJWK.Kid)
	signer, err := jwt.NewSigner(key, publicJWK.Kid)
	require.NoError(t, err)
	verifier, err := jwt.NewVerifier(&key.PublicKey, publicJWK.Kid)
	require.NoError(t, err)
	return signer, verifier
}

// stubLocks is a scriptable lock checker for tests.
type stubLocks struct {
	locked bool
	err    error
}

func (stub stubLocks) IsLocked(context.Context, string) (bool, error) {
	return stub.locked, stub.err
}

// newTestIssuer returns an issuer backed by the reference identity, the
// reference users, and an unlocked lock checker.
func newTestIssuer(t *testing.T, locks lockChecker) *Issuer {
	t.Helper()
	signer, _ := referenceIdentity(t)
	issuer, err := NewIssuer(signer, referenceIssuer, testUsers, locks)
	require.NoError(t, err)
	return issuer
}

// payloadOf decodes and returns the raw JSON payload segment of a compact
// token.
func payloadOf(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	return string(payload)
}

func TestNewIssuer(t *testing.T) {
	signer, _ := referenceIdentity(t)

	t.Run("rejects a nil signer", func(t *testing.T) {
		issuer, err := NewIssuer(nil, referenceIssuer, testUsers, stubLocks{})
		require.Nil(t, issuer)
		require.EqualError(t, err, "token signer is nil")
	})

	t.Run("rejects an empty issuer", func(t *testing.T) {
		issuer, err := NewIssuer(signer, "", testUsers, stubLocks{})
		require.Nil(t, issuer)
		require.EqualError(t, err, "token issuer must not be empty")
	})

	t.Run("rejects a nil lock checker", func(t *testing.T) {
		issuer, err := NewIssuer(signer, referenceIssuer, testUsers, nil)
		require.Nil(t, issuer)
		require.EqualError(t, err, "token lock checker is nil")
	})

	t.Run("derives the userinfo audience from the issuer", func(t *testing.T) {
		issuer, err := NewIssuer(signer, "https://auth.example.com/", testUsers, stubLocks{})
		require.NoError(t, err)
		require.Equal(t, "https://auth.example.com/userinfo", issuer.audience)
	})
}

func TestIssueIDToken(t *testing.T) {
	issuer := newTestIssuer(t, stubLocks{})

	params := IDTokenParams{
		Subject:  "dev-01",
		ClientID: "grafana-prod",
		Nonce:    "abc123XYZ_-",
		Now:      testNow,
	}

	t.Run("matches the reference vector", func(t *testing.T) {
		token, err := issuer.IssueIDToken(context.Background(), params)
		require.NoError(t, err)
		require.Equal(t, referenceIDTokenPayload, payloadOf(t, token))
	})

	t.Run("verifies against the reference identity", func(t *testing.T) {
		token, err := issuer.IssueIDToken(context.Background(), params)
		require.NoError(t, err)
		_, verifier := referenceIdentity(t)
		claims, err := verifier.Verify(token)
		require.NoError(t, err)
		require.Equal(t, "dev-01", claims["sub"])
		require.Equal(t, "grafana-prod", claims["aud"])
		require.Equal(t, "abc123XYZ_-", claims["nonce"])
	})

	t.Run("is deterministic", func(t *testing.T) {
		first, err := issuer.IssueIDToken(context.Background(), params)
		require.NoError(t, err)
		second, err := issuer.IssueIDToken(context.Background(), params)
		require.NoError(t, err)
		require.Equal(t, first, second)
	})

	t.Run("omits the nonce when absent", func(t *testing.T) {
		withoutNonce := params
		withoutNonce.Nonce = ""
		token, err := issuer.IssueIDToken(context.Background(), withoutNonce)
		require.NoError(t, err)
		require.NotContains(t, payloadOf(t, token), `"nonce"`)
	})

	t.Run("includes every custom claim and excludes idp_ claims", func(t *testing.T) {
		token, err := issuer.IssueIDToken(context.Background(), IDTokenParams{
			Subject:  "leaky",
			ClientID: "grafana-prod",
			Now:      testNow,
		})
		require.NoError(t, err)
		payload := payloadOf(t, token)
		require.Contains(t, payload, `"role":"admin"`)
		require.NotContains(t, payload, "idp_login")
		require.NotContains(t, payload, "internal-only")
	})

	t.Run("never emits internal user fields", func(t *testing.T) {
		token, err := issuer.IssueIDToken(context.Background(), params)
		require.NoError(t, err)
		payload := payloadOf(t, token)
		require.NotContains(t, payload, "TOTPRevision")
		require.NotContains(t, payload, "ExpiresAt")
		require.NotContains(t, payload, "expires_at")
	})

	t.Run("denies an unknown subject", func(t *testing.T) {
		unknown := params
		unknown.Subject = "ghost"
		_, err := issuer.IssueIDToken(context.Background(), unknown)
		require.ErrorIs(t, err, ErrDenied)
	})

	t.Run("denies an expired user", func(t *testing.T) {
		expired := params
		expired.Subject = "expired"
		_, err := issuer.IssueIDToken(context.Background(), expired)
		require.ErrorIs(t, err, ErrDenied)
	})

	t.Run("denies a locked user", func(t *testing.T) {
		lockedIssuer := newTestIssuer(t, stubLocks{locked: true})
		_, err := lockedIssuer.IssueIDToken(context.Background(), params)
		require.ErrorIs(t, err, ErrDenied)
	})

	t.Run("propagates lock check failures", func(t *testing.T) {
		brokenIssuer := newTestIssuer(t, stubLocks{err: errors.New("store down")})
		_, err := brokenIssuer.IssueIDToken(context.Background(), params)
		require.ErrorContains(t, err, "check user locks")
		require.NotErrorIs(t, err, ErrDenied)
	})

	t.Run("rejects an empty subject", func(t *testing.T) {
		empty := params
		empty.Subject = ""
		_, err := issuer.IssueIDToken(context.Background(), empty)
		require.EqualError(t, err, "token subject must not be empty")
	})

	t.Run("rejects an empty client id", func(t *testing.T) {
		noClient := params
		noClient.ClientID = ""
		_, err := issuer.IssueIDToken(context.Background(), noClient)
		require.EqualError(t, err, "token client id must not be empty")
	})

	t.Run("issues different audiences per client", func(t *testing.T) {
		other := params
		other.ClientID = "other-client"
		first, err := issuer.IssueIDToken(context.Background(), params)
		require.NoError(t, err)
		second, err := issuer.IssueIDToken(context.Background(), other)
		require.NoError(t, err)
		require.NotEqual(t, first, second)
		require.Contains(t, payloadOf(t, second), `"aud":"other-client"`)
	})
}

func TestIssueAccessToken(t *testing.T) {
	issuer := newTestIssuer(t, stubLocks{})

	params := AccessTokenParams{
		Subject:   "dev-01",
		SessionID: "01JZ0T9QK5V2M7R8X9W4Q6A5B3C",
		Now:       testNow,
	}

	t.Run("matches the reference vector", func(t *testing.T) {
		token, err := issuer.IssueAccessToken(context.Background(), params)
		require.NoError(t, err)
		require.Equal(t, referenceAccessTokenPayload, payloadOf(t, token))
	})

	t.Run("verifies against the reference identity", func(t *testing.T) {
		token, err := issuer.IssueAccessToken(context.Background(), params)
		require.NoError(t, err)
		_, verifier := referenceIdentity(t)
		claims, err := verifier.Verify(token)
		require.NoError(t, err)
		require.Equal(t, "dev-01", claims["sub"])
		require.Equal(t, "https://auth.example.com/userinfo", claims["aud"])
		require.Equal(t, "01JZ0T9QK5V2M7R8X9W4Q6A5B3C", claims["jti"])
	})

	t.Run("is deterministic", func(t *testing.T) {
		first, err := issuer.IssueAccessToken(context.Background(), params)
		require.NoError(t, err)
		second, err := issuer.IssueAccessToken(context.Background(), params)
		require.NoError(t, err)
		require.Equal(t, first, second)
	})

	t.Run("omits jti without a session", func(t *testing.T) {
		noSession := params
		noSession.SessionID = ""
		token, err := issuer.IssueAccessToken(context.Background(), noSession)
		require.NoError(t, err)
		require.NotContains(t, payloadOf(t, token), `"jti"`)
	})

	t.Run("never includes custom claims", func(t *testing.T) {
		token, err := issuer.IssueAccessToken(context.Background(), AccessTokenParams{
			Subject: "leaky",
			Now:     testNow,
		})
		require.NoError(t, err)
		payload := payloadOf(t, token)
		require.NotContains(t, payload, "role")
		require.NotContains(t, payload, "admin")
		require.NotContains(t, payload, "idp_login")
	})

	t.Run("denies an unknown subject", func(t *testing.T) {
		unknown := params
		unknown.Subject = "ghost"
		_, err := issuer.IssueAccessToken(context.Background(), unknown)
		require.ErrorIs(t, err, ErrDenied)
	})

	t.Run("denies an expired user", func(t *testing.T) {
		expired := params
		expired.Subject = "expired"
		_, err := issuer.IssueAccessToken(context.Background(), expired)
		require.ErrorIs(t, err, ErrDenied)
	})

	t.Run("denies a locked user", func(t *testing.T) {
		lockedIssuer := newTestIssuer(t, stubLocks{locked: true})
		_, err := lockedIssuer.IssueAccessToken(context.Background(), params)
		require.ErrorIs(t, err, ErrDenied)
	})

	t.Run("rejects an empty subject", func(t *testing.T) {
		empty := params
		empty.Subject = ""
		_, err := issuer.IssueAccessToken(context.Background(), empty)
		require.EqualError(t, err, "token subject must not be empty")
	})
}
