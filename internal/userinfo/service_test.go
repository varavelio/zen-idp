package userinfo

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/varavelio/zen-idp/internal/config"
	"github.com/varavelio/zen-idp/internal/jwk"
	"github.com/varavelio/zen-idp/internal/jwt"
	"github.com/varavelio/zen-idp/internal/rsakeygen"
	"github.com/varavelio/zen-idp/internal/session"
	"github.com/varavelio/zen-idp/internal/statestore"
	"github.com/varavelio/zen-idp/internal/token"
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

// referenceSessionID is the session record identifier bound to the
// reference session-bound token through its jti claim.
const referenceSessionID = "01JZ0T9QK5V2M7R8X9W4Q6A5B3C"

// testNow is the fixed issuance instant of the reference tokens.
var testNow = time.Unix(1767366245, 0).UTC()

// testUsers covers a user with custom claims, one with an idp_-prefixed
// claim, an expired user, and a user whose TOTP revision was rotated.
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
	{Subject: "rotated", TOTPRevision: 1},
}

// The reference tokens below were issued by the real reference identity
// (rsakeygen → jwk → jwt → token) for the reference parameters and anchor
// the v1 userinfo contract: the reference identity must always reproduce
// the exact same access tokens, and Resolve must always accept them.
const referenceBoundToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjE4bzhXUWY2MFlPU1hyeUd1VkVxaUVXZk84MFRjTnlC" +
	"M0ZMQ1JXeUx6c0UifQ.eyJhdWQiOiJodHRwczovL2F1dGguZXhhbXBsZS5jb20vdXNlcmluZ" +
	"m8iLCJleHAiOjE3NjczNjcxNDUsImlhdCI6MTc2NzM2NjI0NSwiaXNzIjoiaHR0cHM6Ly9hd" +
	"XRoLmV4YW1wbGUuY29tIiwianRpIjoiMDFKWjBUOVFLNVYyTTdSOFg5VzRRNkE1QjNDIiwic" +
	"3ViIjoiZGV2LTAxIn0.LCaGcI7dRmsZ9sIUzoSzB7FOO2JGyNfFWp7TAc8Kf3Ry2J8X9Qf8X" +
	"VycCehQnNCxwHGkwXVa4IFuYaWjg32BM0CSSODO0z-R2jZQveQDRxun4wjCPY3a_D4KP--5-" +
	"MGi2HhDZJ5YjAT5F04XFTJina8BuSw_BfQYtttydpJikKT7LIeVUTcOE9O6Iz_gAiHbOf4so" +
	"fATsvzTomsoCtk-XvTYuKgq-8VGqm7dpu2j8jT7bCj5eKspoNTZVRw93rhOnpGy5VUmhfCwA" +
	"S_pGSbrTNNwmxfTICerYejDeVz7QsiI3Po3Bwc8__fZW5q6IfmzvKr-yBZpGl1ro4xDOMSfv" +
	"A"

const referenceSessionlessToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjE4bzhXUWY2MFlPU1hyeUd1VkVxaUVXZk84MFRjTnlC" +
	"M0ZMQ1JXeUx6c0UifQ.eyJhdWQiOiJodHRwczovL2F1dGguZXhhbXBsZS5jb20vdXNlcmluZ" +
	"m8iLCJleHAiOjE3NjczNjcxNDUsImlhdCI6MTc2NzM2NjI0NSwiaXNzIjoiaHR0cHM6Ly9hd" +
	"XRoLmV4YW1wbGUuY29tIiwic3ViIjoiZGV2LTAxIn0.Rp_1_LP2vEr1tNZGcjVKQLfYtP6HH" +
	"AZs4EZVqTT4YXBAzs2CTglYfOjD4YAZHybguYTxkxT4ArTyK_Z8_oFgle4Nk63FC-Bx0GQns" +
	"WtxWNHQlI__TJVZZLVYo0K9JiqvaSxDnb-um_1YTDGx8Dp25wkCRz1uIV5O_XvOyedU_oCcC" +
	"2Wdi1ww3i9ICGfVJDOOdakT9TGZHaeJKaqk_RFGD9uyOFcemCXPPZ4w7sUy6-N0yGF5nKF2x" +
	"mkAQSm4iia-3LbhI9z8k3V8o4Y7okZE947u4D2zdGlFodk2B2UxVSDohrVZ9EAJKc3L7-bp9" +
	"zDO1kaafodiCPOdtXzv_NvJ2Q"

// referenceClaims is the exact claim set the reference tokens must resolve
// to for the reference user.
var referenceClaims = map[string]any{
	"sub":    "dev-01",
	"groups": []string{"ops", "oncall"},
	"title":  "SRE",
}

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

// stubSessions is a scriptable session validator for tests.
type stubSessions struct {
	err error
}

func (stub stubSessions) ValidateID(
	context.Context,
	string,
	time.Time,
) (session.Session, error) {
	return session.Session{}, stub.err
}

// fixedID is a session identifier generator that always returns one
// identifier, so tests can bind sessions to the reference token's jti.
type fixedID struct {
	id string
}

func (f fixedID) NewID(context.Context) string { return f.id }

// newTestDB returns a migrated temporary SQLite database.
func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := statestore.Connect(context.Background(), path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	require.NoError(t, statestore.Migrate(context.Background(), db))
	return db
}

// newSessionStore returns a session store backed by a migrated temporary
// SQLite database, the anchored reference root secret, and a session
// identifier generator that always returns the reference session id.
func newSessionStore(t *testing.T, maxAge time.Duration) *session.Store {
	t.Helper()
	queries := statestore.New(newTestDB(t))
	store, err := session.NewStore(
		queries,
		fixedID{id: referenceSessionID},
		referenceRootSecret,
		maxAge,
	)
	require.NoError(t, err)
	return store
}

// createSession records an active session for the given identity at now.
func createSession(t *testing.T, store *session.Store, sub string, rev uint64, now time.Time) {
	t.Helper()
	_, err := store.Create(context.Background(), session.CreateParams{
		Subject: sub,
		TOTPRev: rev,
		Now:     now,
	})
	require.NoError(t, err)
}

// newTestService returns a service backed by the reference identity, the
// reference users, and the given lock checker and session validator.
func newTestService(t *testing.T, locks lockChecker, sessions sessionValidator) *Service {
	t.Helper()
	_, verifier := referenceIdentity(t)
	service, err := New(verifier, referenceIssuer, testUsers, locks, sessions)
	require.NoError(t, err)
	return service
}

// issueAccessToken issues a real access token of the reference identity for
// the given subject, session binding, and instant.
func issueAccessToken(t *testing.T, subject, sessionID string, now time.Time) string {
	t.Helper()
	signer, _ := referenceIdentity(t)
	issuer, err := token.NewIssuer(signer, referenceIssuer, testUsers, stubLocks{})
	require.NoError(t, err)
	accessToken, err := issuer.IssueAccessToken(context.Background(), token.AccessTokenParams{
		Subject:   subject,
		SessionID: sessionID,
		Now:       now,
	})
	require.NoError(t, err)
	return accessToken
}

// signClaims signs arbitrary claims with the reference identity, for tokens
// the real issuer would refuse to produce.
func signClaims(t *testing.T, claims map[string]any) string {
	t.Helper()
	signer, _ := referenceIdentity(t)
	signed, err := signer.Sign(claims)
	require.NoError(t, err)
	return signed
}

// validClaims returns a claim set that Resolve must accept for the given
// subject.
func validClaims(subject string) map[string]any {
	return map[string]any{
		"iss": referenceIssuer,
		"sub": subject,
		"aud": "https://auth.example.com/userinfo",
		"iat": testNow.Unix(),
		"exp": testNow.Add(time.Hour).Unix(),
	}
}

func TestNew(t *testing.T) {
	_, verifier := referenceIdentity(t)

	t.Run("rejects a nil verifier", func(t *testing.T) {
		service, err := New(nil, referenceIssuer, testUsers, stubLocks{}, stubSessions{})
		require.Nil(t, service)
		require.EqualError(t, err, "userinfo verifier is nil")
	})

	t.Run("rejects an empty issuer", func(t *testing.T) {
		service, err := New(verifier, "", testUsers, stubLocks{}, stubSessions{})
		require.Nil(t, service)
		require.EqualError(t, err, "userinfo issuer must not be empty")
	})

	t.Run("rejects a nil lock checker", func(t *testing.T) {
		service, err := New(verifier, referenceIssuer, testUsers, nil, stubSessions{})
		require.Nil(t, service)
		require.EqualError(t, err, "userinfo lock checker is nil")
	})

	t.Run("rejects a nil session validator", func(t *testing.T) {
		service, err := New(verifier, referenceIssuer, testUsers, stubLocks{}, nil)
		require.Nil(t, service)
		require.EqualError(t, err, "userinfo session validator is nil")
	})

	t.Run("derives the userinfo audience from the issuer", func(t *testing.T) {
		service, err := New(
			verifier,
			"https://auth.example.com/",
			testUsers,
			stubLocks{},
			stubSessions{},
		)
		require.NoError(t, err)
		require.Equal(t, "https://auth.example.com/userinfo", service.audience)
	})
}

func TestResolve(t *testing.T) {
	ctx := context.Background()

	t.Run("matches the reference vector for a session-bound token", func(t *testing.T) {
		store := newSessionStore(t, 72*time.Hour)
		createSession(t, store, "dev-01", 0, testNow)
		service := newTestService(t, stubLocks{}, store)

		claims, err := service.Resolve(ctx, referenceBoundToken, testNow.Add(time.Minute))
		require.NoError(t, err)
		require.Equal(t, referenceClaims, claims)
	})

	t.Run("resolves a sessionless token", func(t *testing.T) {
		service := newTestService(t, stubLocks{}, newSessionStore(t, 72*time.Hour))

		claims, err := service.Resolve(ctx, referenceSessionlessToken, testNow.Add(time.Minute))
		require.NoError(t, err)
		require.Equal(t, referenceClaims, claims)
	})

	t.Run("includes every custom claim and excludes idp_ claims", func(t *testing.T) {
		service := newTestService(t, stubLocks{}, newSessionStore(t, 72*time.Hour))
		accessToken := issueAccessToken(t, "leaky", "", testNow)

		claims, err := service.Resolve(ctx, accessToken, testNow.Add(time.Minute))
		require.NoError(t, err)
		require.Equal(t, map[string]any{"sub": "leaky", "role": "admin"}, claims)
	})

	t.Run("rejects a tampered token", func(t *testing.T) {
		service := newTestService(t, stubLocks{}, newSessionStore(t, 72*time.Hour))
		tampered := referenceSessionlessToken[:len(referenceSessionlessToken)-4] + "AAAA"

		_, err := service.Resolve(ctx, tampered, testNow.Add(time.Minute))
		require.ErrorIs(t, err, ErrDenied)
	})

	t.Run("rejects a token that is not a JWT", func(t *testing.T) {
		service := newTestService(t, stubLocks{}, newSessionStore(t, 72*time.Hour))

		_, err := service.Resolve(ctx, "not-a-jwt", testNow.Add(time.Minute))
		require.ErrorIs(t, err, ErrDenied)
	})

	t.Run("rejects a token signed by another identity", func(t *testing.T) {
		service := newTestService(t, stubLocks{}, newSessionStore(t, 72*time.Hour))
		var otherSecret [sha256.Size]byte
		for index := range otherSecret {
			otherSecret[index] = 0xAA
		}
		key, err := rsakeygen.GeneratePrivateKey(otherSecret)
		require.NoError(t, err)
		publicJWK, err := jwk.FromPublicKey(&key.PublicKey)
		require.NoError(t, err)
		signer, err := jwt.NewSigner(key, publicJWK.Kid)
		require.NoError(t, err)
		foreign, err := signer.Sign(validClaims("dev-01"))
		require.NoError(t, err)

		_, err = service.Resolve(ctx, foreign, testNow.Add(time.Minute))
		require.ErrorIs(t, err, ErrDenied)
	})

	t.Run("rejects a wrong issuer", func(t *testing.T) {
		service := newTestService(t, stubLocks{}, newSessionStore(t, 72*time.Hour))
		claims := validClaims("dev-01")
		claims["iss"] = "https://evil.example.com"

		_, err := service.Resolve(ctx, signClaims(t, claims), testNow.Add(time.Minute))
		require.ErrorIs(t, err, ErrDenied)
	})

	t.Run("rejects a wrong audience", func(t *testing.T) {
		service := newTestService(t, stubLocks{}, newSessionStore(t, 72*time.Hour))
		claims := validClaims("dev-01")
		claims["aud"] = "https://auth.example.com/admin"

		_, err := service.Resolve(ctx, signClaims(t, claims), testNow.Add(time.Minute))
		require.ErrorIs(t, err, ErrDenied)
	})

	t.Run("rejects an absent audience", func(t *testing.T) {
		service := newTestService(t, stubLocks{}, newSessionStore(t, 72*time.Hour))
		claims := validClaims("dev-01")
		delete(claims, "aud")

		_, err := service.Resolve(ctx, signClaims(t, claims), testNow.Add(time.Minute))
		require.ErrorIs(t, err, ErrDenied)
	})

	t.Run("accepts an audience array containing the userinfo audience", func(t *testing.T) {
		service := newTestService(t, stubLocks{}, newSessionStore(t, 72*time.Hour))
		claims := validClaims("dev-01")
		claims["aud"] = []any{"https://auth.example.com/userinfo"}

		resolved, err := service.Resolve(ctx, signClaims(t, claims), testNow.Add(time.Minute))
		require.NoError(t, err)
		require.Equal(t, referenceClaims, resolved)
	})

	t.Run("rejects an audience array without the userinfo audience", func(t *testing.T) {
		service := newTestService(t, stubLocks{}, newSessionStore(t, 72*time.Hour))
		claims := validClaims("dev-01")
		claims["aud"] = []any{"https://auth.example.com/other"}

		_, err := service.Resolve(ctx, signClaims(t, claims), testNow.Add(time.Minute))
		require.ErrorIs(t, err, ErrDenied)
	})

	t.Run("rejects an expired token", func(t *testing.T) {
		service := newTestService(t, stubLocks{}, newSessionStore(t, 72*time.Hour))
		accessToken := issueAccessToken(t, "dev-01", "", testNow)

		_, err := service.Resolve(ctx, accessToken, testNow.Add(900*time.Second))
		require.ErrorIs(t, err, ErrDenied)
		_, err = service.Resolve(ctx, accessToken, testNow.Add(901*time.Second))
		require.ErrorIs(t, err, ErrDenied)
	})

	t.Run("rejects a token without exp", func(t *testing.T) {
		service := newTestService(t, stubLocks{}, newSessionStore(t, 72*time.Hour))
		claims := validClaims("dev-01")
		delete(claims, "exp")

		_, err := service.Resolve(ctx, signClaims(t, claims), testNow.Add(time.Minute))
		require.ErrorIs(t, err, ErrDenied)
	})

	t.Run("rejects a token with a non-numeric exp", func(t *testing.T) {
		service := newTestService(t, stubLocks{}, newSessionStore(t, 72*time.Hour))
		claims := validClaims("dev-01")
		claims["exp"] = "soon"

		_, err := service.Resolve(ctx, signClaims(t, claims), testNow.Add(time.Minute))
		require.ErrorIs(t, err, ErrDenied)
	})

	t.Run("rejects a token without sub", func(t *testing.T) {
		service := newTestService(t, stubLocks{}, newSessionStore(t, 72*time.Hour))
		claims := validClaims("dev-01")
		delete(claims, "sub")

		_, err := service.Resolve(ctx, signClaims(t, claims), testNow.Add(time.Minute))
		require.ErrorIs(t, err, ErrDenied)
	})

	t.Run("rejects a non-string sub", func(t *testing.T) {
		service := newTestService(t, stubLocks{}, newSessionStore(t, 72*time.Hour))
		claims := validClaims("dev-01")
		claims["sub"] = 42

		_, err := service.Resolve(ctx, signClaims(t, claims), testNow.Add(time.Minute))
		require.ErrorIs(t, err, ErrDenied)
	})

	t.Run("rejects an unknown subject", func(t *testing.T) {
		service := newTestService(t, stubLocks{}, newSessionStore(t, 72*time.Hour))

		_, err := service.Resolve(
			ctx,
			signClaims(t, validClaims("ghost")),
			testNow.Add(time.Minute),
		)
		require.ErrorIs(t, err, ErrDenied)
	})

	t.Run("rejects an expired user", func(t *testing.T) {
		service := newTestService(t, stubLocks{}, newSessionStore(t, 72*time.Hour))

		_, err := service.Resolve(
			ctx,
			signClaims(t, validClaims("expired")),
			testNow.Add(time.Minute),
		)
		require.ErrorIs(t, err, ErrDenied)
	})

	t.Run("rejects a locked user", func(t *testing.T) {
		service := newTestService(t, stubLocks{locked: true}, newSessionStore(t, 72*time.Hour))
		accessToken := issueAccessToken(t, "dev-01", "", testNow)

		_, err := service.Resolve(ctx, accessToken, testNow.Add(time.Minute))
		require.ErrorIs(t, err, ErrDenied)
	})

	t.Run("rejects a revoked session", func(t *testing.T) {
		store := newSessionStore(t, 72*time.Hour)
		createSession(t, store, "dev-01", 0, testNow)
		service := newTestService(t, stubLocks{}, store)
		accessToken := issueAccessToken(t, "dev-01", referenceSessionID, testNow)
		require.NoError(t, store.RevokeAllForSubject(ctx, "dev-01"))

		_, err := service.Resolve(ctx, accessToken, testNow.Add(time.Minute))
		require.ErrorIs(t, err, ErrDenied)
	})

	t.Run("rejects an expired session", func(t *testing.T) {
		store := newSessionStore(t, 5*time.Minute)
		createSession(t, store, "dev-01", 0, testNow)
		service := newTestService(t, stubLocks{}, store)
		accessToken := issueAccessToken(t, "dev-01", referenceSessionID, testNow.Add(time.Minute))

		_, err := service.Resolve(ctx, accessToken, testNow.Add(6*time.Minute))
		require.ErrorIs(t, err, ErrDenied)
	})

	t.Run("rejects a stale TOTP revision", func(t *testing.T) {
		store := newSessionStore(t, 72*time.Hour)
		createSession(t, store, "rotated", 0, testNow)
		service := newTestService(t, stubLocks{}, store)
		accessToken := issueAccessToken(t, "rotated", referenceSessionID, testNow)

		_, err := service.Resolve(ctx, accessToken, testNow.Add(time.Minute))
		require.ErrorIs(t, err, ErrDenied)
	})

	t.Run("rejects a session bound to another subject", func(t *testing.T) {
		store := newSessionStore(t, 72*time.Hour)
		createSession(t, store, "dev-01", 0, testNow)
		service := newTestService(t, stubLocks{}, store)
		claims := validClaims("leaky")
		claims["jti"] = referenceSessionID

		_, err := service.Resolve(ctx, signClaims(t, claims), testNow.Add(time.Minute))
		require.ErrorIs(t, err, ErrDenied)
	})

	t.Run("rejects a non-string jti", func(t *testing.T) {
		service := newTestService(t, stubLocks{}, newSessionStore(t, 72*time.Hour))
		claims := validClaims("dev-01")
		claims["jti"] = 123

		_, err := service.Resolve(ctx, signClaims(t, claims), testNow.Add(time.Minute))
		require.ErrorIs(t, err, ErrDenied)
	})

	t.Run("rejects an empty jti", func(t *testing.T) {
		service := newTestService(t, stubLocks{}, newSessionStore(t, 72*time.Hour))
		claims := validClaims("dev-01")
		claims["jti"] = ""

		_, err := service.Resolve(ctx, signClaims(t, claims), testNow.Add(time.Minute))
		require.ErrorIs(t, err, ErrDenied)
	})

	t.Run("propagates lock check failures", func(t *testing.T) {
		service := newTestService(
			t,
			stubLocks{err: errors.New("store down")},
			newSessionStore(t, 72*time.Hour),
		)
		accessToken := issueAccessToken(t, "dev-01", "", testNow)

		_, err := service.Resolve(ctx, accessToken, testNow.Add(time.Minute))
		require.ErrorContains(t, err, "check user locks")
		require.NotErrorIs(t, err, ErrDenied)
	})

	t.Run("propagates session validation failures", func(t *testing.T) {
		service := newTestService(t, stubLocks{}, stubSessions{err: errors.New("db down")})

		_, err := service.Resolve(ctx, referenceBoundToken, testNow.Add(time.Minute))
		require.ErrorContains(t, err, "validate session")
		require.NotErrorIs(t, err, ErrDenied)
	})
}
