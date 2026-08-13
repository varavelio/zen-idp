package login

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"database/sql"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/varavelio/zen-idp/internal/audit"
	"github.com/varavelio/zen-idp/internal/clock"
	"github.com/varavelio/zen-idp/internal/config"
	"github.com/varavelio/zen-idp/internal/id"
	"github.com/varavelio/zen-idp/internal/lock"
	"github.com/varavelio/zen-idp/internal/ratelimit"
	"github.com/varavelio/zen-idp/internal/session"
	"github.com/varavelio/zen-idp/internal/statestore"
	"github.com/varavelio/zen-idp/internal/totp"
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

const (
	testSubject = "alice"
	testLogin   = "alice@example.com"
	testMaxAge  = 72 * time.Hour
)

// testUsers covers both identifier kinds and a non-zero TOTP revision.
var testUsers = []config.User{
	{Subject: testSubject, Login: testLogin, TOTPRevision: 0},
	{Subject: "bob", TOTPRevision: 2},
}

// testNow is the fixed instant used as the authentication time in tests.
var testNow = time.Date(2026, 1, 2, 15, 4, 5, 0, time.UTC)

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

// testTxRunner runs functions inside transactions of the test database,
// satisfying the transaction-runner interface of the lock package.
type testTxRunner struct {
	db *sql.DB
}

// WithTx runs fn inside one database transaction of the test database.
func (runner testTxRunner) WithTx(
	ctx context.Context,
	fn func(*statestore.Queries) error,
) error {
	return statestore.WithTx(ctx, runner.db, fn)
}

// testService bundles a login service with its real dependencies so tests
// can inspect counters, locks, sessions, and audit records directly.
type testService struct {
	service *Service
	queries *statestore.Queries
	limiter *ratelimit.Limiter
	locks   *lock.Locks
	session *session.Store
	audit   *audit.Recorder
}

// newTestService returns a service backed by a migrated temporary SQLite
// database and the anchored reference root secret.
func newTestService(
	t *testing.T,
	users []config.User,
	maxAttempts int,
	window time.Duration,
) testService {
	t.Helper()
	db := newTestDB(t)
	queries := statestore.New(db)
	limiter, err := ratelimit.New(queries, maxAttempts, window)
	require.NoError(t, err)
	locks, err := lock.NewLocks(queries, testTxRunner{db: db})
	require.NoError(t, err)
	store, err := session.NewStore(queries, id.NewIDGenerator(), referenceRootSecret, testMaxAge)
	require.NoError(t, err)
	recorder, err := audit.NewRecorder(queries, id.NewIDGenerator())
	require.NoError(t, err)
	service, err := New(users, referenceRootSecret, limiter, locks, store, recorder)
	require.NoError(t, err)
	return testService{
		service: service,
		queries: queries,
		limiter: limiter,
		locks:   locks,
		session: store,
		audit:   recorder,
	}
}

// codeFor derives the deterministic secret of one user and returns its
// RFC 6238 code at the given instant.
func codeFor(t *testing.T, sub string, revision uint64, at time.Time) string {
	t.Helper()
	secret, err := totp.DeriveSharedSecret(referenceRootSecret, sub, revision)
	require.NoError(t, err)
	return totpCode(t, secret, at)
}

// totpCode computes the RFC 6238 TOTP code for secret at the given instant
// with the authenticator profile: HMAC-SHA-1, a 30-second step, and six
// decimal digits. It is an independent implementation used to exercise the
// service against real codes.
func totpCode(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	require.NoError(t, err)

	counter := make([]byte, 8)
	binary.BigEndian.PutUint64(counter, uint64(at.Unix()/30))
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(counter)
	digest := mac.Sum(nil)

	offset := digest[len(digest)-1] & 0x0f
	code := binary.BigEndian.Uint32(digest[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", code%1_000_000)
}

// wrongCode returns a well-formed six-digit code that differs from code.
func wrongCode(code string) string {
	if code[len(code)-1] != '0' {
		return code[:len(code)-1] + "0"
	}
	return code[:len(code)-1] + "1"
}

func TestNew(t *testing.T) {
	t.Run("rejects nil rate limiter", func(t *testing.T) {
		db := newTestDB(t)
		queries := statestore.New(db)
		locks, err := lock.NewLocks(queries, testTxRunner{db: db})
		require.NoError(t, err)
		store, err := session.NewStore(
			queries,
			id.NewIDGenerator(),
			referenceRootSecret,
			testMaxAge,
		)
		require.NoError(t, err)
		recorder, err := audit.NewRecorder(queries, id.NewIDGenerator())
		require.NoError(t, err)

		_, err = New(testUsers, referenceRootSecret, nil, locks, store, recorder)
		require.EqualError(t, err, "login rate limiter is nil")
	})

	t.Run("rejects nil lock checker", func(t *testing.T) {
		queries := statestore.New(newTestDB(t))
		limiter, err := ratelimit.New(queries, 5, 5*time.Minute)
		require.NoError(t, err)
		store, err := session.NewStore(
			queries,
			id.NewIDGenerator(),
			referenceRootSecret,
			testMaxAge,
		)
		require.NoError(t, err)
		recorder, err := audit.NewRecorder(queries, id.NewIDGenerator())
		require.NoError(t, err)

		_, err = New(testUsers, referenceRootSecret, limiter, nil, store, recorder)
		require.EqualError(t, err, "login lock checker is nil")
	})

	t.Run("rejects nil session creator", func(t *testing.T) {
		db := newTestDB(t)
		queries := statestore.New(db)
		limiter, err := ratelimit.New(queries, 5, 5*time.Minute)
		require.NoError(t, err)
		locks, err := lock.NewLocks(queries, testTxRunner{db: db})
		require.NoError(t, err)
		recorder, err := audit.NewRecorder(queries, id.NewIDGenerator())
		require.NoError(t, err)

		_, err = New(testUsers, referenceRootSecret, limiter, locks, nil, recorder)
		require.EqualError(t, err, "login session creator is nil")
	})

	t.Run("rejects nil audit recorder", func(t *testing.T) {
		db := newTestDB(t)
		queries := statestore.New(db)
		limiter, err := ratelimit.New(queries, 5, 5*time.Minute)
		require.NoError(t, err)
		locks, err := lock.NewLocks(queries, testTxRunner{db: db})
		require.NoError(t, err)
		store, err := session.NewStore(
			queries,
			id.NewIDGenerator(),
			referenceRootSecret,
			testMaxAge,
		)
		require.NoError(t, err)

		_, err = New(testUsers, referenceRootSecret, limiter, locks, store, nil)
		require.EqualError(t, err, "login audit recorder is nil")
	})

	t.Run("accepts valid dependencies", func(t *testing.T) {
		service := newTestService(t, testUsers, 5, 5*time.Minute)
		require.NotNil(t, service.service)
	})
}

func TestLogin(t *testing.T) {
	t.Run("matches the independently computed reference vector", func(t *testing.T) {
		service := newTestService(t, testUsers, 5, 5*time.Minute)
		ctx := context.Background()

		secret, err := totp.DeriveSharedSecret(referenceRootSecret, "alice", 0)
		require.NoError(t, err)
		require.Equal(t, "LQJ2MSFEHZMA4KVBU5SNJRDAJHEH7PCGYIADZIKUDNYNG4SD6XFQ", secret)
		require.Equal(t, "949548", totpCode(t, secret, testNow))

		token, err := service.service.Login(ctx, Params{
			Identifier: "alice",
			Code:       "949548",
			Now:        testNow,
		})
		require.NoError(t, err)
		require.NotEmpty(t, token)
	})

	t.Run("authenticates by sub and records the session", func(t *testing.T) {
		service := newTestService(t, testUsers, 5, 5*time.Minute)
		ctx := context.Background()
		code := codeFor(t, "alice", 0, testNow)

		token, err := service.service.Login(ctx, Params{
			Identifier: "alice",
			Code:       code,
			IPAddress:  "192.0.2.10",
			UserAgent:  "login-test",
			Now:        testNow,
		})
		require.NoError(t, err)
		require.NotEmpty(t, token)

		authenticated, err := service.session.Validate(ctx, token, testNow.Add(time.Hour))
		require.NoError(t, err)
		require.Equal(t, testSubject, authenticated.Subject)
		require.Equal(t, uint64(0), authenticated.TOTPRev)

		id := strings.Split(token, "_")[1]
		record, err := service.queries.GetSession(ctx, id)
		require.NoError(t, err)
		require.Equal(t, "192.0.2.10", record.IpAddress.String)
		require.Equal(t, "login-test", record.UserAgent.String)
	})

	t.Run("authenticates by idp_login with the stable subject", func(t *testing.T) {
		service := newTestService(t, testUsers, 5, 5*time.Minute)
		ctx := context.Background()
		code := codeFor(t, "alice", 0, testNow)

		token, err := service.service.Login(ctx, Params{
			Identifier: testLogin,
			Code:       code,
			Now:        testNow,
		})
		require.NoError(t, err)

		authenticated, err := service.session.Validate(ctx, token, testNow.Add(time.Hour))
		require.NoError(t, err)
		require.Equal(t, testSubject, authenticated.Subject)
	})

	t.Run("records the authenticated TOTP revision", func(t *testing.T) {
		service := newTestService(t, testUsers, 5, 5*time.Minute)
		ctx := context.Background()
		code := codeFor(t, "bob", 2, testNow)

		token, err := service.service.Login(ctx, Params{
			Identifier: "bob",
			Code:       code,
			Now:        testNow,
		})
		require.NoError(t, err)

		authenticated, err := service.session.Validate(ctx, token, testNow.Add(time.Hour))
		require.NoError(t, err)
		require.Equal(t, uint64(2), authenticated.TOTPRev)
	})

	t.Run("accepts one adjacent time step of clock skew", func(t *testing.T) {
		service := newTestService(t, testUsers, 5, 5*time.Minute)
		ctx := context.Background()

		for _, skew := range []time.Duration{-30 * time.Second, 30 * time.Second} {
			token, err := service.service.Login(ctx, Params{
				Identifier: "alice",
				Code:       codeFor(t, "alice", 0, testNow.Add(skew)),
				Now:        testNow,
			})
			require.NoError(t, err)
			require.NotEmpty(t, token)
		}
	})

	t.Run("resets the failure counter on success", func(t *testing.T) {
		service := newTestService(t, testUsers, 5, 5*time.Minute)
		ctx := context.Background()
		code := codeFor(t, "alice", 0, testNow)
		wrong := wrongCode(code)

		for range 3 {
			_, err := service.service.Login(ctx, Params{
				Identifier: "alice",
				Code:       wrong,
				Now:        testNow,
			})
			require.ErrorIs(t, err, ErrDenied)
		}
		_, err := service.queries.GetRateLimitCounter(ctx, "alice")
		require.NoError(t, err)

		token, err := service.service.Login(ctx, Params{
			Identifier: "alice",
			Code:       code,
			Now:        testNow,
		})
		require.NoError(t, err)
		require.NotEmpty(t, token)

		_, err = service.queries.GetRateLimitCounter(ctx, "alice")
		require.ErrorIs(t, err, sql.ErrNoRows)
	})

	t.Run("shares one counter between sub and idp_login", func(t *testing.T) {
		service := newTestService(t, testUsers, 2, 5*time.Minute)
		ctx := context.Background()
		code := codeFor(t, "alice", 0, testNow)

		for _, identifier := range []string{testSubject, testLogin} {
			_, err := service.service.Login(ctx, Params{
				Identifier: identifier,
				Code:       wrongCode(code),
				Now:        testNow,
			})
			require.ErrorIs(t, err, ErrDenied)
		}

		record, err := service.queries.GetRateLimitCounter(ctx, "alice")
		require.NoError(t, err)
		require.Equal(t, int64(2), record.Attempts)

		_, err = service.service.Login(ctx, Params{
			Identifier: testLogin,
			Code:       code,
			Now:        testNow,
		})
		require.ErrorIs(t, err, ErrDenied)
	})

	t.Run("denies an unknown identifier and bounds it", func(t *testing.T) {
		service := newTestService(t, testUsers, 2, 5*time.Minute)
		ctx := context.Background()

		_, err := service.service.Login(ctx, Params{
			Identifier: "mallory@example.com",
			Code:       "123456",
			Now:        testNow,
		})
		require.ErrorIs(t, err, ErrDenied)

		record, err := service.queries.GetRateLimitCounter(ctx, "mallory@example.com")
		require.NoError(t, err)
		require.Equal(t, int64(1), record.Attempts)

		_, err = service.service.Login(ctx, Params{
			Identifier: "mallory@example.com",
			Code:       "654321",
			Now:        testNow,
		})
		require.ErrorIs(t, err, ErrDenied)

		_, err = service.service.Login(ctx, Params{
			Identifier: "mallory@example.com",
			Code:       "111111",
			Now:        testNow,
		})
		require.ErrorIs(t, err, ErrDenied)

		record, err = service.queries.GetRateLimitCounter(ctx, "mallory@example.com")
		require.NoError(t, err)
		require.Equal(t, int64(2), record.Attempts)
	})

	t.Run("denies an expired user with a valid code", func(t *testing.T) {
		users := append([]config.User(nil), testUsers...)
		users = append(users, config.User{Subject: "carol", ExpiresAt: testNow.Add(-time.Hour)})
		service := newTestService(t, users, 5, 5*time.Minute)
		ctx := context.Background()

		_, err := service.service.Login(ctx, Params{
			Identifier: "carol",
			Code:       codeFor(t, "carol", 0, testNow),
			Now:        testNow,
		})
		require.ErrorIs(t, err, ErrDenied)
	})

	t.Run("denies a user with an active panic lock", func(t *testing.T) {
		service := newTestService(t, testUsers, 5, 5*time.Minute)
		ctx := context.Background()
		require.NoError(t, service.queries.CreatePanicLock(ctx, statestore.CreatePanicLockParams{
			Sub:       testSubject,
			CreatedAt: clock.Format(testNow),
		}))

		_, err := service.service.Login(ctx, Params{
			Identifier: testSubject,
			Code:       codeFor(t, "alice", 0, testNow),
			Now:        testNow,
		})
		require.ErrorIs(t, err, ErrDenied)
	})

	t.Run("denies an administratively locked user", func(t *testing.T) {
		service := newTestService(t, testUsers, 5, 5*time.Minute)
		ctx := context.Background()
		require.NoError(t, service.locks.LockSubject(ctx, testSubject, testNow))

		_, err := service.service.Login(ctx, Params{
			Identifier: testSubject,
			Code:       codeFor(t, "alice", 0, testNow),
			Now:        testNow,
		})
		require.ErrorIs(t, err, ErrDenied)
	})

	t.Run("denies throttled identifiers before verification", func(t *testing.T) {
		service := newTestService(t, testUsers, 3, 5*time.Minute)
		ctx := context.Background()
		code := codeFor(t, "alice", 0, testNow)

		for range 3 {
			require.NoError(t, service.limiter.RecordFailure(ctx, "alice", testNow))
		}

		_, err := service.service.Login(ctx, Params{
			Identifier: testSubject,
			Code:       code,
			Now:        testNow,
		})
		require.ErrorIs(t, err, ErrDenied)

		record, err := service.queries.GetRateLimitCounter(ctx, "alice")
		require.NoError(t, err)
		require.Equal(t, int64(3), record.Attempts)
	})

	t.Run("denies a wrong code and consumes one failure", func(t *testing.T) {
		service := newTestService(t, testUsers, 5, 5*time.Minute)
		ctx := context.Background()
		code := codeFor(t, "alice", 0, testNow)

		_, err := service.service.Login(ctx, Params{
			Identifier: testSubject,
			Code:       wrongCode(code),
			Now:        testNow,
		})
		require.ErrorIs(t, err, ErrDenied)

		record, err := service.queries.GetRateLimitCounter(ctx, "alice")
		require.NoError(t, err)
		require.Equal(t, int64(1), record.Attempts)
	})

	t.Run("denies a malformed code", func(t *testing.T) {
		service := newTestService(t, testUsers, 5, 5*time.Minute)
		ctx := context.Background()

		for _, code := range []string{"12345", "abcdef", "1234567"} {
			_, err := service.service.Login(ctx, Params{
				Identifier: testSubject,
				Code:       code,
				Now:        testNow,
			})
			require.ErrorIs(t, err, ErrDenied)
		}
	})

	t.Run("denies an empty identifier", func(t *testing.T) {
		service := newTestService(t, testUsers, 5, 5*time.Minute)

		_, err := service.service.Login(context.Background(), Params{
			Identifier: "",
			Code:       codeFor(t, "alice", 0, testNow),
			Now:        testNow,
		})
		require.ErrorIs(t, err, ErrDenied)
	})

	t.Run("denies an oversized identifier", func(t *testing.T) {
		service := newTestService(t, testUsers, 5, 5*time.Minute)

		_, err := service.service.Login(context.Background(), Params{
			Identifier: strings.Repeat("x", 257),
			Code:       "123456",
			Now:        testNow,
		})
		require.ErrorIs(t, err, ErrDenied)
	})

	t.Run("every denial is the same generic error", func(t *testing.T) {
		users := append([]config.User(nil), testUsers...)
		users = append(users, config.User{Subject: "carol", ExpiresAt: testNow.Add(-time.Hour)})
		service := newTestService(t, users, 2, 5*time.Minute)
		ctx := context.Background()
		code := codeFor(t, "alice", 0, testNow)
		require.NoError(t, service.queries.CreatePanicLock(ctx, statestore.CreatePanicLockParams{
			Sub:       "bob",
			CreatedAt: clock.Format(testNow),
		}))

		cases := map[string]Params{
			"unknown identifier": {Identifier: "mallory", Code: "123456", Now: testNow},
			"wrong code":         {Identifier: testSubject, Code: wrongCode(code), Now: testNow},
			"malformed code":     {Identifier: testSubject, Code: "12ab", Now: testNow},
			"expired user": {
				Identifier: "carol",
				Code:       codeFor(t, "carol", 0, testNow),
				Now:        testNow,
			},
			"panicked user": {
				Identifier: "bob",
				Code:       codeFor(t, "bob", 2, testNow),
				Now:        testNow,
			},
		}

		for name, params := range cases {
			t.Run(name, func(t *testing.T) {
				_, err := service.service.Login(ctx, params)
				require.ErrorIs(t, err, ErrDenied)
			})
		}

		require.NoError(t, service.limiter.RecordFailure(ctx, "alice", testNow))
		require.NoError(t, service.limiter.RecordFailure(ctx, "alice", testNow))
		_, err := service.service.Login(ctx, Params{
			Identifier: testSubject,
			Code:       code,
			Now:        testNow,
		})
		require.ErrorIs(t, err, ErrDenied)
	})
}

func TestRateLimitAuditEvents(t *testing.T) {
	// listEvents returns the recorded audit events, newest first.
	listEvents := func(t *testing.T, service testService) []audit.Event {
		t.Helper()
		events, err := service.audit.List(context.Background(), 10)
		require.NoError(t, err)
		return events
	}

	// exhaust budgets every failed attempt of the key so the next login is
	// throttled before any verification.
	exhaust := func(t *testing.T, service testService, key string, maxAttempts int) {
		t.Helper()
		for range maxAttempts {
			require.NoError(t, service.limiter.RecordFailure(context.Background(), key, testNow))
		}
	}

	t.Run("records a throttled known user with its stable subject and key", func(t *testing.T) {
		service := newTestService(t, testUsers, 3, 5*time.Minute)
		exhaust(t, service, testSubject, 3)

		_, err := service.service.Login(context.Background(), Params{
			Identifier: testLogin,
			Code:       codeFor(t, testSubject, 0, testNow),
			Now:        testNow,
		})
		require.ErrorIs(t, err, ErrDenied)

		events := listEvents(t, service)
		require.Len(t, events, 1)
		require.Equal(t, audit.CategoryRateLimit, events[0].Category)
		require.Equal(t, testSubject, events[0].Subject)
		require.JSONEq(t, `{"key":"alice"}`, events[0].Details)
	})

	t.Run("records a throttled unknown identifier with its exact key", func(t *testing.T) {
		service := newTestService(t, testUsers, 3, 5*time.Minute)
		exhaust(t, service, "mallory", 3)

		_, err := service.service.Login(context.Background(), Params{
			Identifier: "mallory",
			Code:       "123456",
			Now:        testNow,
		})
		require.ErrorIs(t, err, ErrDenied)

		events := listEvents(t, service)
		require.Len(t, events, 1)
		require.Equal(t, audit.CategoryRateLimit, events[0].Category)
		require.Empty(t, events[0].Subject)
		require.JSONEq(t, `{"key":"mallory"}`, events[0].Details)
	})

	t.Run("does not record events for ordinary failed attempts", func(t *testing.T) {
		service := newTestService(t, testUsers, 5, 5*time.Minute)
		code := codeFor(t, testSubject, 0, testNow)

		for _, params := range []Params{
			{Identifier: testSubject, Code: wrongCode(code), Now: testNow},
			{Identifier: testSubject, Code: "12ab", Now: testNow},
			{Identifier: "mallory", Code: "123456", Now: testNow},
		} {
			_, err := service.service.Login(context.Background(), params)
			require.ErrorIs(t, err, ErrDenied)
		}

		require.Empty(t, listEvents(t, service))
	})

	t.Run("propagates audit failures on throttled attempts", func(t *testing.T) {
		service := newTestService(t, testUsers, 3, 5*time.Minute)
		exhaust(t, service, testSubject, 3)
		service.service.audit = failingAuditRecorder{err: errors.New("boom")}

		_, err := service.service.Login(context.Background(), Params{
			Identifier: testSubject,
			Code:       "123456",
			Now:        testNow,
		})

		require.ErrorContains(t, err, "record rate limit event: boom")
	})
}

// failingAuditRecorder is an audit recorder stub that always fails.
type failingAuditRecorder struct {
	err error
}

// Record fails with the stub error.
func (stub failingAuditRecorder) Record(context.Context, audit.RecordParams) error {
	return stub.err
}
