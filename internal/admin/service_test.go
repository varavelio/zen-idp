package admin

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
	"github.com/varavelio/zen-idp/internal/audit"
	"github.com/varavelio/zen-idp/internal/id"
	"github.com/varavelio/zen-idp/internal/ratelimit"
	sess "github.com/varavelio/zen-idp/internal/session"
	"github.com/varavelio/zen-idp/internal/statestore"
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

// testAdminPassword is the plaintext administrator credential of the test
// service and testAdminPasswordHash is its precomputed Argon2id PHC hash,
// anchored as a regression vector.
const (
	testAdminPassword     = "test-admin-password"
	testAdminPasswordHash = "$argon2id$v=19$m=65536,t=2,p=2$INy39hwa9rMN8WhprspfDQ$45uH4EsaLtb2h9bUkVfgAAoLKsgPK1ALYprlwxm16B4"
)

// testMaxAttempts and testWindow bound the test rate limiter.
const (
	testMaxAttempts = 3
	testWindow      = time.Hour
)

// testNow is the fixed instant used as the authentication time in tests.
var testNow = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

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

// newTestService returns a service backed by a migrated temporary SQLite
// database with a real rate limiter, session store, and audit recorder,
// together with the underlying session store for behavioral assertions.
func newTestService(t *testing.T) (*Service, *sess.Store) {
	t.Helper()
	queries := statestore.New(newTestDB(t))
	rootSecret := referenceRootSecret

	limiter, err := ratelimit.New(queries, testMaxAttempts, testWindow)
	require.NoError(t, err)

	stores, err := sess.NewStore(queries, id.NewIDGenerator(), rootSecret, 72*time.Hour)
	require.NoError(t, err)

	recorder, err := audit.NewRecorder(queries, id.NewIDGenerator())
	require.NoError(t, err)

	service, err := New(testAdminPasswordHash, limiter, stores, recorder)
	require.NoError(t, err)
	return service, stores
}

func TestNew(t *testing.T) {
	queries := statestore.New(newTestDB(t))
	limiter, err := ratelimit.New(queries, testMaxAttempts, testWindow)
	require.NoError(t, err)
	stores, err := sess.NewStore(queries, id.NewIDGenerator(), referenceRootSecret, time.Hour)
	require.NoError(t, err)
	recorder, err := audit.NewRecorder(queries, id.NewIDGenerator())
	require.NoError(t, err)

	t.Run("rejects an invalid password hash", func(t *testing.T) {
		_, err := New("not-a-phc-hash", limiter, stores, recorder)
		require.ErrorContains(t, err, "admin password hash")
	})

	t.Run("rejects an empty password hash", func(t *testing.T) {
		_, err := New("", limiter, stores, recorder)
		require.ErrorContains(t, err, "admin password hash")
	})

	t.Run("rejects nil rate limiter", func(t *testing.T) {
		_, err := New(testAdminPasswordHash, nil, stores, recorder)
		require.EqualError(t, err, "admin rate limiter is nil")
	})

	t.Run("rejects nil session creator", func(t *testing.T) {
		_, err := New(testAdminPasswordHash, limiter, nil, recorder)
		require.EqualError(t, err, "admin session creator is nil")
	})

	t.Run("rejects nil audit recorder", func(t *testing.T) {
		_, err := New(testAdminPasswordHash, limiter, stores, nil)
		require.EqualError(t, err, "admin audit recorder is nil")
	})

	t.Run("accepts valid dependencies", func(t *testing.T) {
		service, err := New(testAdminPasswordHash, limiter, stores, recorder)
		require.NoError(t, err)
		require.NotNil(t, service)
	})
}

func TestLogin(t *testing.T) {
	t.Run("authenticates the administrator and creates an admin session", func(t *testing.T) {
		service, stores := newTestService(t)

		token, err := service.Login(context.Background(), testAdminPassword, testNow)
		require.NoError(t, err)
		require.NotEmpty(t, token)

		record, err := stores.ValidateAdmin(context.Background(), token, testNow.Add(time.Hour))
		require.NoError(t, err)
		require.Equal(t, sess.KindAdmin, record.Kind)
	})

	t.Run("the admin session never validates as a user session", func(t *testing.T) {
		service, stores := newTestService(t)

		token, err := service.Login(context.Background(), testAdminPassword, testNow)
		require.NoError(t, err)

		_, err = stores.Validate(context.Background(), token, testNow.Add(time.Hour))
		require.ErrorIs(t, err, sess.ErrInvalidSession)
	})

	t.Run("rejects a wrong password with ErrDenied", func(t *testing.T) {
		service, _ := newTestService(t)

		_, err := service.Login(context.Background(), "wrong-password", testNow)
		require.ErrorIs(t, err, ErrDenied)
	})

	t.Run("recovers after a wrong password", func(t *testing.T) {
		service, _ := newTestService(t)

		_, err := service.Login(context.Background(), "wrong-password", testNow)
		require.ErrorIs(t, err, ErrDenied)

		token, err := service.Login(context.Background(), testAdminPassword, testNow)
		require.NoError(t, err)
		require.NotEmpty(t, token)
	})

	t.Run("throttles after exhausting the attempt budget", func(t *testing.T) {
		service, stores := newTestService(t)

		for range testMaxAttempts {
			_, err := service.Login(context.Background(), "wrong-password", testNow)
			require.ErrorIs(t, err, ErrDenied)
		}

		// The budget is exhausted: even the correct password is denied and
		// no new session is created.
		token, err := service.Login(context.Background(), testAdminPassword, testNow)
		require.ErrorIs(t, err, ErrDenied)
		require.Empty(t, token)

		_, err = stores.ValidateAdmin(context.Background(), "sess_unknown_secret", testNow)
		require.ErrorIs(t, err, sess.ErrInvalidSession)
	})

	t.Run("resets the budget after a successful login", func(t *testing.T) {
		service, _ := newTestService(t)

		for range testMaxAttempts - 1 {
			_, err := service.Login(context.Background(), "wrong-password", testNow)
			require.ErrorIs(t, err, ErrDenied)
		}

		_, err := service.Login(context.Background(), testAdminPassword, testNow)
		require.NoError(t, err)

		// A fresh budget is available after the reset.
		for range testMaxAttempts - 1 {
			_, err := service.Login(context.Background(), "wrong-password", testNow)
			require.ErrorIs(t, err, ErrDenied)
		}
		_, err = service.Login(context.Background(), testAdminPassword, testNow)
		require.NoError(t, err)
	})

	t.Run("propagates rate limiter failures", func(t *testing.T) {
		service, _ := newTestService(t)
		service.rateLimiter = failingLimiter{err: errors.New("boom")}

		_, err := service.Login(context.Background(), testAdminPassword, testNow)
		require.ErrorContains(t, err, "check admin rate limit: boom")
	})

	t.Run("propagates session creation failures", func(t *testing.T) {
		service, _ := newTestService(t)
		service.sessions = failingSessionCreator{err: errors.New("boom")}

		_, err := service.Login(context.Background(), testAdminPassword, testNow)
		require.ErrorContains(t, err, "create admin session: boom")
	})

	t.Run("propagates audit failures", func(t *testing.T) {
		service, _ := newTestService(t)
		service.audit = failingRecorder{err: errors.New("boom")}

		_, err := service.Login(context.Background(), testAdminPassword, testNow)
		require.ErrorContains(t, err, "record admin authentication event: boom")
	})
}

func TestLoginAuditEvents(t *testing.T) {
	// listEvents returns the recorded audit events with the recorder built
	// inside the service under test.
	listEvents := func(t *testing.T, service *Service) []audit.Event {
		t.Helper()
		recorder, ok := service.audit.(*audit.Recorder)
		require.True(t, ok)
		events, err := recorder.List(context.Background(), 10)
		require.NoError(t, err)
		return events
	}

	t.Run("records failed and successful authentications", func(t *testing.T) {
		service, _ := newTestService(t)

		_, err := service.Login(context.Background(), "wrong-password", testNow)
		require.ErrorIs(t, err, ErrDenied)
		_, err = service.Login(context.Background(), testAdminPassword, testNow)
		require.NoError(t, err)

		events := listEvents(t, service)
		require.Len(t, events, 2)
		require.Equal(t, audit.CategoryAdminAuthentication, events[0].Category)
		require.JSONEq(t, `{"outcome":"success"}`, events[0].Details)
		require.Equal(t, audit.CategoryAdminAuthentication, events[1].Category)
		require.JSONEq(t, `{"outcome":"failure"}`, events[1].Details)
	})

	t.Run("does not audit throttled attempts", func(t *testing.T) {
		service, _ := newTestService(t)

		for range testMaxAttempts {
			_, err := service.Login(context.Background(), "wrong-password", testNow)
			require.ErrorIs(t, err, ErrDenied)
		}
		// The throttled attempt carries no verification and no event.
		_, err := service.Login(context.Background(), testAdminPassword, testNow)
		require.ErrorIs(t, err, ErrDenied)

		events := listEvents(t, service)
		require.Len(t, events, testMaxAttempts)
		for _, event := range events {
			require.JSONEq(t, `{"outcome":"failure"}`, event.Details)
		}
	})
}

// failingLimiter, failingSessionCreator, and failingRecorder are stub
// implementations that always return the configured error.
type failingLimiter struct{ err error }

func (stub failingLimiter) Allow(context.Context, string, time.Time) (bool, error) {
	return false, stub.err
}

func (stub failingLimiter) RecordFailure(context.Context, string, time.Time) error {
	return stub.err
}

func (stub failingLimiter) Reset(context.Context, string) error {
	return stub.err
}

type failingSessionCreator struct{ err error }

func (stub failingSessionCreator) CreateAdmin(context.Context, sess.AdminParams) (string, error) {
	return "", stub.err
}

type failingRecorder struct{ err error }

func (stub failingRecorder) Record(context.Context, audit.RecordParams) error {
	return stub.err
}
