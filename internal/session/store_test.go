package session

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/varavelio/zen-idp/internal/clock"
	"github.com/varavelio/zen-idp/internal/id"
	"github.com/varavelio/zen-idp/internal/statestore"
)

const (
	testSubject = "dev-01"
	testTOTPRev = uint64(2)
	testMaxAge  = 72 * time.Hour
)

// testNow is the fixed instant used as the creation time in lifecycle tests.
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

// newTestStore returns a store backed by a migrated temporary SQLite
// database, the anchored reference root secret, and its sqlc queries.
func newTestStore(t *testing.T, maxAge time.Duration) (*Store, *statestore.Queries) {
	t.Helper()
	queries := statestore.New(newTestDB(t))
	store, err := NewStore(
		queries,
		id.NewIDGenerator(),
		referenceRootSecret,
		maxAge,
	)
	require.NoError(t, err)
	return store, queries
}

// createToken records a session for the test identity at testNow and returns
// its browser token.
func createToken(t *testing.T, store *Store) string {
	t.Helper()
	token, err := store.Create(context.Background(), CreateParams{
		Subject: testSubject,
		TOTPRev: testTOTPRev,
		Now:     testNow,
	})
	require.NoError(t, err)
	return token
}

// splitToken returns the id and secret halves of a browser token.
func splitToken(t *testing.T, token string) (id, secret string) {
	t.Helper()
	parts := strings.Split(token, "_")
	require.Len(t, parts, 3)
	require.Equal(t, "sess", parts[0])
	require.NotEmpty(t, parts[1])
	require.NotEmpty(t, parts[2])
	return parts[1], parts[2]
}

func TestNewStore(t *testing.T) {
	queries := statestore.New(newTestDB(t))
	ids := id.NewIDGenerator()

	t.Run("rejects nil queries", func(t *testing.T) {
		_, err := NewStore(nil, ids, referenceRootSecret, testMaxAge)
		require.EqualError(t, err, "session store queries are nil")
	})

	t.Run("rejects nil id generator", func(t *testing.T) {
		_, err := NewStore(queries, nil, referenceRootSecret, testMaxAge)
		require.EqualError(t, err, "session store id generator is nil")
	})

	t.Run("rejects non-positive max age", func(t *testing.T) {
		_, err := NewStore(queries, ids, referenceRootSecret, 0)
		require.EqualError(t, err, "session max age must be positive")
		_, err = NewStore(queries, ids, referenceRootSecret, -time.Hour)
		require.EqualError(t, err, "session max age must be positive")
	})

	t.Run("accepts valid dependencies", func(t *testing.T) {
		store, err := NewStore(queries, ids, referenceRootSecret, testMaxAge)
		require.NoError(t, err)
		require.NotNil(t, store)
	})
}

func TestCreate(t *testing.T) {
	t.Run("returns a sess_{id}_{secret} token", func(t *testing.T) {
		store, _ := newTestStore(t, testMaxAge)
		token := createToken(t, store)
		splitToken(t, token)
	})

	t.Run("persists the record with canonical timestamps", func(t *testing.T) {
		store, queries := newTestStore(t, testMaxAge)
		token := createToken(t, store)
		idPart, _ := splitToken(t, token)

		record, err := queries.GetSession(context.Background(), idPart)
		require.NoError(t, err)
		require.Equal(t, testSubject, record.Sub)
		require.Equal(t, int64(testTOTPRev), record.TotpRev)
		require.Equal(t, clock.Format(testNow), record.CreatedAt)
		require.Equal(t, clock.Format(testNow.Add(testMaxAge)), record.ExpiresAt)
		require.False(t, record.IpAddress.Valid)
		require.False(t, record.UserAgent.Valid)
	})

	t.Run("stores only the domain-separated secret digest", func(t *testing.T) {
		store, queries := newTestStore(t, testMaxAge)
		token := createToken(t, store)
		idPart, secretPart := splitToken(t, token)

		record, err := queries.GetSession(context.Background(), idPart)
		require.NoError(t, err)
		require.NotEqual(t, []byte(secretPart), record.SecretHash)
		require.Equal(t, hashSecret(referenceRootSecret, secretPart), record.SecretHash)
	})

	t.Run("records client context when provided", func(t *testing.T) {
		store, queries := newTestStore(t, testMaxAge)
		token, err := store.Create(context.Background(), CreateParams{
			Subject:   testSubject,
			TOTPRev:   testTOTPRev,
			IPAddress: "192.0.2.10",
			UserAgent: "curl/8.0",
			Now:       testNow,
		})
		require.NoError(t, err)
		idPart, _ := splitToken(t, token)

		record, err := queries.GetSession(context.Background(), idPart)
		require.NoError(t, err)
		require.Equal(t, "192.0.2.10", record.IpAddress.String)
		require.True(t, record.IpAddress.Valid)
		require.Equal(t, "curl/8.0", record.UserAgent.String)
		require.True(t, record.UserAgent.Valid)
	})

	t.Run("creates distinct tokens per session", func(t *testing.T) {
		store, _ := newTestStore(t, testMaxAge)
		first := createToken(t, store)
		second := createToken(t, store)
		require.NotEqual(t, first, second)
	})

	t.Run("rejects an empty subject", func(t *testing.T) {
		store, _ := newTestStore(t, testMaxAge)
		_, err := store.Create(context.Background(), CreateParams{Now: testNow})
		require.EqualError(t, err, "session subject must not be empty")
	})
}

func TestValidate(t *testing.T) {
	t.Run("authenticates a fresh token", func(t *testing.T) {
		store, _ := newTestStore(t, testMaxAge)
		token := createToken(t, store)
		idPart, _ := splitToken(t, token)

		session, err := store.Validate(
			context.Background(), token, testNow.Add(time.Hour),
		)
		require.NoError(t, err)
		require.Equal(t, idPart, session.ID)
		require.Equal(t, testSubject, session.Subject)
		require.Equal(t, testTOTPRev, session.TOTPRev)
		require.Equal(t, testNow, session.CreatedAt)
		require.Equal(t, testNow.Add(testMaxAge), session.ExpiresAt)
	})

	t.Run("accepts one second before expiration", func(t *testing.T) {
		store, _ := newTestStore(t, testMaxAge)
		token := createToken(t, store)

		_, err := store.Validate(
			context.Background(), token, testNow.Add(testMaxAge-time.Second),
		)
		require.NoError(t, err)
	})

	t.Run("rejects at the expiration instant and deletes the row", func(t *testing.T) {
		store, queries := newTestStore(t, testMaxAge)
		token := createToken(t, store)
		idPart, _ := splitToken(t, token)

		_, err := store.Validate(context.Background(), token, testNow.Add(testMaxAge))
		require.ErrorIs(t, err, ErrExpiredSession)

		_, err = store.Validate(context.Background(), token, testNow.Add(testMaxAge))
		require.ErrorIs(t, err, ErrInvalidSession)

		_, err = queries.GetSession(context.Background(), idPart)
		require.ErrorIs(t, err, sql.ErrNoRows)
	})

	t.Run("rejects a wrong secret", func(t *testing.T) {
		store, _ := newTestStore(t, testMaxAge)
		token := createToken(t, store)
		idPart, _ := splitToken(t, token)

		forged := formatToken(idPart, "F0rg3dS3cr3tF0rg3dS3cr3tF0rg3dS3cr3tF0rg3d")
		_, err := store.Validate(context.Background(), forged, testNow.Add(time.Hour))
		require.ErrorIs(t, err, ErrInvalidSession)
	})

	t.Run("rejects an unknown identifier", func(t *testing.T) {
		store, _ := newTestStore(t, testMaxAge)
		unknown := formatToken(
			"01h2v8d9q3m5t7w0x2y4a6c8e",
			"F0rg3dS3cr3tF0rg3dS3cr3tF0rg3dS3cr3tF0rg3d",
		)

		_, err := store.Validate(context.Background(), unknown, testNow.Add(time.Hour))
		require.ErrorIs(t, err, ErrInvalidSession)
	})

	t.Run("rejects a malformed token", func(t *testing.T) {
		store, _ := newTestStore(t, testMaxAge)
		_, err := store.Validate(context.Background(), "not-a-token", testNow)
		require.ErrorIs(t, err, ErrMalformedToken)
	})
}

func TestValidateID(t *testing.T) {
	t.Run("validates an active record by its identifier", func(t *testing.T) {
		store, _ := newTestStore(t, testMaxAge)
		token := createToken(t, store)
		idPart, _ := splitToken(t, token)

		session, err := store.ValidateID(
			context.Background(), idPart, testNow.Add(time.Hour),
		)
		require.NoError(t, err)
		require.Equal(t, idPart, session.ID)
		require.Equal(t, testSubject, session.Subject)
		require.Equal(t, testTOTPRev, session.TOTPRev)
		require.Equal(t, testNow, session.CreatedAt)
		require.Equal(t, testNow.Add(testMaxAge), session.ExpiresAt)
	})

	t.Run("accepts one second before expiration", func(t *testing.T) {
		store, _ := newTestStore(t, testMaxAge)
		token := createToken(t, store)
		idPart, _ := splitToken(t, token)

		_, err := store.ValidateID(
			context.Background(), idPart, testNow.Add(testMaxAge-time.Second),
		)
		require.NoError(t, err)
	})

	t.Run("rejects at the expiration instant and deletes the row", func(t *testing.T) {
		store, queries := newTestStore(t, testMaxAge)
		token := createToken(t, store)
		idPart, _ := splitToken(t, token)

		_, err := store.ValidateID(context.Background(), idPart, testNow.Add(testMaxAge))
		require.ErrorIs(t, err, ErrExpiredSession)

		_, err = store.ValidateID(context.Background(), idPart, testNow.Add(testMaxAge))
		require.ErrorIs(t, err, ErrInvalidSession)

		_, err = queries.GetSession(context.Background(), idPart)
		require.ErrorIs(t, err, sql.ErrNoRows)
	})

	t.Run("rejects an unknown identifier", func(t *testing.T) {
		store, _ := newTestStore(t, testMaxAge)

		_, err := store.ValidateID(
			context.Background(), "01h2v8d9q3m5t7w0x2y4a6c8e", testNow.Add(time.Hour),
		)
		require.ErrorIs(t, err, ErrInvalidSession)
	})

	t.Run("rejects an empty identifier", func(t *testing.T) {
		store, _ := newTestStore(t, testMaxAge)

		_, err := store.ValidateID(context.Background(), "", testNow.Add(time.Hour))
		require.EqualError(t, err, "session id must not be empty")
	})
}

func TestRevoke(t *testing.T) {
	t.Run("invalidates the revoked token", func(t *testing.T) {
		store, _ := newTestStore(t, testMaxAge)
		token := createToken(t, store)

		require.NoError(t, store.Revoke(context.Background(), token))
		_, err := store.Validate(context.Background(), token, testNow.Add(time.Hour))
		require.ErrorIs(t, err, ErrInvalidSession)
	})

	t.Run("revoking an unknown token succeeds", func(t *testing.T) {
		store, _ := newTestStore(t, testMaxAge)
		unknown := formatToken(
			"01h2v8d9q3m5t7w0x2y4a6c8e",
			"F0rg3dS3cr3tF0rg3dS3cr3tF0rg3dS3cr3tF0rg3d",
		)
		require.NoError(t, store.Revoke(context.Background(), unknown))
	})

	t.Run("rejects a malformed token", func(t *testing.T) {
		store, _ := newTestStore(t, testMaxAge)
		err := store.Revoke(context.Background(), "not-a-token")
		require.ErrorIs(t, err, ErrMalformedToken)
	})
}

func TestRevokeAllForSubject(t *testing.T) {
	t.Run("revokes every session of the subject only", func(t *testing.T) {
		store, _ := newTestStore(t, testMaxAge)
		first := createToken(t, store)
		second := createToken(t, store)

		otherToken, err := store.Create(context.Background(), CreateParams{
			Subject: "dev-02",
			TOTPRev: testTOTPRev,
			Now:     testNow,
		})
		require.NoError(t, err)

		require.NoError(t, store.RevokeAllForSubject(context.Background(), testSubject))

		_, err = store.Validate(context.Background(), first, testNow.Add(time.Hour))
		require.ErrorIs(t, err, ErrInvalidSession)
		_, err = store.Validate(context.Background(), second, testNow.Add(time.Hour))
		require.ErrorIs(t, err, ErrInvalidSession)

		_, err = store.Validate(context.Background(), otherToken, testNow.Add(time.Hour))
		require.NoError(t, err)
	})
}
