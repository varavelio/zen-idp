package lock

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/varavelio/zen-idp/internal/clock"
	"github.com/varavelio/zen-idp/internal/statestore"
)

const testSubject = "dev-01"

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

// testTxRunner runs functions inside transactions of the test database,
// satisfying the package's transaction-runner interface.
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

// newTestLocks returns a manager backed by a migrated temporary SQLite
// database and its sqlc queries.
func newTestLocks(t *testing.T) (*Locks, *statestore.Queries) {
	t.Helper()
	db := newTestDB(t)
	queries := statestore.New(db)
	locks, err := NewLocks(queries, testTxRunner{db: db})
	require.NoError(t, err)
	return locks, queries
}

// createPanicLock records a panic lock for the subject directly, without
// going through the manager, for tests of the remaining operations.
func createPanicLock(t *testing.T, queries *statestore.Queries, sub string) {
	t.Helper()
	require.NoError(
		t,
		queries.CreatePanicLock(context.Background(), statestore.CreatePanicLockParams{
			Sub:       sub,
			CreatedAt: clock.Format(testNow),
		}),
	)
}

// createAdminLock records an administrative lock for the subject directly,
// without going through the manager, for tests of the remaining operations.
func createAdminLock(t *testing.T, queries *statestore.Queries, sub string) {
	t.Helper()
	require.NoError(
		t,
		queries.CreateAdminLock(context.Background(), statestore.CreateAdminLockParams{
			Sub:       sub,
			CreatedAt: clock.Format(testNow),
		}),
	)
}

// insertSession records a user session row directly, without going through
// the session store, for the atomic-revocation tests.
func insertSession(t *testing.T, queries *statestore.Queries, id, sub string) {
	t.Helper()
	require.NoError(t, queries.CreateSession(context.Background(), statestore.CreateSessionParams{
		ID:         id,
		Kind:       "user",
		SecretHash: []byte("hash"),
		Sub:        sub,
		TotpRev:    0,
		CreatedAt:  clock.Format(testNow),
		ExpiresAt:  clock.Format(testNow.Add(time.Hour)),
	}))
}

func TestNewLocks(t *testing.T) {
	t.Run("rejects nil queries", func(t *testing.T) {
		_, err := NewLocks(nil, testTxRunner{})
		require.Error(t, err)
	})

	t.Run("rejects a nil transaction runner", func(t *testing.T) {
		queries := statestore.New(newTestDB(t))
		_, err := NewLocks(queries, nil)
		require.Error(t, err)
	})

	t.Run("accepts valid queries and runner", func(t *testing.T) {
		_, queries := newTestLocks(t)
		locks, err := NewLocks(queries, testTxRunner{})
		require.NoError(t, err)
		require.NotNil(t, locks)
	})
}

func TestIsLocked(t *testing.T) {
	t.Run("reports unlocked when no lock exists", func(t *testing.T) {
		locks, _ := newTestLocks(t)
		locked, err := locks.IsLocked(context.Background(), testSubject)
		require.NoError(t, err)
		require.False(t, locked)
	})

	t.Run("reports locked when only the panic lock exists", func(t *testing.T) {
		locks, queries := newTestLocks(t)
		createPanicLock(t, queries, testSubject)

		locked, err := locks.IsLocked(context.Background(), testSubject)
		require.NoError(t, err)
		require.True(t, locked)
	})

	t.Run("reports locked when only the administrative lock exists", func(t *testing.T) {
		locks, queries := newTestLocks(t)
		createAdminLock(t, queries, testSubject)

		locked, err := locks.IsLocked(context.Background(), testSubject)
		require.NoError(t, err)
		require.True(t, locked)
	})

	t.Run("reports locked when both locks exist", func(t *testing.T) {
		locks, queries := newTestLocks(t)
		createPanicLock(t, queries, testSubject)
		createAdminLock(t, queries, testSubject)

		locked, err := locks.IsLocked(context.Background(), testSubject)
		require.NoError(t, err)
		require.True(t, locked)
	})

	t.Run("clearing one lock does not unlock a subject holding the other", func(t *testing.T) {
		locks, queries := newTestLocks(t)
		createPanicLock(t, queries, testSubject)
		createAdminLock(t, queries, testSubject)
		require.NoError(t, locks.UnlockSubject(context.Background(), testSubject))

		locked, err := locks.IsLocked(context.Background(), testSubject)
		require.NoError(t, err)
		require.True(t, locked)
	})

	t.Run("does not leak locks across subjects", func(t *testing.T) {
		locks, queries := newTestLocks(t)
		createPanicLock(t, queries, testSubject)

		locked, err := locks.IsLocked(context.Background(), "other-subject")
		require.NoError(t, err)
		require.False(t, locked)
	})

	t.Run("rejects an empty subject", func(t *testing.T) {
		locks, _ := newTestLocks(t)
		_, err := locks.IsLocked(context.Background(), "")
		require.Error(t, err)
	})
}
