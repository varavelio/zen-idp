package lock

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
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

// newTestLocks returns a manager backed by a migrated temporary SQLite
// database and its sqlc queries.
func newTestLocks(t *testing.T) (*Locks, *statestore.Queries) {
	t.Helper()
	queries := statestore.New(newTestDB(t))
	locks, err := NewLocks(queries)
	require.NoError(t, err)
	return locks, queries
}

func TestNewLocks(t *testing.T) {
	t.Run("rejects nil queries", func(t *testing.T) {
		_, err := NewLocks(nil)
		require.Error(t, err)
	})

	t.Run("accepts valid queries", func(t *testing.T) {
		_, queries := newTestLocks(t)
		locks, err := NewLocks(queries)
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
		locks, _ := newTestLocks(t)
		require.NoError(t, locks.LockPanic(context.Background(), testSubject, testNow))

		locked, err := locks.IsLocked(context.Background(), testSubject)
		require.NoError(t, err)
		require.True(t, locked)
	})

	t.Run("reports locked when only the administrative lock exists", func(t *testing.T) {
		locks, _ := newTestLocks(t)
		require.NoError(t, locks.LockAdmin(context.Background(), testSubject, testNow))

		locked, err := locks.IsLocked(context.Background(), testSubject)
		require.NoError(t, err)
		require.True(t, locked)
	})

	t.Run("reports locked when both locks exist", func(t *testing.T) {
		locks, _ := newTestLocks(t)
		require.NoError(t, locks.LockPanic(context.Background(), testSubject, testNow))
		require.NoError(t, locks.LockAdmin(context.Background(), testSubject, testNow))

		locked, err := locks.IsLocked(context.Background(), testSubject)
		require.NoError(t, err)
		require.True(t, locked)
	})

	t.Run("clearing one lock does not unlock a subject holding the other", func(t *testing.T) {
		locks, _ := newTestLocks(t)
		require.NoError(t, locks.LockPanic(context.Background(), testSubject, testNow))
		require.NoError(t, locks.LockAdmin(context.Background(), testSubject, testNow))
		require.NoError(t, locks.ClearAdmin(context.Background(), testSubject))

		locked, err := locks.IsLocked(context.Background(), testSubject)
		require.NoError(t, err)
		require.True(t, locked)
	})

	t.Run("does not leak locks across subjects", func(t *testing.T) {
		locks, _ := newTestLocks(t)
		require.NoError(t, locks.LockPanic(context.Background(), testSubject, testNow))

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
