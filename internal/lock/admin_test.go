package lock

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/varavelio/zen-idp/internal/clock"
)

func TestLockAdmin(t *testing.T) {
	t.Run("creates a lock recording the given instant", func(t *testing.T) {
		locks, queries := newTestLocks(t)
		require.NoError(t, locks.LockAdmin(context.Background(), testSubject, testNow))

		record, err := queries.GetAdminLock(context.Background(), testSubject)
		require.NoError(t, err)
		require.Equal(t, clock.Format(testNow), record.CreatedAt)
	})

	t.Run("is idempotent and keeps the original creation instant", func(t *testing.T) {
		locks, queries := newTestLocks(t)
		require.NoError(t, locks.LockAdmin(context.Background(), testSubject, testNow))
		require.NoError(
			t,
			locks.LockAdmin(context.Background(), testSubject, testNow.Add(time.Hour)),
		)

		record, err := queries.GetAdminLock(context.Background(), testSubject)
		require.NoError(t, err)
		require.Equal(t, clock.Format(testNow), record.CreatedAt)
	})

	t.Run("rejects an empty subject", func(t *testing.T) {
		locks, _ := newTestLocks(t)
		require.Error(t, locks.LockAdmin(context.Background(), "", testNow))
	})
}

func TestIsAdminLocked(t *testing.T) {
	t.Run("reports false for a subject without a lock", func(t *testing.T) {
		locks, _ := newTestLocks(t)
		locked, err := locks.IsAdminLocked(context.Background(), testSubject)
		require.NoError(t, err)
		require.False(t, locked)
	})

	t.Run("reports true after locking", func(t *testing.T) {
		locks, _ := newTestLocks(t)
		require.NoError(t, locks.LockAdmin(context.Background(), testSubject, testNow))

		locked, err := locks.IsAdminLocked(context.Background(), testSubject)
		require.NoError(t, err)
		require.True(t, locked)
	})

	t.Run("reports false after clearing", func(t *testing.T) {
		locks, _ := newTestLocks(t)
		require.NoError(t, locks.LockAdmin(context.Background(), testSubject, testNow))
		require.NoError(t, locks.ClearAdmin(context.Background(), testSubject))

		locked, err := locks.IsAdminLocked(context.Background(), testSubject)
		require.NoError(t, err)
		require.False(t, locked)
	})

	t.Run("ignores a panic lock", func(t *testing.T) {
		locks, _ := newTestLocks(t)
		require.NoError(t, locks.LockPanic(context.Background(), testSubject, testNow))

		locked, err := locks.IsAdminLocked(context.Background(), testSubject)
		require.NoError(t, err)
		require.False(t, locked)
	})

	t.Run("rejects an empty subject", func(t *testing.T) {
		locks, _ := newTestLocks(t)
		_, err := locks.IsAdminLocked(context.Background(), "")
		require.Error(t, err)
	})
}

func TestClearAdmin(t *testing.T) {
	t.Run("removes an existing lock", func(t *testing.T) {
		locks, queries := newTestLocks(t)
		require.NoError(t, locks.LockAdmin(context.Background(), testSubject, testNow))
		require.NoError(t, locks.ClearAdmin(context.Background(), testSubject))

		_, err := queries.GetAdminLock(context.Background(), testSubject)
		require.ErrorIs(t, err, sql.ErrNoRows)
	})

	t.Run("succeeds for a subject without a lock", func(t *testing.T) {
		locks, _ := newTestLocks(t)
		require.NoError(t, locks.ClearAdmin(context.Background(), testSubject))
	})

	t.Run("rejects an empty subject", func(t *testing.T) {
		locks, _ := newTestLocks(t)
		require.Error(t, locks.ClearAdmin(context.Background(), ""))
	})
}
