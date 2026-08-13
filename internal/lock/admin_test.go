package lock

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/varavelio/zen-idp/internal/clock"
)

func TestLockSubject(t *testing.T) {
	t.Run("creates the administrative lock recording the given instant", func(t *testing.T) {
		locks, queries := newTestLocks(t)
		require.NoError(t, locks.LockSubject(context.Background(), testSubject, testNow))

		record, err := queries.GetAdminLock(context.Background(), testSubject)
		require.NoError(t, err)
		require.Equal(t, clock.Format(testNow), record.CreatedAt)

		locked, err := locks.IsLocked(context.Background(), testSubject)
		require.NoError(t, err)
		require.True(t, locked)
	})

	t.Run("revokes every active session of the subject in the same call", func(t *testing.T) {
		locks, queries := newTestLocks(t)
		insertSession(t, queries, "sess-1", testSubject)
		insertSession(t, queries, "sess-2", testSubject)
		insertSession(t, queries, "sess-3", "other-subject")

		require.NoError(t, locks.LockSubject(context.Background(), testSubject, testNow))

		_, err := queries.GetSession(context.Background(), "sess-1")
		require.ErrorIs(t, err, sql.ErrNoRows)
		_, err = queries.GetSession(context.Background(), "sess-2")
		require.ErrorIs(t, err, sql.ErrNoRows)

		// Sessions of other subjects survive the lock.
		record, err := queries.GetSession(context.Background(), "sess-3")
		require.NoError(t, err)
		require.Equal(t, "other-subject", record.Sub)
	})

	t.Run("is idempotent and keeps the original creation instant", func(t *testing.T) {
		locks, queries := newTestLocks(t)
		require.NoError(t, locks.LockSubject(context.Background(), testSubject, testNow))
		require.NoError(
			t,
			locks.LockSubject(context.Background(), testSubject, testNow.Add(time.Hour)),
		)

		record, err := queries.GetAdminLock(context.Background(), testSubject)
		require.NoError(t, err)
		require.Equal(t, clock.Format(testNow), record.CreatedAt)
	})

	t.Run("rejects an empty subject", func(t *testing.T) {
		locks, _ := newTestLocks(t)
		require.Error(t, locks.LockSubject(context.Background(), "", testNow))
	})
}

func TestUnlockSubject(t *testing.T) {
	t.Run("removes an existing administrative lock", func(t *testing.T) {
		locks, queries := newTestLocks(t)
		require.NoError(t, locks.LockSubject(context.Background(), testSubject, testNow))
		require.NoError(t, locks.UnlockSubject(context.Background(), testSubject))

		_, err := queries.GetAdminLock(context.Background(), testSubject)
		require.ErrorIs(t, err, sql.ErrNoRows)

		locked, err := locks.IsLocked(context.Background(), testSubject)
		require.NoError(t, err)
		require.False(t, locked)
	})

	t.Run("never clears a distinct panic lock", func(t *testing.T) {
		locks, queries := newTestLocks(t)
		createPanicLock(t, queries, testSubject)
		require.NoError(t, locks.LockSubject(context.Background(), testSubject, testNow))
		require.NoError(t, locks.UnlockSubject(context.Background(), testSubject))

		panicked, err := locks.IsPanicked(context.Background(), testSubject)
		require.NoError(t, err)
		require.True(t, panicked)
	})

	t.Run("succeeds for a subject without a lock", func(t *testing.T) {
		locks, _ := newTestLocks(t)
		require.NoError(t, locks.UnlockSubject(context.Background(), testSubject))
	})

	t.Run("rejects an empty subject", func(t *testing.T) {
		locks, _ := newTestLocks(t)
		require.Error(t, locks.UnlockSubject(context.Background(), ""))
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
		require.NoError(t, locks.LockSubject(context.Background(), testSubject, testNow))

		locked, err := locks.IsAdminLocked(context.Background(), testSubject)
		require.NoError(t, err)
		require.True(t, locked)
	})

	t.Run("reports false after clearing", func(t *testing.T) {
		locks, _ := newTestLocks(t)
		require.NoError(t, locks.LockSubject(context.Background(), testSubject, testNow))
		require.NoError(t, locks.UnlockSubject(context.Background(), testSubject))

		locked, err := locks.IsAdminLocked(context.Background(), testSubject)
		require.NoError(t, err)
		require.False(t, locked)
	})

	t.Run("ignores a panic lock", func(t *testing.T) {
		locks, queries := newTestLocks(t)
		createPanicLock(t, queries, testSubject)

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
