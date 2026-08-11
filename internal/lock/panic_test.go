package lock

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/varavelio/zen-idp/internal/clock"
)

func TestLockPanic(t *testing.T) {
	t.Run("creates a lock recording the given instant", func(t *testing.T) {
		locks, queries := newTestLocks(t)
		require.NoError(t, locks.LockPanic(context.Background(), testSubject, testNow))

		record, err := queries.GetPanicLock(context.Background(), testSubject)
		require.NoError(t, err)
		require.Equal(t, clock.Format(testNow), record.CreatedAt)
	})

	t.Run("is idempotent and keeps the original creation instant", func(t *testing.T) {
		locks, queries := newTestLocks(t)
		require.NoError(t, locks.LockPanic(context.Background(), testSubject, testNow))
		require.NoError(
			t,
			locks.LockPanic(context.Background(), testSubject, testNow.Add(time.Hour)),
		)

		record, err := queries.GetPanicLock(context.Background(), testSubject)
		require.NoError(t, err)
		require.Equal(t, clock.Format(testNow), record.CreatedAt)
	})

	t.Run("rejects an empty subject", func(t *testing.T) {
		locks, _ := newTestLocks(t)
		require.Error(t, locks.LockPanic(context.Background(), "", testNow))
	})
}

func TestIsPanicked(t *testing.T) {
	t.Run("reports false for a subject without a lock", func(t *testing.T) {
		locks, _ := newTestLocks(t)
		panicked, err := locks.IsPanicked(context.Background(), testSubject)
		require.NoError(t, err)
		require.False(t, panicked)
	})

	t.Run("reports true after locking", func(t *testing.T) {
		locks, _ := newTestLocks(t)
		require.NoError(t, locks.LockPanic(context.Background(), testSubject, testNow))

		panicked, err := locks.IsPanicked(context.Background(), testSubject)
		require.NoError(t, err)
		require.True(t, panicked)
	})

	t.Run("reports false after clearing", func(t *testing.T) {
		locks, _ := newTestLocks(t)
		require.NoError(t, locks.LockPanic(context.Background(), testSubject, testNow))
		require.NoError(t, locks.ClearPanic(context.Background(), testSubject))

		panicked, err := locks.IsPanicked(context.Background(), testSubject)
		require.NoError(t, err)
		require.False(t, panicked)
	})

	t.Run("ignores an administrative lock", func(t *testing.T) {
		locks, _ := newTestLocks(t)
		require.NoError(t, locks.LockAdmin(context.Background(), testSubject, testNow))

		panicked, err := locks.IsPanicked(context.Background(), testSubject)
		require.NoError(t, err)
		require.False(t, panicked)
	})

	t.Run("rejects an empty subject", func(t *testing.T) {
		locks, _ := newTestLocks(t)
		_, err := locks.IsPanicked(context.Background(), "")
		require.Error(t, err)
	})
}

func TestClearPanic(t *testing.T) {
	t.Run("removes an existing lock", func(t *testing.T) {
		locks, queries := newTestLocks(t)
		require.NoError(t, locks.LockPanic(context.Background(), testSubject, testNow))
		require.NoError(t, locks.ClearPanic(context.Background(), testSubject))

		_, err := queries.GetPanicLock(context.Background(), testSubject)
		require.ErrorIs(t, err, sql.ErrNoRows)
	})

	t.Run("succeeds for a subject without a lock", func(t *testing.T) {
		locks, _ := newTestLocks(t)
		require.NoError(t, locks.ClearPanic(context.Background(), testSubject))
	})

	t.Run("rejects an empty subject", func(t *testing.T) {
		locks, _ := newTestLocks(t)
		require.Error(t, locks.ClearPanic(context.Background(), ""))
	})
}
