package lock

import (
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsPanicked(t *testing.T) {
	t.Run("reports false for a subject without a lock", func(t *testing.T) {
		locks, _ := newTestLocks(t)
		panicked, err := locks.IsPanicked(context.Background(), testSubject)
		require.NoError(t, err)
		require.False(t, panicked)
	})

	t.Run("reports true when the panic lock exists", func(t *testing.T) {
		locks, queries := newTestLocks(t)
		createPanicLock(t, queries, testSubject)

		panicked, err := locks.IsPanicked(context.Background(), testSubject)
		require.NoError(t, err)
		require.True(t, panicked)
	})

	t.Run("reports false after clearing", func(t *testing.T) {
		locks, queries := newTestLocks(t)
		createPanicLock(t, queries, testSubject)
		require.NoError(t, locks.ClearPanic(context.Background(), testSubject))

		panicked, err := locks.IsPanicked(context.Background(), testSubject)
		require.NoError(t, err)
		require.False(t, panicked)
	})

	t.Run("ignores an administrative lock", func(t *testing.T) {
		locks, queries := newTestLocks(t)
		createAdminLock(t, queries, testSubject)

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
		createPanicLock(t, queries, testSubject)
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
