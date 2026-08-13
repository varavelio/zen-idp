package lock

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/varavelio/zen-idp/internal/clock"
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

func TestPanicSubject(t *testing.T) {
	t.Run("creates the panic lock recording the given instant", func(t *testing.T) {
		locks, queries := newTestLocks(t)
		require.NoError(t, locks.PanicSubject(context.Background(), testSubject, testNow))

		record, err := queries.GetPanicLock(context.Background(), testSubject)
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

		require.NoError(t, locks.PanicSubject(context.Background(), testSubject, testNow))

		_, err := queries.GetSession(context.Background(), "sess-1")
		require.ErrorIs(t, err, sql.ErrNoRows)
		_, err = queries.GetSession(context.Background(), "sess-2")
		require.ErrorIs(t, err, sql.ErrNoRows)

		// Sessions of other subjects survive the panic action.
		record, err := queries.GetSession(context.Background(), "sess-3")
		require.NoError(t, err)
		require.Equal(t, "other-subject", record.Sub)
	})

	t.Run("is idempotent and keeps the original creation instant", func(t *testing.T) {
		locks, queries := newTestLocks(t)
		require.NoError(t, locks.PanicSubject(context.Background(), testSubject, testNow))
		require.NoError(
			t,
			locks.PanicSubject(context.Background(), testSubject, testNow.Add(time.Hour)),
		)

		record, err := queries.GetPanicLock(context.Background(), testSubject)
		require.NoError(t, err)
		require.Equal(t, clock.Format(testNow), record.CreatedAt)
	})

	t.Run("rejects an empty subject", func(t *testing.T) {
		locks, _ := newTestLocks(t)
		require.Error(t, locks.PanicSubject(context.Background(), "", testNow))
	})
}
