package statestore

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// withTxTestDB opens and migrates a temporary SQLite database for the
// transaction tests.
func withTxTestDB(t *testing.T) *sql.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := Connect(context.Background(), path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	require.NoError(t, Migrate(context.Background(), db))
	return db
}

func TestWithTx(t *testing.T) {
	t.Run("commits the statements of a successful function", func(t *testing.T) {
		db := withTxTestDB(t)

		err := WithTx(context.Background(), db, func(queries *Queries) error {
			return queries.CreateSession(context.Background(), CreateSessionParams{
				ID:         "committed",
				Kind:       "user",
				SecretHash: []byte("hash"),
				Sub:        "alice",
				TotpRev:    0,
				CreatedAt:  "2026-01-02T03:04:05Z",
				ExpiresAt:  "2026-01-03T03:04:05Z",
			})
		})
		require.NoError(t, err)

		// The row is visible to a fresh query outside the transaction.
		record, err := New(db).GetSession(context.Background(), "committed")
		require.NoError(t, err)
		require.Equal(t, "alice", record.Sub)
	})

	t.Run("rolls back the statements of a failing function", func(t *testing.T) {
		db := withTxTestDB(t)

		boom := errors.New("boom")
		err := WithTx(context.Background(), db, func(queries *Queries) error {
			require.NoError(t, queries.CreateSession(context.Background(), CreateSessionParams{
				ID:         "rolled-back",
				Kind:       "user",
				SecretHash: []byte("hash"),
				Sub:        "alice",
				TotpRev:    0,
				CreatedAt:  "2026-01-02T03:04:05Z",
				ExpiresAt:  "2026-01-03T03:04:05Z",
			}))
			return boom
		})

		require.ErrorIs(t, err, boom)

		// The row written before the failure is gone.
		_, err = New(db).GetSession(context.Background(), "rolled-back")
		require.ErrorIs(t, err, sql.ErrNoRows)
	})

	t.Run("rejects a nil database", func(t *testing.T) {
		err := WithTx(context.Background(), nil, func(*Queries) error { return nil })
		require.Error(t, err)
	})
}
