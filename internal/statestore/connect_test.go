package statestore

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConnect(t *testing.T) {
	t.Run("opens a usable database with the required pragmas", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "state.db")
		db, err := Connect(context.Background(), path)
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, db.Close()) })

		requirePragma(t, db, "PRAGMA journal_mode", "wal")
		requirePragma(t, db, "PRAGMA foreign_keys", "1")
		requirePragma(t, db, "PRAGMA busy_timeout", "5000")

		_, err = db.ExecContext(
			context.Background(),
			"CREATE TABLE probe (id INTEGER PRIMARY KEY, value TEXT NOT NULL)",
		)
		require.NoError(t, err)
		_, err = db.ExecContext(
			context.Background(),
			"INSERT INTO probe (value) VALUES (?)",
			"hello",
		)
		require.NoError(t, err)
		var value string
		require.NoError(
			t,
			db.QueryRowContext(context.Background(), "SELECT value FROM probe WHERE id = 1").
				Scan(&value),
		)
		require.Equal(t, "hello", value)
	})

	t.Run("rejects an empty path", func(t *testing.T) {
		db, err := Connect(context.Background(), "   ")
		require.Nil(t, db)
		require.EqualError(t, err, "state database path must not be empty")
	})

	t.Run("fails when the path cannot be opened", func(t *testing.T) {
		// A directory is not an openable SQLite database.
		path := t.TempDir()
		db, err := Connect(context.Background(), path)
		require.Nil(t, db)
		require.Error(t, err)
	})
}

func requirePragma(t *testing.T, db *sql.DB, pragma, want string) {
	t.Helper()
	var got string
	require.NoError(t, db.QueryRowContext(context.Background(), pragma).Scan(&got))
	require.Equal(t, want, got)
}

func connectTestDB(t *testing.T) *sql.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := Connect(context.Background(), path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	return db
}
