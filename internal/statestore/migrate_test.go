package statestore

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMigrate(t *testing.T) {
	t.Run("succeeds on a fresh database with no migrations", func(t *testing.T) {
		db := connectTestDB(t)
		require.NoError(t, Migrate(context.Background(), db))

		// The database remains fully usable after a no-op migration run.
		_, err := db.ExecContext(
			context.Background(),
			"CREATE TABLE probe (id INTEGER PRIMARY KEY, value TEXT NOT NULL)",
		)
		require.NoError(t, err)
	})

	t.Run("is idempotent across repeated runs", func(t *testing.T) {
		db := connectTestDB(t)
		require.NoError(t, Migrate(context.Background(), db))
		require.NoError(t, Migrate(context.Background(), db))
	})

	t.Run("rejects a nil connection", func(t *testing.T) {
		err := Migrate(context.Background(), nil)
		require.EqualError(t, err, "state database connection is nil")
	})
}
