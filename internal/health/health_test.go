package health

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/varavelio/zen-idp/internal/statestore"
)

// stubPinger is a pinger whose verdict and call count are controlled by
// the test.
type stubPinger struct {
	healthy bool
	calls   atomic.Int64
}

func (p *stubPinger) PingContext(context.Context) error {
	p.calls.Add(1)
	if !p.healthy {
		return errors.New("database unavailable")
	}
	return nil
}

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

func TestOK(t *testing.T) {
	t.Run("reports the verdict of the first probe", func(t *testing.T) {
		pinger := &stubPinger{healthy: true}
		checker := New(pinger, time.Minute)
		require.True(t, checker.OK(context.Background()))
		require.Equal(t, int64(1), pinger.calls.Load())
	})

	t.Run("caches the verdict within the interval", func(t *testing.T) {
		pinger := &stubPinger{healthy: true}
		checker := New(pinger, time.Minute)
		require.True(t, checker.OK(context.Background()))
		require.True(t, checker.OK(context.Background()))
		require.Equal(t, int64(1), pinger.calls.Load())
	})

	t.Run("serves the cached failure until the interval elapses", func(t *testing.T) {
		pinger := &stubPinger{healthy: false}
		checker := New(pinger, 20*time.Millisecond)
		require.False(t, checker.OK(context.Background()))
		pinger.healthy = true
		// The cached failure still serves within the interval.
		require.False(t, checker.OK(context.Background()))
		require.Equal(t, int64(1), pinger.calls.Load())
		// After the interval the probe runs again and recovers.
		time.Sleep(50 * time.Millisecond)
		require.True(t, checker.OK(context.Background()))
		require.Equal(t, int64(2), pinger.calls.Load())
	})

	t.Run("probes a real state database", func(t *testing.T) {
		db := newTestDB(t)
		checker := New(db, time.Minute)
		require.True(t, checker.OK(context.Background()))
		require.NoError(t, db.Close())
		require.False(t, New(db, time.Minute).OK(context.Background()))
	})
}
