package ratelimit

import (
	"context"
	"database/sql"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/varavelio/zen-idp/internal/clock"
	"github.com/varavelio/zen-idp/internal/statestore"
)

const (
	testKey         = "login:alice"
	testOtherKey    = "login:bob"
	testMaxAttempts = 3
	testWindow      = 5 * time.Minute
)

// testNow is the fixed instant used as the reference time in window tests.
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

// newTestLimiter returns a limiter backed by a migrated temporary SQLite
// database and its sqlc queries.
func newTestLimiter(
	t *testing.T,
	maxAttempts int,
	window time.Duration,
) (*Limiter, *statestore.Queries) {
	t.Helper()
	queries := statestore.New(newTestDB(t))
	limiter, err := New(queries, maxAttempts, window)
	require.NoError(t, err)
	return limiter, queries
}

func TestNew(t *testing.T) {
	t.Run("rejects nil queries", func(t *testing.T) {
		_, err := New(nil, testMaxAttempts, testWindow)
		require.Error(t, err)
	})

	t.Run("rejects non-positive max attempts", func(t *testing.T) {
		_, queries := newTestLimiter(t, testMaxAttempts, testWindow)
		_, err := New(queries, 0, testWindow)
		require.Error(t, err)
		_, err = New(queries, -1, testWindow)
		require.Error(t, err)
	})

	t.Run("rejects non-positive window", func(t *testing.T) {
		_, queries := newTestLimiter(t, testMaxAttempts, testWindow)
		_, err := New(queries, testMaxAttempts, 0)
		require.Error(t, err)
		_, err = New(queries, testMaxAttempts, -time.Second)
		require.Error(t, err)
	})

	t.Run("accepts valid parameters", func(t *testing.T) {
		_, queries := newTestLimiter(t, testMaxAttempts, testWindow)
		limiter, err := New(queries, testMaxAttempts, testWindow)
		require.NoError(t, err)
		require.NotNil(t, limiter)
	})
}

func TestAllow(t *testing.T) {
	t.Run("allows a key without a counter", func(t *testing.T) {
		limiter, _ := newTestLimiter(t, testMaxAttempts, testWindow)
		allowed, err := limiter.Allow(context.Background(), testKey, testNow)
		require.NoError(t, err)
		require.True(t, allowed)
	})

	t.Run("allows while failures are below the limit", func(t *testing.T) {
		limiter, _ := newTestLimiter(t, testMaxAttempts, testWindow)
		ctx := context.Background()
		for range testMaxAttempts - 1 {
			require.NoError(t, limiter.RecordFailure(ctx, testKey, testNow))
		}
		allowed, err := limiter.Allow(ctx, testKey, testNow)
		require.NoError(t, err)
		require.True(t, allowed)
	})

	t.Run("denies once failures reach the limit", func(t *testing.T) {
		limiter, _ := newTestLimiter(t, testMaxAttempts, testWindow)
		ctx := context.Background()
		for range testMaxAttempts {
			require.NoError(t, limiter.RecordFailure(ctx, testKey, testNow))
		}
		allowed, err := limiter.Allow(ctx, testKey, testNow)
		require.NoError(t, err)
		require.False(t, allowed)
	})

	t.Run("allows again after the window has ended", func(t *testing.T) {
		limiter, _ := newTestLimiter(t, testMaxAttempts, testWindow)
		ctx := context.Background()
		for range testMaxAttempts {
			require.NoError(t, limiter.RecordFailure(ctx, testKey, testNow))
		}
		require.False(t, mustAllow(t, limiter, ctx, testKey, testNow))

		afterWindow := testNow.Add(testWindow)
		allowed, err := limiter.Allow(ctx, testKey, afterWindow)
		require.NoError(t, err)
		require.True(t, allowed)
	})

	t.Run("keeps keys independent", func(t *testing.T) {
		limiter, _ := newTestLimiter(t, testMaxAttempts, testWindow)
		ctx := context.Background()
		for range testMaxAttempts {
			require.NoError(t, limiter.RecordFailure(ctx, testKey, testNow))
		}
		require.False(t, mustAllow(t, limiter, ctx, testKey, testNow))

		allowed, err := limiter.Allow(ctx, testOtherKey, testNow)
		require.NoError(t, err)
		require.True(t, allowed)
	})

	t.Run("rejects an empty key", func(t *testing.T) {
		limiter, _ := newTestLimiter(t, testMaxAttempts, testWindow)
		_, err := limiter.Allow(context.Background(), "", testNow)
		require.Error(t, err)
	})

	t.Run("rejects an oversized key", func(t *testing.T) {
		limiter, _ := newTestLimiter(t, testMaxAttempts, testWindow)
		_, err := limiter.Allow(context.Background(), string(make([]byte, maxKeyLength+1)), testNow)
		require.Error(t, err)
	})
}

func TestRecordFailure(t *testing.T) {
	t.Run("first failure opens a window", func(t *testing.T) {
		limiter, queries := newTestLimiter(t, testMaxAttempts, testWindow)
		require.NoError(t, limiter.RecordFailure(context.Background(), testKey, testNow))

		record, err := queries.GetRateLimitCounter(context.Background(), testKey)
		require.NoError(t, err)
		require.Equal(t, int64(1), record.Attempts)
		require.Equal(t, clock.Format(testNow.Add(testWindow)), record.ResetAt)
	})

	t.Run("failures accumulate within the window", func(t *testing.T) {
		limiter, queries := newTestLimiter(t, testMaxAttempts, testWindow)
		ctx := context.Background()
		for range testMaxAttempts {
			require.NoError(t, limiter.RecordFailure(ctx, testKey, testNow))
		}

		record, err := queries.GetRateLimitCounter(ctx, testKey)
		require.NoError(t, err)
		require.Equal(t, int64(testMaxAttempts), record.Attempts)
		require.Equal(t, clock.Format(testNow.Add(testWindow)), record.ResetAt)
	})

	t.Run("expired window restarts the counter", func(t *testing.T) {
		limiter, queries := newTestLimiter(t, testMaxAttempts, testWindow)
		ctx := context.Background()
		for range testMaxAttempts {
			require.NoError(t, limiter.RecordFailure(ctx, testKey, testNow))
		}

		afterWindow := testNow.Add(testWindow)
		require.NoError(t, limiter.RecordFailure(ctx, testKey, afterWindow))

		record, err := queries.GetRateLimitCounter(ctx, testKey)
		require.NoError(t, err)
		require.Equal(t, int64(1), record.Attempts)
		require.Equal(t, clock.Format(afterWindow.Add(testWindow)), record.ResetAt)
	})

	t.Run("rejects an empty key", func(t *testing.T) {
		limiter, _ := newTestLimiter(t, testMaxAttempts, testWindow)
		require.Error(t, limiter.RecordFailure(context.Background(), "", testNow))
	})

	t.Run("rejects an oversized key", func(t *testing.T) {
		limiter, _ := newTestLimiter(t, testMaxAttempts, testWindow)
		key := string(make([]byte, maxKeyLength+1))
		require.Error(t, limiter.RecordFailure(context.Background(), key, testNow))
	})
}

func TestReset(t *testing.T) {
	t.Run("removes the counter", func(t *testing.T) {
		limiter, queries := newTestLimiter(t, testMaxAttempts, testWindow)
		ctx := context.Background()
		for range testMaxAttempts {
			require.NoError(t, limiter.RecordFailure(ctx, testKey, testNow))
		}
		require.False(t, mustAllow(t, limiter, ctx, testKey, testNow))

		require.NoError(t, limiter.Reset(ctx, testKey))

		allowed, err := limiter.Allow(ctx, testKey, testNow)
		require.NoError(t, err)
		require.True(t, allowed)
		_, err = queries.GetRateLimitCounter(ctx, testKey)
		require.ErrorIs(t, err, sql.ErrNoRows)
	})

	t.Run("resetting an absent key is not an error", func(t *testing.T) {
		limiter, _ := newTestLimiter(t, testMaxAttempts, testWindow)
		require.NoError(t, limiter.Reset(context.Background(), testKey))
	})

	t.Run("rejects an empty key", func(t *testing.T) {
		limiter, _ := newTestLimiter(t, testMaxAttempts, testWindow)
		require.Error(t, limiter.Reset(context.Background(), ""))
	})
}

func TestPurgeExpired(t *testing.T) {
	t.Run("deletes only expired counters", func(t *testing.T) {
		limiter, _ := newTestLimiter(t, testMaxAttempts, testWindow)
		ctx := context.Background()
		// liveKey fails inside the current window; staleKey failed two
		// windows ago, so its counter is no longer relevant.
		for range testMaxAttempts {
			require.NoError(t, limiter.RecordFailure(ctx, testKey, testNow))
		}
		require.NoError(t, limiter.RecordFailure(ctx, testOtherKey, testNow.Add(-2*testWindow)))

		deleted, err := limiter.PurgeExpired(ctx, testNow)
		require.NoError(t, err)
		require.Equal(t, int64(1), deleted)

		require.False(t, mustAllow(t, limiter, ctx, testKey, testNow))
		allowed, err := limiter.Allow(ctx, testOtherKey, testNow)
		require.NoError(t, err)
		require.True(t, allowed)
	})

	t.Run("returns zero when nothing is expired", func(t *testing.T) {
		limiter, _ := newTestLimiter(t, testMaxAttempts, testWindow)
		ctx := context.Background()
		require.NoError(t, limiter.RecordFailure(ctx, testKey, testNow))

		deleted, err := limiter.PurgeExpired(ctx, testNow)
		require.NoError(t, err)
		require.Zero(t, deleted)
	})
}

// TestConcurrentRecordFailure guards the atomicity of the counter upsert:
// concurrent failures must each be counted exactly once.
func TestConcurrentRecordFailure(t *testing.T) {
	const attempts = 40
	limiter, queries := newTestLimiter(t, attempts, testWindow)
	ctx := context.Background()

	var wait sync.WaitGroup
	for range attempts {
		wait.Go(func() {
			require.NoError(t, limiter.RecordFailure(ctx, testKey, testNow))
		})
	}
	wait.Wait()

	record, err := queries.GetRateLimitCounter(ctx, testKey)
	require.NoError(t, err)
	require.Equal(t, int64(attempts), record.Attempts)
}

// mustAllow asserts that Allow permits the key and returns the result.
func mustAllow(
	t *testing.T,
	limiter *Limiter,
	ctx context.Context,
	key string,
	now time.Time,
) bool {
	t.Helper()
	allowed, err := limiter.Allow(ctx, key, now)
	require.NoError(t, err)
	return allowed
}
