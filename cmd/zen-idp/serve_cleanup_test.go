package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/varavelio/zen-idp/internal/cleanup"
)

func TestRunCleanupLoop(t *testing.T) {
	t.Run("runs one pass immediately and then every interval until canceled", func(t *testing.T) {
		previous := slog.Default()
		slog.SetDefault(slog.New(slog.DiscardHandler))
		defer slog.SetDefault(previous)

		rateLimits := &countingPurger{}
		cleaner, err := cleanup.New(
			rateLimits,
			&countingPurger{},
			&countingPurger{},
			&countingPurger{},
			time.Hour,
		)
		require.NoError(t, err)

		ctx, cancel := context.WithCancel(context.Background())
		loopDone := make(chan struct{})
		go func() {
			runCleanupLoop(ctx, cleaner, 20*time.Millisecond)
			close(loopDone)
		}()

		// The immediate pass plus at least two ticker passes.
		require.Eventually(t, func() bool {
			return rateLimits.calls.Load() >= 3
		}, 2*time.Second, 10*time.Millisecond)

		cancel()
		select {
		case <-loopDone:
		case <-time.After(2 * time.Second):
			t.Fatal("cleanup loop kept running after cancellation")
		}
	})

	t.Run("logs failed passes without stopping the loop", func(t *testing.T) {
		var logBuffer bytes.Buffer
		previous := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&logBuffer, nil)))
		defer slog.SetDefault(previous)

		rateLimits := &flakyPurger{}
		cleaner, err := cleanup.New(
			rateLimits,
			&countingPurger{},
			&countingPurger{},
			&countingPurger{},
			time.Hour,
		)
		require.NoError(t, err)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		loopDone := make(chan struct{})
		go func() {
			runCleanupLoop(ctx, cleaner, 20*time.Millisecond)
			close(loopDone)
		}()

		// The purger fails its first two passes; the loop must survive
		// them and keep running passes.
		require.Eventually(t, func() bool {
			return rateLimits.calls.Load() >= 4
		}, 2*time.Second, 10*time.Millisecond)

		cancel()
		select {
		case <-loopDone:
		case <-time.After(2 * time.Second):
			t.Fatal("cleanup loop kept running after cancellation")
		}
		// The loop is stopped, so the log buffer is no longer written to.
		require.Contains(t, logBuffer.String(), "state cleanup failed")
	})
}

// countingPurger counts purge calls and never fails.
type countingPurger struct {
	calls atomic.Int64
}

// PurgeExpired counts the call and reports zero removed records.
func (purger *countingPurger) PurgeExpired(context.Context, time.Time) (int64, error) {
	purger.calls.Add(1)
	return 0, nil
}

// flakyPurger counts purge calls and fails the first two of them.
type flakyPurger struct {
	calls atomic.Int64
}

// PurgeExpired fails the first two calls and then succeeds.
func (purger *flakyPurger) PurgeExpired(context.Context, time.Time) (int64, error) {
	purger.calls.Add(1)
	if purger.calls.Load() <= 2 {
		return 0, errors.New("boom")
	}
	return 0, nil
}
