package ratelimit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/varavelio/zen-idp/internal/clock"
	"github.com/varavelio/zen-idp/internal/statestore"
)

// maxKeyLength bounds caller-chosen keys so the counter table cannot be
// bloated by unbounded identifiers. It comfortably fits any realistic sub,
// login identifier, or prefixed key.
const maxKeyLength = 256

// rateLimitQueries is the SQLite-backed counter persistence the limiter
// needs, satisfied by statestore.Queries. It is defined consumer-side so the
// limiter never depends on a concrete persistence implementation.
type rateLimitQueries interface {
	GetRateLimitCounter(context.Context, string) (statestore.RateLimitCounter, error)
	RecordRateLimitAttempt(context.Context, statestore.RecordRateLimitAttemptParams) error
	DeleteRateLimitCounter(context.Context, string) error
	DeleteExpiredRateLimitCounters(context.Context, string) (int64, error)
}

// Limiter enforces a maximum number of failed attempts per key within a
// fixed window. A key's window starts at its first recorded failure and
// ends maxAttempts-window later; once maxAttempts failures are recorded
// inside one window, the key is denied until the window ends.
type Limiter struct {
	queries     rateLimitQueries
	maxAttempts int
	window      time.Duration
}

// New returns a limiter that persists counters through queries, denies a key
// once maxAttempts failures are recorded within one window, and restarts
// windows every window duration.
func New(queries rateLimitQueries, maxAttempts int, window time.Duration) (*Limiter, error) {
	if queries == nil {
		return nil, errors.New("rate limit queries are nil")
	}
	if maxAttempts <= 0 {
		return nil, errors.New("max attempts must be positive")
	}
	if window <= 0 {
		return nil, errors.New("rate limit window must be positive")
	}
	return &Limiter{
		queries:     queries,
		maxAttempts: maxAttempts,
		window:      window,
	}, nil
}

// Allow reports whether an attempt for key is permitted at the given
// instant. It only inspects the stored counter and never records anything,
// so it must be paired with RecordFailure to consume the attempt budget.
// An absent counter, an expired window, or a counter below maxAttempts
// failures all allow the attempt.
func (limiter *Limiter) Allow(ctx context.Context, key string, now time.Time) (bool, error) {
	if err := validateKey(key); err != nil {
		return false, err
	}

	record, err := limiter.queries.GetRateLimitCounter(ctx, key)
	if errors.Is(err, sql.ErrNoRows) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("get rate limit counter: %w", err)
	}

	resetAt, err := clock.Parse(record.ResetAt)
	if err != nil {
		return false, fmt.Errorf("parse rate limit reset: %w", err)
	}
	if !now.Before(resetAt) {
		// The window has ended; the stale counter no longer limits.
		return true, nil
	}
	return record.Attempts < int64(limiter.maxAttempts), nil
}

// RecordFailure counts one failed attempt for key at the given instant. The
// count is applied atomically: the first failure opens a window that ends
// window later, later failures increment the count, and a failure arriving
// after the window has ended restarts the counter at one.
func (limiter *Limiter) RecordFailure(ctx context.Context, key string, now time.Time) error {
	if err := validateKey(key); err != nil {
		return err
	}

	err := limiter.queries.RecordRateLimitAttempt(ctx, statestore.RecordRateLimitAttemptParams{
		Key:       key,
		ResetAt:   clock.Format(now.Add(limiter.window)),
		UpdatedAt: clock.Format(now),
	})
	if err != nil {
		return fmt.Errorf("record rate limit attempt: %w", err)
	}
	return nil
}

// Reset removes any counter for key, typically after a successful outcome
// such as a successful login. It is not an error to reset a key without a
// counter.
func (limiter *Limiter) Reset(ctx context.Context, key string) error {
	if err := validateKey(key); err != nil {
		return err
	}
	if err := limiter.queries.DeleteRateLimitCounter(ctx, key); err != nil {
		return fmt.Errorf("reset rate limit counter: %w", err)
	}
	return nil
}

// PurgeExpired deletes every counter whose window ended before the given
// instant and returns the number of counters removed. It keeps the counter
// table bounded by reclaiming keys that no longer limit anyone.
func (limiter *Limiter) PurgeExpired(ctx context.Context, now time.Time) (int64, error) {
	deleted, err := limiter.queries.DeleteExpiredRateLimitCounters(ctx, clock.Format(now))
	if err != nil {
		return 0, fmt.Errorf("purge expired rate limit counters: %w", err)
	}
	return deleted, nil
}

// validateKey rejects empty and oversized keys.
func validateKey(key string) error {
	if key == "" {
		return errors.New("rate limit key must not be empty")
	}
	if len(key) > maxKeyLength {
		return fmt.Errorf("rate limit key exceeds %d bytes", maxKeyLength)
	}
	return nil
}
