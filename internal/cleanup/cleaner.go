package cleanup

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// rateLimitPurger removes expired rate-limit counters, satisfied by
// ratelimit.Limiter. All rate limiters share one counter table, so any
// limiter can purge the whole table.
type rateLimitPurger interface {
	PurgeExpired(context.Context, time.Time) (int64, error)
}

// tokenPurger removes expired one-use tokens, satisfied by onetoken.Store.
type tokenPurger interface {
	PurgeExpired(context.Context, time.Time) (int64, error)
}

// sessionPurger removes expired sessions, satisfied by session.Store.
type sessionPurger interface {
	PurgeExpired(context.Context, time.Time) (int64, error)
}

// auditPurger removes audit records older than the retention, satisfied by
// audit.Recorder.
type auditPurger interface {
	PurgeExpired(context.Context, time.Time) (int64, error)
}

// Cleaner runs periodic cleanup passes over the disposable state database.
type Cleaner struct {
	rateLimits     rateLimitPurger
	tokens         tokenPurger
	sessions       sessionPurger
	audits         auditPurger
	auditRetention time.Duration
}

// New returns a cleaner that purges expired state through the given domain
// purgers. auditRetention bounds how long audit records are kept; a zero
// value keeps audit records indefinitely and disables the audit purge.
func New(
	rateLimits rateLimitPurger,
	tokens tokenPurger,
	sessions sessionPurger,
	audits auditPurger,
	auditRetention time.Duration,
) (*Cleaner, error) {
	if rateLimits == nil {
		return nil, errors.New("cleanup rate limit purger is nil")
	}
	if tokens == nil {
		return nil, errors.New("cleanup token purger is nil")
	}
	if sessions == nil {
		return nil, errors.New("cleanup session purger is nil")
	}
	if audits == nil {
		return nil, errors.New("cleanup audit purger is nil")
	}
	if auditRetention < 0 {
		return nil, errors.New("cleanup audit retention must not be negative")
	}
	return &Cleaner{
		rateLimits:     rateLimits,
		tokens:         tokens,
		sessions:       sessions,
		audits:         audits,
		auditRetention: auditRetention,
	}, nil
}

// Clean runs one full cleanup pass at the given instant: expired rate-limit
// counters, expired one-use tokens, expired sessions, and audit records
// older than the configured retention are removed, in that order. Locks are
// never touched. The returned error is wrapped with the failing purge, and
// the removed counts are logged when the pass succeeds.
func (cleaner *Cleaner) Clean(ctx context.Context, now time.Time) error {
	rateLimitCount, err := cleaner.rateLimits.PurgeExpired(ctx, now)
	if err != nil {
		return fmt.Errorf("purge expired rate limit counters: %w", err)
	}
	tokenCount, err := cleaner.tokens.PurgeExpired(ctx, now)
	if err != nil {
		return fmt.Errorf("purge expired one-use tokens: %w", err)
	}
	sessionCount, err := cleaner.sessions.PurgeExpired(ctx, now)
	if err != nil {
		return fmt.Errorf("purge expired sessions: %w", err)
	}

	auditCount := int64(0)
	if cleaner.auditRetention > 0 {
		auditCount, err = cleaner.audits.PurgeExpired(
			ctx,
			now.Add(-cleaner.auditRetention),
		)
		if err != nil {
			return fmt.Errorf("purge expired audit records: %w", err)
		}
	}

	slog.InfoContext(
		ctx, "state cleanup completed",
		slog.Int64("rate_limit_counters", rateLimitCount),
		slog.Int64("one_use_tokens", tokenCount),
		slog.Int64("sessions", sessionCount),
		slog.Int64("audit_records", auditCount),
	)
	return nil
}
