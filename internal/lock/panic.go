package lock

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/varavelio/zen-idp/internal/clock"
	"github.com/varavelio/zen-idp/internal/statestore"
)

// LockPanic creates the panic lock for sub at the given instant, recording
// it as the time the emergency action was taken. Creating an existing lock
// is not an error and keeps the original creation instant, so repeated
// actions cannot extend the lock.
func (locks *Locks) LockPanic(ctx context.Context, sub string, now time.Time) error {
	if err := validateSub(sub); err != nil {
		return err
	}
	err := locks.queries.CreatePanicLock(ctx, statestore.CreatePanicLockParams{
		Sub:       sub,
		CreatedAt: clock.Format(now),
	})
	if err != nil {
		return fmt.Errorf("create panic lock: %w", err)
	}
	return nil
}

// IsPanicked reports whether a panic lock is present for sub.
func (locks *Locks) IsPanicked(ctx context.Context, sub string) (bool, error) {
	if err := validateSub(sub); err != nil {
		return false, err
	}
	_, err := locks.queries.GetPanicLock(ctx, sub)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("get panic lock: %w", err)
	}
	return true, nil
}

// ClearPanic removes the panic lock for sub, re-enabling login for the
// subject unless another gate still applies. Removing an absent lock is not
// an error, so administrative recovery always succeeds.
func (locks *Locks) ClearPanic(ctx context.Context, sub string) error {
	if err := validateSub(sub); err != nil {
		return err
	}
	if err := locks.queries.ClearPanicLock(ctx, sub); err != nil {
		return fmt.Errorf("clear panic lock: %w", err)
	}
	return nil
}
