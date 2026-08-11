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

// LockAdmin creates the administrative lock for sub at the given instant,
// recording it as the time the action was taken. Creating an existing lock
// is not an error and keeps the original creation instant.
func (locks *Locks) LockAdmin(ctx context.Context, sub string, now time.Time) error {
	if err := validateSub(sub); err != nil {
		return err
	}
	err := locks.queries.CreateAdminLock(ctx, statestore.CreateAdminLockParams{
		Sub:       sub,
		CreatedAt: clock.Format(now),
	})
	if err != nil {
		return fmt.Errorf("create admin lock: %w", err)
	}
	return nil
}

// IsAdminLocked reports whether an administrative lock is present for sub.
func (locks *Locks) IsAdminLocked(ctx context.Context, sub string) (bool, error) {
	if err := validateSub(sub); err != nil {
		return false, err
	}
	_, err := locks.queries.GetAdminLock(ctx, sub)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("get admin lock: %w", err)
	}
	return true, nil
}

// ClearAdmin removes the administrative lock for sub. It never clears a
// distinct panic lock. Removing an absent lock is not an error, so
// administrative recovery always succeeds.
func (locks *Locks) ClearAdmin(ctx context.Context, sub string) error {
	if err := validateSub(sub); err != nil {
		return err
	}
	if err := locks.queries.ClearAdminLock(ctx, sub); err != nil {
		return fmt.Errorf("clear admin lock: %w", err)
	}
	return nil
}
