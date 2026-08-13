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

// LockSubject administratively locks sub and, in the same database
// transaction, revokes every active session of the subject, so the lock
// blocks login and SSO use immediately. Creating an existing lock is not an
// error and keeps the original creation instant; the session revocation
// then simply finds nothing left to delete.
func (locks *Locks) LockSubject(ctx context.Context, sub string, now time.Time) error {
	if err := validateSub(sub); err != nil {
		return err
	}
	err := locks.runTx.WithTx(ctx, func(queries *statestore.Queries) error {
		if err := queries.CreateAdminLock(ctx, statestore.CreateAdminLockParams{
			Sub:       sub,
			CreatedAt: clock.Format(now),
		}); err != nil {
			return fmt.Errorf("create admin lock: %w", err)
		}
		if err := queries.RevokeSessionsBySubject(ctx, sub); err != nil {
			return fmt.Errorf("revoke sessions for subject: %w", err)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("lock subject: %w", err)
	}
	return nil
}

// UnlockSubject removes the administrative lock for sub. It never clears a
// distinct panic lock, and removing an absent lock is not an error, so
// administrative recovery always succeeds.
func (locks *Locks) UnlockSubject(ctx context.Context, sub string) error {
	if err := validateSub(sub); err != nil {
		return err
	}
	if err := locks.queries.ClearAdminLock(ctx, sub); err != nil {
		return fmt.Errorf("clear admin lock: %w", err)
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
