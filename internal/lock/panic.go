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

// PanicSubject invokes the user panic action for sub and, in the same
// database transaction, revokes every active session of the subject, so the
// panic lock blocks login and SSO use immediately. Creating an existing lock
// is not an error and keeps the original creation instant; the session
// revocation then simply finds nothing left to delete.
func (locks *Locks) PanicSubject(ctx context.Context, sub string, now time.Time) error {
	if err := validateSub(sub); err != nil {
		return err
	}
	err := locks.runTx.WithTx(ctx, func(queries *statestore.Queries) error {
		if err := queries.CreatePanicLock(ctx, statestore.CreatePanicLockParams{
			Sub:       sub,
			CreatedAt: clock.Format(now),
		}); err != nil {
			return fmt.Errorf("create panic lock: %w", err)
		}
		if err := queries.RevokeSessionsBySubject(ctx, sub); err != nil {
			return fmt.Errorf("revoke sessions for subject: %w", err)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("panic subject: %w", err)
	}
	return nil
}
