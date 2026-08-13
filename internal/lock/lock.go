package lock

import (
	"context"
	"errors"

	"github.com/varavelio/zen-idp/internal/statestore"
)

// lockQueries is the SQLite-backed lock persistence the manager needs,
// satisfied by statestore.Queries. It is defined consumer-side so the
// manager never depends on a concrete persistence implementation.
type lockQueries interface {
	CreateAdminLock(context.Context, statestore.CreateAdminLockParams) error
	GetAdminLock(context.Context, string) (statestore.AdminLock, error)
	ClearAdminLock(context.Context, string) error
	GetPanicLock(context.Context, string) (statestore.PanicLock, error)
	ClearPanicLock(context.Context, string) error
}

// txRunner executes a function inside one database transaction, receiving
// the sqlc queries bound to that transaction so every statement commits or
// rolls back together. It is satisfied by the state store transaction
// runner wired at startup.
type txRunner interface {
	WithTx(context.Context, func(*statestore.Queries) error) error
}

// Locks manages the disposable panic and administrative locks that gate a
// subject's login and SSO use, and the atomic lock actions that revoke the
// subject's sessions together with the lock creation.
type Locks struct {
	queries lockQueries
	runTx   txRunner
}

// NewLocks returns a manager that persists both lock kinds through queries
// and executes atomic actions through runTx.
func NewLocks(queries lockQueries, runTx txRunner) (*Locks, error) {
	if queries == nil {
		return nil, errors.New("lock queries are nil")
	}
	if runTx == nil {
		return nil, errors.New("lock transaction runner is nil")
	}
	return &Locks{queries: queries, runTx: runTx}, nil
}

// IsLocked reports whether any lock, panic or administrative, is present for
// sub. It is the combined gate that login and session validation apply
// before granting access.
func (locks *Locks) IsLocked(ctx context.Context, sub string) (bool, error) {
	panicked, err := locks.IsPanicked(ctx, sub)
	if err != nil {
		return false, err
	}
	if panicked {
		return true, nil
	}
	return locks.IsAdminLocked(ctx, sub)
}

// validateSub rejects empty subjects so no lock row is ever created or
// inspected under a blank key.
func validateSub(sub string) error {
	if sub == "" {
		return errors.New("lock subject must not be empty")
	}
	return nil
}
