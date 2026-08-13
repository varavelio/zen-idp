package statestore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// WithTx runs fn inside one database transaction. The function receives the
// sqlc queries bound to the transaction, so every statement it issues
// commits or rolls back together. When fn returns nil the transaction is
// committed; otherwise it is rolled back and the error is returned
// unchanged. It is the primitive behind the atomic administrative and panic
// actions that must revoke sessions and create a lock in one step.
func WithTx(ctx context.Context, db *sql.DB, fn func(*Queries) error) error {
	if db == nil {
		return errors.New("state database is nil")
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin state transaction: %w", err)
	}

	if err := fn(New(tx)); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit state transaction: %w", err)
	}
	return nil
}
