package statestore

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"

	"github.com/pressly/goose/v3"
)

// migrationsFS contains every SQL migration compiled into the application
// binary.
//
//go:embed all:migrations
var migrationsFS embed.FS

// Migrate applies every pending migration embedded in the binary to db. A
// binary with no migrations yet leaves the database untouched.
func Migrate(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return errors.New("state database connection is nil")
	}

	migrations, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("load embedded migrations: %w", err)
	}

	provider, err := goose.NewProvider(goose.DialectSQLite3, db, migrations)
	if errors.Is(err, goose.ErrNoMigrations) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("create migration provider: %w", err)
	}
	// Do not call provider.Close: goose closes the caller-owned *sql.DB there.

	if _, err := provider.Up(ctx); err != nil {
		return fmt.Errorf("run state database migrations: %w", err)
	}
	return nil
}
