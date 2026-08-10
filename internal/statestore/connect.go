package statestore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	_ "modernc.org/sqlite"
)

const driverName = "sqlite"

// Connect opens the SQLite state database at path and verifies the connection
// with a ping before returning it. Every connection applies the pragmas Zen
// IdP requires: WAL journal mode, enabled foreign keys, a five-second busy
// timeout, and normal synchronous mode.
func Connect(ctx context.Context, path string) (*sql.DB, error) {
	dsn, err := dataSourceName(path)
	if err != nil {
		return nil, err
	}

	db, err := sql.Open(driverName, dsn)
	if err != nil {
		return nil, fmt.Errorf("open state database: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		if closeErr := db.Close(); closeErr != nil {
			return nil, errors.Join(
				fmt.Errorf("ping state database: %w", err),
				fmt.Errorf("close state database: %w", closeErr),
			)
		}
		return nil, fmt.Errorf("ping state database: %w", err)
	}
	return db, nil
}

// dataSourceName returns the SQLite DSN for path with the pragmas that must
// apply to every connection.
func dataSourceName(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("state database path must not be empty")
	}
	return "file:" + path +
		"?_pragma=journal_mode(WAL)" +
		"&_pragma=foreign_keys(1)" +
		"&_pragma=busy_timeout(5000)" +
		"&_pragma=synchronous(NORMAL)", nil
}
