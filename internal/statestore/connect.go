package statestore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	_ "modernc.org/sqlite"
)

const (
	driverName   = "sqlite"
	maxOpenConns = 4
	maxIdleConns = 4
)

// Connect opens the SQLite state database at path and verifies the connection
// with a ping before returning it. Every connection applies the pragmas Zen
// IdP requires: WAL journal mode, enabled foreign keys, a five-second busy
// timeout, normal synchronous mode, an in-memory temp store, and a 64 MiB
// page cache. The connection pool is bounded because SQLite serializes writes
// on a single file; a handful of connections serves concurrent readers
// without creating lock contention. Connections are not given a lifetime
// limit because local SQLite connections never go stale.
func Connect(ctx context.Context, path string) (*sql.DB, error) {
	dsn, err := dataSourceName(path)
	if err != nil {
		return nil, err
	}

	db, err := sql.Open(driverName, dsn)
	if err != nil {
		return nil, fmt.Errorf("open state database: %w", err)
	}
	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(maxIdleConns)

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
		"&_pragma=synchronous(NORMAL)" +
		"&_pragma=busy_timeout(5000)" +
		"&_pragma=foreign_keys(1)" +
		"&_pragma=temp_store(MEMORY)" +
		"&_pragma=cache_size(-64000)", nil
}
