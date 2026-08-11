-- +goose Up
CREATE TABLE panic_locks (
    sub        TEXT PRIMARY KEY, -- subject whose login is blocked by a user-authorized panic action
    created_at TEXT NOT NULL     -- lock creation time, UTC RFC 3339
);

-- +goose Down
DROP TABLE panic_locks;
