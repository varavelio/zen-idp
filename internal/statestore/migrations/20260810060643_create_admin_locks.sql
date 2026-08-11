-- +goose Up
CREATE TABLE admin_locks (
    sub        TEXT PRIMARY KEY, -- subject whose login and SSO use is blocked by an administrator
    created_at TEXT NOT NULL     -- lock creation time, UTC RFC 3339
);

-- +goose Down
DROP TABLE admin_locks;
