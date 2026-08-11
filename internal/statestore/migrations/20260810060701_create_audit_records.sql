-- +goose Up
CREATE TABLE audit_records (
    id         TEXT    PRIMARY KEY,           -- record identifier (TypeID)
    created_at TEXT    NOT NULL,              -- event time, UTC RFC 3339
    category   TEXT    NOT NULL,              -- event category, e.g. admin_authentication, lock_change
    sub        TEXT,                          -- affected subject or administrator; NULL when not applicable
    details    TEXT    NOT NULL DEFAULT '{}'  -- JSON details; MUST NOT contain credentials, cookies, tokens, or derived keys
);

CREATE INDEX idx_audit_records_created_at ON audit_records (created_at);
CREATE INDEX idx_audit_records_category ON audit_records (category);

-- +goose Down
DROP TABLE audit_records;
