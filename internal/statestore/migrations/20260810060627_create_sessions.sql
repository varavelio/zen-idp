-- +goose Up
CREATE TABLE sessions (
    id          TEXT    PRIMARY KEY, -- opaque session identifier (TypeID); cookie lookup key
    kind        TEXT    NOT NULL     -- session kind: regular user SSO or administrator
                        CHECK (kind IN ('user', 'admin')),
    secret_hash BLOB    NOT NULL,    -- HMAC-SHA256 of the secret half of the browser credential, keyed by a dedicated domain-separated root-secret derivation
    sub         TEXT    NOT NULL,    -- authenticated subject; the reserved literal "admin" for administrator sessions
    totp_rev    INTEGER NOT NULL,    -- authenticated TOTP revision at issue time; 0 for administrator sessions
    created_at  TEXT    NOT NULL,    -- creation time, UTC RFC 3339
    expires_at  TEXT    NOT NULL,    -- absolute expiration, UTC RFC 3339
    ip_address  TEXT,                -- client IP address observed at session start; NULL when not available
    user_agent  TEXT                 -- HTTP user agent observed at session start; NULL when not available
);

CREATE INDEX idx_sessions_sub ON sessions (sub);
CREATE INDEX idx_sessions_expires_at ON sessions (expires_at);

-- +goose Down
DROP TABLE sessions;
