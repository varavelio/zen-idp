-- +goose Up
CREATE TABLE one_use_tokens (
    id          TEXT PRIMARY KEY, -- allowlisted opaque token identifier (TypeID)
    secret_hash BLOB NOT NULL,    -- HMAC-SHA256 of the secret half of the token, keyed by a dedicated domain-separated root-secret derivation
    sub         TEXT NOT NULL,    -- subject the token is bound to
    totp_rev    INTEGER NOT NULL, -- TOTP revision the token is bound to
    expires_at  TEXT NOT NULL,    -- absolute expiration, UTC RFC 3339
    consumed_at TEXT,             -- consumption time, UTC RFC 3339; NULL until consumed exactly once
    created_at  TEXT NOT NULL     -- creation time, UTC RFC 3339
);

CREATE INDEX idx_one_use_tokens_sub ON one_use_tokens (sub);
CREATE INDEX idx_one_use_tokens_expires_at ON one_use_tokens (expires_at);

-- +goose Down
DROP TABLE one_use_tokens;
