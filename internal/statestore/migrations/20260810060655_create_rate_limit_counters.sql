-- +goose Up
CREATE TABLE rate_limit_counters (
    key        TEXT    PRIMARY KEY, -- sub or deterministic hash of anything
    attempts   INTEGER NOT NULL     -- failed attempts within the current window
                       CHECK (attempts >= 0),
    reset_at   TEXT    NOT NULL,    -- window end, UTC RFC 3339
    updated_at TEXT    NOT NULL     -- last increment, UTC RFC 3339
);

CREATE INDEX idx_rate_limit_counters_reset_at ON rate_limit_counters (reset_at);

-- +goose Down
DROP TABLE rate_limit_counters;
