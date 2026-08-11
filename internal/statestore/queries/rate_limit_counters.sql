-- RecordRateLimitAttempt counts one failed attempt for a key in a single
-- atomic statement. Inserting the first attempt and incrementing an existing
-- counter in one upsert prevents concurrent failures from being
-- double-counted. When the stored reset_at has already passed, the window
-- restarts: attempts resets to 1 and reset_at advances by the window.
-- updated_at carries the current instant and doubles as the comparison time;
-- canonical RFC 3339 UTC timestamps compare lexicographically, so the
-- reset_at <= excluded.updated_at test is a valid time comparison.
-- name: RecordRateLimitAttempt :exec
INSERT INTO rate_limit_counters (key, attempts, reset_at, updated_at)
VALUES (sqlc.arg(key), 1, sqlc.arg(reset_at), sqlc.arg(updated_at))
ON CONFLICT (key) DO UPDATE SET
    attempts = CASE
        WHEN rate_limit_counters.reset_at <= excluded.updated_at THEN 1
        ELSE rate_limit_counters.attempts + 1
    END,
    reset_at = CASE
        WHEN rate_limit_counters.reset_at <= excluded.updated_at THEN excluded.reset_at
        ELSE rate_limit_counters.reset_at
    END,
    updated_at = excluded.updated_at;

-- name: GetRateLimitCounter :one
SELECT key, attempts, reset_at, updated_at
FROM rate_limit_counters
WHERE key = sqlc.arg(key);

-- name: DeleteRateLimitCounter :exec
DELETE FROM rate_limit_counters
WHERE key = sqlc.arg(key);

-- name: DeleteExpiredRateLimitCounters :execrows
DELETE FROM rate_limit_counters
WHERE reset_at < sqlc.arg(now);
