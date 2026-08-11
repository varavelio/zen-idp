-- name: CreateRateLimitCounter :exec
INSERT INTO rate_limit_counters (key, attempts, reset_at, updated_at)
VALUES (sqlc.arg(key), 1, sqlc.arg(reset_at), sqlc.arg(updated_at))
ON CONFLICT (key) DO NOTHING;

-- name: GetRateLimitCounter :one
SELECT key, attempts, reset_at, updated_at
FROM rate_limit_counters
WHERE key = sqlc.arg(key);

-- name: IncrementRateLimitCounter :exec
UPDATE rate_limit_counters
SET attempts = attempts + 1,
    updated_at = sqlc.arg(updated_at)
WHERE key = sqlc.arg(key);

-- name: DeleteExpiredRateLimitCounters :exec
DELETE FROM rate_limit_counters
WHERE reset_at < sqlc.arg(now);
