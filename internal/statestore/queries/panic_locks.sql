-- name: CreatePanicLock :exec
INSERT INTO panic_locks (sub, created_at)
VALUES (sqlc.arg(sub), sqlc.arg(created_at))
ON CONFLICT (sub) DO NOTHING;

-- name: GetPanicLock :one
SELECT sub, created_at
FROM panic_locks
WHERE sub = sqlc.arg(sub);

-- name: ClearPanicLock :exec
DELETE FROM panic_locks
WHERE sub = sqlc.arg(sub);
