-- name: CreateAdminLock :exec
INSERT INTO admin_locks (sub, created_at)
VALUES (sqlc.arg(sub), sqlc.arg(created_at))
ON CONFLICT (sub) DO NOTHING;

-- name: GetAdminLock :one
SELECT sub, created_at
FROM admin_locks
WHERE sub = sqlc.arg(sub);

-- name: ClearAdminLock :exec
DELETE FROM admin_locks
WHERE sub = sqlc.arg(sub);
