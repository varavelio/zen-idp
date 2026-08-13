-- name: CreateSession :exec
INSERT INTO sessions (
    id,
    kind,
    secret_hash,
    sub,
    totp_rev,
    created_at,
    expires_at,
    ip_address,
    user_agent
) VALUES (
    sqlc.arg(id),
    sqlc.arg(kind),
    sqlc.arg(secret_hash),
    sqlc.arg(sub),
    sqlc.arg(totp_rev),
    sqlc.arg(created_at),
    sqlc.arg(expires_at),
    sqlc.arg(ip_address),
    sqlc.arg(user_agent)
);

-- name: GetSession :one
SELECT id, kind, secret_hash, sub, totp_rev, created_at, expires_at, ip_address, user_agent
FROM sessions
WHERE id = sqlc.arg(id);

-- name: RevokeSession :exec
DELETE FROM sessions
WHERE id = sqlc.arg(id);

-- name: RevokeSessionsBySubject :exec
DELETE FROM sessions
WHERE sub = sqlc.arg(sub);

-- name: DeleteExpiredSessions :execrows
DELETE FROM sessions
WHERE expires_at <= sqlc.arg(now);
