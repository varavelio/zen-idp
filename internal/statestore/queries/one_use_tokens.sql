-- name: CreateOneUseToken :exec
INSERT INTO one_use_tokens (
    id,
    secret_hash,
    sub,
    totp_rev,
    expires_at,
    created_at
) VALUES (
    sqlc.arg(id),
    sqlc.arg(secret_hash),
    sqlc.arg(sub),
    sqlc.arg(totp_rev),
    sqlc.arg(expires_at),
    sqlc.arg(created_at)
);

-- name: GetOneUseToken :one
SELECT id, secret_hash, sub, totp_rev, expires_at, consumed_at, created_at
FROM one_use_tokens
WHERE id = sqlc.arg(id);

-- name: ConsumeOneUseToken :exec
UPDATE one_use_tokens
SET consumed_at = sqlc.arg(consumed_at)
WHERE id = sqlc.arg(id)
  AND consumed_at IS NULL;

-- name: DeleteExpiredOneUseTokens :exec
DELETE FROM one_use_tokens
WHERE expires_at < sqlc.arg(now);
