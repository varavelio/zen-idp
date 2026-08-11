-- name: CreateOneUseToken :exec
INSERT INTO one_use_tokens (
    id,
    secret_hash,
    sub,
    totp_rev,
    expires_at,
    created_at,
    client_id,
    redirect_uri,
    scope,
    nonce,
    pkce_challenge,
    pkce_method
) VALUES (
    sqlc.arg(id),
    sqlc.arg(secret_hash),
    sqlc.arg(sub),
    sqlc.arg(totp_rev),
    sqlc.arg(expires_at),
    sqlc.arg(created_at),
    sqlc.arg(client_id),
    sqlc.arg(redirect_uri),
    sqlc.arg(scope),
    sqlc.arg(nonce),
    sqlc.arg(pkce_challenge),
    sqlc.arg(pkce_method)
);

-- name: GetOneUseToken :one
SELECT id, secret_hash, sub, totp_rev, expires_at, consumed_at, created_at,
       client_id, redirect_uri, scope, nonce, pkce_challenge, pkce_method
FROM one_use_tokens
WHERE id = sqlc.arg(id);

-- name: ConsumeOneUseToken :execrows
UPDATE one_use_tokens
SET consumed_at = sqlc.arg(consumed_at)
WHERE id = sqlc.arg(id)
  AND consumed_at IS NULL;

-- name: DeleteOneUseToken :exec
DELETE FROM one_use_tokens
WHERE id = sqlc.arg(id);

-- name: DeleteExpiredOneUseTokens :execrows
DELETE FROM one_use_tokens
WHERE expires_at < sqlc.arg(now);
