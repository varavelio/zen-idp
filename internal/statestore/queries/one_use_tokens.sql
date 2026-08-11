-- name: CreateOneUseToken :exec
INSERT INTO one_use_tokens (
    id,
    kind,
    secret_hash,
    sub,
    totp_rev,
    expires_at,
    created_at,
    code_client_id,
    code_redirect_uri,
    code_scope,
    code_nonce,
    code_pkce_challenge,
    code_pkce_method
) VALUES (
    sqlc.arg(id),
    sqlc.arg(kind),
    sqlc.arg(secret_hash),
    sqlc.arg(sub),
    sqlc.arg(totp_rev),
    sqlc.arg(expires_at),
    sqlc.arg(created_at),
    sqlc.arg(code_client_id),
    sqlc.arg(code_redirect_uri),
    sqlc.arg(code_scope),
    sqlc.arg(code_nonce),
    sqlc.arg(code_pkce_challenge),
    sqlc.arg(code_pkce_method)
);

-- name: GetOneUseToken :one
SELECT id, kind, secret_hash, sub, totp_rev, expires_at, consumed_at, created_at,
       code_client_id, code_redirect_uri, code_scope, code_nonce,
       code_pkce_challenge, code_pkce_method
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
