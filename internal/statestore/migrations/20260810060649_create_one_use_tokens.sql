-- +goose Up
CREATE TABLE one_use_tokens (
    id                  TEXT PRIMARY KEY, -- allowlisted opaque token identifier (TypeID)
    kind                TEXT NOT NULL     -- token use case: enrollment tokens or authorization codes
                             CHECK (kind IN ('enrollment', 'code')),
    secret_hash         BLOB NOT NULL,    -- HMAC-SHA256 of the secret half of the token, keyed by a dedicated domain-separated root-secret derivation
    sub                 TEXT NOT NULL,    -- subject the token is bound to
    totp_rev            INTEGER NOT NULL, -- TOTP revision the token is bound to
    expires_at          TEXT NOT NULL,    -- absolute expiration, UTC RFC 3339
    consumed_at         TEXT,             -- consumption time, UTC RFC 3339; NULL until consumed exactly once
    created_at          TEXT NOT NULL,    -- creation time, UTC RFC 3339
    code_client_id      TEXT,             -- authorization-code binding: OIDC client identifier; NULL for enrollment tokens
    code_redirect_uri   TEXT,             -- authorization-code binding: exact registered redirect URI; NULL for enrollment tokens
    code_scope          TEXT,             -- authorization-code binding: requested scope string; NULL for enrollment tokens
    code_nonce          TEXT,             -- authorization-code binding: request nonce, when present
    code_pkce_challenge TEXT,             -- authorization-code binding: PKCE S256 challenge, when PKCE was used
    code_pkce_method    TEXT,             -- authorization-code binding: PKCE method ("S256"), when PKCE was used
    code_auth_time      TEXT,             -- authorization-code binding: session authentication time, UTC RFC 3339; NULL for enrollment tokens
    CHECK (
        (kind = 'enrollment' AND code_client_id IS NULL) OR
        (kind = 'code' AND code_client_id IS NOT NULL)
    )
);

CREATE INDEX idx_one_use_tokens_sub ON one_use_tokens (sub);
CREATE INDEX idx_one_use_tokens_expires_at ON one_use_tokens (expires_at);

-- +goose Down
DROP TABLE one_use_tokens;
