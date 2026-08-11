// Package onetoken manages disposable SQLite-backed one-use tokens.
//
// A one-use token is an opaque credential of the form tok_{id}_{secret} that
// can be redeemed exactly once before its absolute expiration. It is the
// mechanism behind enrollment tokens and OIDC authorization codes: both are
// allowlisted records in the same one_use_tokens table, distinguished by
// their bindings. Enrollment tokens bind a subject and TOTP revision;
// authorization codes additionally bind a client, exact redirect URI,
// requested scopes, optional nonce, and the PKCE challenge and method when
// PKCE was used.
//
// The secret half is persisted only as an HMAC-SHA-256 digest keyed by the
// normalized root secret with a dedicated domain-separated prefix, so a
// stolen database is insufficient to redeem a token. Consumption is an
// atomic SQLite update that succeeds exactly once; concurrent or repeated
// redemption attempts fail.
//
// Validation authenticates the token against the authoritative record with
// a constant-time comparison, enforces the absolute expiration, and rejects
// tokens redeemed with the wrong flow: an authorization code cannot be
// consumed as an enrollment token and vice versa.
package onetoken
