// Package admin authenticates the Zen IdP administrator and creates the
// distinct administrator sessions that gate the administrative interfaces.
//
// Authentication verifies the presented credential against the configured
// Argon2id PHC hash of config.security.admin_password_hash with a
// constant-time comparison. Attempts are bounded by a dedicated rate-limit
// counter with a fixed key, so the administrator credential receives
// protections equivalent to user login. Successful and failed verifications
// are recorded as audit events; every denial is indistinguishable through
// the single ErrDenied sentinel.
//
// The administrator session is created through the session store with its
// admin kind, whose credential domain can never validate as a user SSO
// session.
package admin
