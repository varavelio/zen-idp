// Package lock manages the disposable panic and administrative locks that
// gate a subject's login and SSO use.
//
// A panic lock is created by an authenticated user's emergency action and
// blocks new login until an administrator clears it. An administrative lock
// is created by an administrator and blocks login and SSO use until removed.
// Both kinds are independent gates: clearing one never clears the other, and
// because they live in SQLite, losing the state file clears both.
//
// Administrative locking is atomic: LockSubject creates the administrative
// lock and revokes every active session of the subject in one database
// transaction, so the lock blocks SSO use immediately. Creation is
// idempotent and records the first creation instant; checks report whether
// a gate is present; removal succeeds even when no gate exists, so recovery
// flows never fail on absent locks. IsLocked reports either gate and is the
// single check that login and session validation apply before granting
// access.
package lock
