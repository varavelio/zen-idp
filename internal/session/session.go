package session

import (
	"errors"
	"time"
)

// Sentinel errors reported by the store. Callers can rely on them to
// distinguish malformed input from unknown or expired sessions.
var (
	// ErrMalformedToken reports a browser token that does not match the
	// sess_{id}_{secret} format.
	ErrMalformedToken = errors.New("session token is malformed")
	// ErrInvalidSession reports a token whose record is missing or whose
	// secret does not match the stored digest. Both failures map to the same
	// error so the store does not reveal which one occurred.
	ErrInvalidSession = errors.New("session is invalid")
	// ErrExpiredSession reports a valid credential whose record has passed
	// its absolute expiration. The expired row is deleted opportunistically.
	ErrExpiredSession = errors.New("session has expired")
)

// Session is the authenticated, active SSO session record that a validated
// browser token resolves to.
type Session struct {
	// ID is the opaque record identifier embedded in the browser token.
	ID string
	// Subject is the authenticated user's stable subject.
	Subject string
	// TOTPRev is the authenticated TOTP revision at issue time. A later
	// revision invalidates the session at every subsequent use.
	TOTPRev uint64
	// CreatedAt is the moment the session was created, in UTC.
	CreatedAt time.Time
	// ExpiresAt is the absolute moment the session stops being valid, in UTC.
	ExpiresAt time.Time
}
