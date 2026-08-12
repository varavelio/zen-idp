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
	// ErrInvalidSession reports a token whose record is missing, whose
	// secret does not match the stored digest, or whose kind does not match
	// the requested kind. All failures map to the same error so the store
	// does not reveal which one occurred.
	ErrInvalidSession = errors.New("session is invalid")
	// ErrExpiredSession reports a valid credential whose record has passed
	// its absolute expiration. The expired row is deleted opportunistically.
	ErrExpiredSession = errors.New("session has expired")
)

// Kind discriminates the two session domains the store persists: regular
// user SSO sessions and administrator sessions. The value is stored verbatim
// in the kind column and selects the domain-separated secret digest.
type Kind string

// Kind constants for the v1 session vocabulary.
const (
	// KindUser marks a regular SSO session created after TOTP
	// authentication.
	KindUser Kind = "user"
	// KindAdmin marks an administrator session created after administrator
	// authentication.
	KindAdmin Kind = "admin"
)

// adminSubject is the reserved literal subject recorded for administrator
// sessions. It is only meaningful inside admin-kind records, which no
// user-facing flow ever accepts.
const adminSubject = "admin"

// Session is the authenticated, active session record that a validated
// browser token resolves to.
type Session struct {
	// ID is the opaque record identifier embedded in the browser token.
	ID string
	// Kind is the session domain the record belongs to.
	Kind Kind
	// Subject is the authenticated user's stable subject, or the reserved
	// adminSubject literal for administrator sessions.
	Subject string
	// TOTPRev is the authenticated TOTP revision at issue time. A later
	// revision invalidates the session at every subsequent use.
	TOTPRev uint64
	// CreatedAt is the moment the session was created, in UTC.
	CreatedAt time.Time
	// ExpiresAt is the absolute moment the session stops being valid, in UTC.
	ExpiresAt time.Time
}
