package onetoken

import (
	"errors"
	"time"
)

// Sentinel errors reported by the store. Callers can rely on them to
// distinguish malformed input from unknown, consumed, or expired tokens.
var (
	// ErrMalformedToken reports a token that does not match the
	// tok_{id}_{secret} format.
	ErrMalformedToken = errors.New("one-use token is malformed")
	// ErrInvalidToken reports a token whose record is missing, whose secret
	// does not match the stored digest, that was redeemed through the wrong
	// flow, or that was already consumed. These failures map to the same
	// error so the store does not reveal which one occurred.
	ErrInvalidToken = errors.New("one-use token is invalid")
	// ErrExpiredToken reports a valid credential whose record has passed its
	// absolute expiration. The expired row is deleted opportunistically.
	ErrExpiredToken = errors.New("one-use token has expired")
)

// Enrollment is the validated record an enrollment token resolves to. It
// carries the bindings the consuming flow must check against the current
// configuration: the user must still exist, be unexpired, and be at the
// recorded TOTP revision.
type Enrollment struct {
	// ID is the opaque record identifier embedded in the token.
	ID string
	// Subject is the exact configured sub the token is bound to.
	Subject string
	// TOTPRev is the TOTP revision the token is bound to.
	TOTPRev uint64
	// ExpiresAt is the absolute moment the token stops being redeemable,
	// in UTC.
	ExpiresAt time.Time
}

// Code is the validated record an authorization code resolves to. It carries
// every binding the token endpoint must validate: the presented client must
// match ClientID, the presented redirect URI must match RedirectURI exactly,
// and a PKCE-bound code requires the verifier for PKCEChallenge.
type Code struct {
	// ID is the opaque record identifier embedded in the token.
	ID string
	// Subject is the authenticated subject the code is bound to.
	Subject string
	// TOTPRev is the authenticated TOTP revision at issuance.
	TOTPRev uint64
	// ClientID is the OIDC client the code was issued to.
	ClientID string
	// RedirectURI is the exact redirect URI the code was issued for.
	RedirectURI string
	// Scope is the scope string accepted in the authorization request.
	Scope string
	// Nonce is the request nonce, empty when the request carried none.
	Nonce string
	// PKCEChallenge is the S256 challenge the code is bound to, empty when
	// the authorization request used no PKCE.
	PKCEChallenge string
	// PKCEMethod is the PKCE method, "S256" when PKCE was used.
	PKCEMethod string
	// ExpiresAt is the absolute moment the code stops being redeemable,
	// in UTC.
	ExpiresAt time.Time
}
