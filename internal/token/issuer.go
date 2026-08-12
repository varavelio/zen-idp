package token

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/varavelio/zen-idp/internal/config"
)

// Token lifetimes are fixed protocol constants: both token kinds expire 900
// seconds after issuance and are not configurable.
const (
	idTokenLifetime     = 900 * time.Second
	accessTokenLifetime = 900 * time.Second
)

// ErrDenied is the generic issuance failure returned when the subject is
// unknown, expired, or locked. All three causes produce the same error so
// that failure causes cannot be distinguished.
var ErrDenied = errors.New("token issuance denied")

// tokenSigner signs the compact JWS serialization of a claims object,
// satisfied by jwt.Signer.
type tokenSigner interface {
	Sign(claims map[string]any) (string, error)
}

// lockChecker reports whether a subject is currently gated by a panic or
// administrative lock, satisfied by lock.Locks.
type lockChecker interface {
	IsLocked(context.Context, string) (bool, error)
}

// Issuer issues the RS256-signed ID and access tokens of the signing
// identity.
type Issuer struct {
	signer   tokenSigner
	issuer   string
	audience string
	users    []config.User
	locks    lockChecker
}

// NewIssuer returns an Issuer that signs tokens with signer, stamps them
// with the issuer origin, resolves subjects against users, and gates
// issuance through locks.
func NewIssuer(
	signer tokenSigner,
	issuer string,
	users []config.User,
	locks lockChecker,
) (*Issuer, error) {
	if signer == nil {
		return nil, errors.New("token signer is nil")
	}
	if issuer == "" {
		return nil, errors.New("token issuer must not be empty")
	}
	if locks == nil {
		return nil, errors.New("token lock checker is nil")
	}
	return &Issuer{
		signer:   signer,
		issuer:   issuer,
		audience: strings.TrimSuffix(issuer, "/") + "/userinfo",
		users:    users,
		locks:    locks,
	}, nil
}

// IDTokenParams carries the data needed to issue one client-specific ID
// token.
type IDTokenParams struct {
	// Subject is the authenticated user's stable subject.
	Subject string
	// ClientID is the audience of the token.
	ClientID string
	// Nonce is the optional request nonce echoed in the token. It is
	// omitted when empty.
	Nonce string
	// Now is the issuance instant, in UTC.
	Now time.Time
}

// IssueIDToken issues a client-specific ID token for the subject at the
// given instant.
//
// The subject must still be declared, unexpired, and unlocked at the
// issuance instant; otherwise ErrDenied is returned. The token carries iss,
// sub, aud, iat, exp, the nonce when present, and every current custom
// claim of the user, while excluding internal user fields and claim keys
// beginning with idp_.
func (issuer *Issuer) IssueIDToken(ctx context.Context, params IDTokenParams) (string, error) {
	if params.ClientID == "" {
		return "", errors.New("token client id must not be empty")
	}
	user, err := issuer.requireUser(ctx, params.Subject, params.Now)
	if err != nil {
		return "", err
	}

	claims := map[string]any{}
	for key, value := range user.Claims {
		if strings.HasPrefix(key, "idp_") {
			continue
		}
		claims[key] = value
	}
	claims["iss"] = issuer.issuer
	claims["sub"] = user.Subject
	claims["aud"] = params.ClientID
	claims["iat"] = params.Now.Unix()
	claims["exp"] = params.Now.Add(idTokenLifetime).Unix()
	if params.Nonce != "" {
		claims["nonce"] = params.Nonce
	}

	token, err := issuer.signer.Sign(claims)
	if err != nil {
		return "", fmt.Errorf("sign id token: %w", err)
	}
	return token, nil
}

// AccessTokenParams carries the data needed to issue one thin access token.
type AccessTokenParams struct {
	// Subject is the authenticated user's stable subject.
	Subject string
	// SessionID optionally binds the token to its originating session
	// record through a jti claim. It is omitted when empty.
	SessionID string
	// Now is the issuance instant, in UTC.
	Now time.Time
}

// IssueAccessToken issues a thin access token for the subject at the given
// instant.
//
// The subject must still be declared, unexpired, and unlocked at the
// issuance instant; otherwise ErrDenied is returned. The payload is limited
// to sub and exp plus the JWT metadata iss, the /userinfo-specific
// audience aud, iat, and the jti binding when a session is supplied.
// Custom claims are never included.
func (issuer *Issuer) IssueAccessToken(
	ctx context.Context,
	params AccessTokenParams,
) (string, error) {
	user, err := issuer.requireUser(ctx, params.Subject, params.Now)
	if err != nil {
		return "", err
	}

	claims := map[string]any{
		"iss": issuer.issuer,
		"sub": user.Subject,
		"aud": issuer.audience,
		"iat": params.Now.Unix(),
		"exp": params.Now.Add(accessTokenLifetime).Unix(),
	}
	if params.SessionID != "" {
		claims["jti"] = params.SessionID
	}

	token, err := issuer.signer.Sign(claims)
	if err != nil {
		return "", fmt.Errorf("sign access token: %w", err)
	}
	return token, nil
}

// requireUser resolves subject against the active configuration and returns
// the user only when it still exists, is not expired at now, and is not
// gated by a panic or administrative lock. Every other state returns
// ErrDenied.
func (issuer *Issuer) requireUser(
	ctx context.Context,
	subject string,
	now time.Time,
) (config.User, error) {
	if subject == "" {
		return config.User{}, errors.New("token subject must not be empty")
	}
	user, known := issuer.resolve(subject)
	if !known {
		return config.User{}, ErrDenied
	}
	if !user.ExpiresAt.IsZero() && !now.Before(user.ExpiresAt) {
		return config.User{}, ErrDenied
	}
	locked, err := issuer.locks.IsLocked(ctx, subject)
	if err != nil {
		return config.User{}, fmt.Errorf("check user locks: %w", err)
	}
	if locked {
		return config.User{}, ErrDenied
	}
	return user, nil
}

// resolve returns the configured user with the exact subject. Configuration
// validation guarantees subject uniqueness, so the first match is the only
// match.
func (issuer *Issuer) resolve(subject string) (config.User, bool) {
	for _, user := range issuer.users {
		if user.Subject == subject {
			return user, true
		}
	}
	return config.User{}, false
}
