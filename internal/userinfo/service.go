package userinfo

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/varavelio/zen-idp/internal/config"
	"github.com/varavelio/zen-idp/internal/session"
)

// ErrDenied is the generic resolution failure returned for every rejected
// access token: unauthentic or malformed tokens, wrong issuer or audience,
// expired tokens, removed or expired users, locked users, and revoked or
// stale sessions all produce this same error so that failure causes cannot
// be distinguished.
var ErrDenied = errors.New("userinfo denied")

// tokenVerifier authenticates a compact JWS token and returns its claims,
// satisfied by jwt.Verifier. It is defined consumer-side so the service
// never depends on a concrete token implementation.
type tokenVerifier interface {
	Verify(token string) (map[string]any, error)
}

// lockChecker reports whether a subject is currently gated by a panic or
// administrative lock, satisfied by lock.Locks.
type lockChecker interface {
	IsLocked(context.Context, string) (bool, error)
}

// sessionValidator validates an active session record by its identifier,
// satisfied by session.Store.
type sessionValidator interface {
	ValidateID(context.Context, string, time.Time) (session.Session, error)
}

// Service resolves access tokens into the current claims of their subject.
type Service struct {
	verifier tokenVerifier
	issuer   string
	audience string
	users    []config.User
	locks    lockChecker
	sessions sessionValidator
}

// New returns a service that authenticates access tokens with verifier,
// accepts only tokens stamped with the issuer origin and its dedicated
// /userinfo audience, resolves subjects against users, and enforces current
// lock and session state through locks and sessions.
func New(
	verifier tokenVerifier,
	issuer string,
	users []config.User,
	locks lockChecker,
	sessions sessionValidator,
) (*Service, error) {
	if verifier == nil {
		return nil, errors.New("userinfo verifier is nil")
	}
	if issuer == "" {
		return nil, errors.New("userinfo issuer must not be empty")
	}
	if locks == nil {
		return nil, errors.New("userinfo lock checker is nil")
	}
	if sessions == nil {
		return nil, errors.New("userinfo session validator is nil")
	}
	return &Service{
		verifier: verifier,
		issuer:   issuer,
		audience: strings.TrimSuffix(issuer, "/") + "/userinfo",
		users:    users,
		locks:    locks,
		sessions: sessions,
	}, nil
}

// Resolve returns the current claims of the subject authenticated by
// accessToken at the given instant, or ErrDenied when the token or its
// subject is not acceptable.
//
// The token must be an authentic token of the signing identity whose
// issuer, dedicated /userinfo audience, and expiration are valid. The
// subject must still be declared, unexpired, and unlocked, and where the
// token is session-bound through its jti claim, the session record must
// still be active, belong to the subject, and carry the subject's current
// TOTP revision. The returned claims are sub plus every current custom
// claim, excluding internal user fields and claim keys beginning with idp_.
func (service *Service) Resolve(
	ctx context.Context,
	accessToken string,
	now time.Time,
) (map[string]any, error) {
	claims, err := service.verifier.Verify(accessToken)
	if err != nil {
		return nil, ErrDenied
	}

	subject, ok := claims["sub"].(string)
	if !ok || subject == "" {
		return nil, ErrDenied
	}
	if claims["iss"] != service.issuer {
		return nil, ErrDenied
	}
	if !audienceMatches(claims["aud"], service.audience) {
		return nil, ErrDenied
	}
	exp, ok := claims["exp"].(float64)
	if !ok || !now.Before(time.Unix(int64(exp), 0)) {
		return nil, ErrDenied
	}

	user, err := service.requireUser(ctx, subject, now)
	if err != nil {
		return nil, err
	}

	if jti, bound := claims["jti"]; bound {
		if err := service.requireSession(ctx, jti, subject, user.TOTPRevision, now); err != nil {
			return nil, err
		}
	}

	resolved := map[string]any{"sub": user.Subject}
	for key, value := range user.Claims {
		if strings.HasPrefix(key, "idp_") {
			continue
		}
		resolved[key] = value
	}
	return resolved, nil
}

// requireUser resolves subject against the active configuration and returns
// the user only when it still exists, is not expired at now, and is not
// gated by a panic or administrative lock. Every other state returns
// ErrDenied.
func (service *Service) requireUser(
	ctx context.Context,
	subject string,
	now time.Time,
) (config.User, error) {
	user, known := service.resolve(subject)
	if !known {
		return config.User{}, ErrDenied
	}
	if !user.ExpiresAt.IsZero() && !now.Before(user.ExpiresAt) {
		return config.User{}, ErrDenied
	}
	locked, err := service.locks.IsLocked(ctx, subject)
	if err != nil {
		return config.User{}, fmt.Errorf("check user locks: %w", err)
	}
	if locked {
		return config.User{}, ErrDenied
	}
	return user, nil
}

// requireSession validates the session record bound to the token through
// its jti claim. The record must exist, belong to the token's subject, be
// unexpired at now, and carry the subject's current TOTP revision; every
// other state returns ErrDenied.
func (service *Service) requireSession(
	ctx context.Context,
	jti any,
	subject string,
	revision uint64,
	now time.Time,
) error {
	id, ok := jti.(string)
	if !ok || id == "" {
		return ErrDenied
	}
	record, err := service.sessions.ValidateID(ctx, id, now)
	if errors.Is(err, session.ErrInvalidSession) || errors.Is(err, session.ErrExpiredSession) {
		return ErrDenied
	}
	if err != nil {
		return fmt.Errorf("validate session: %w", err)
	}
	if record.Subject != subject {
		return ErrDenied
	}
	if record.TOTPRev != revision {
		return ErrDenied
	}
	return nil
}

// resolve returns the configured user with the exact subject. Configuration
// validation guarantees subject uniqueness, so the first match is the only
// match.
func (service *Service) resolve(subject string) (config.User, bool) {
	for _, user := range service.users {
		if user.Subject == subject {
			return user, true
		}
	}
	return config.User{}, false
}

// audienceMatches reports whether the token audience accepts the given
// /userinfo audience: the single-string form or an array containing it.
func audienceMatches(claim any, audience string) bool {
	switch value := claim.(type) {
	case string:
		return value == audience
	case []any:
		for _, member := range value {
			if member == audience {
				return true
			}
		}
	}
	return false
}
