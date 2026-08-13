package login

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/varavelio/zen-idp/internal/audit"
	"github.com/varavelio/zen-idp/internal/config"
	"github.com/varavelio/zen-idp/internal/session"
	"github.com/varavelio/zen-idp/internal/totp"
)

// maxIdentifierLength bounds login identifiers so that unknown identifiers
// always fit the rate-limit key contract. It comfortably fits any realistic
// sub or idp_login value, including email addresses.
const maxIdentifierLength = 256

// ErrDenied is the generic authentication failure returned for every denied
// login attempt. Unknown identifiers, wrong or malformed codes, expired
// users, locked users, and throttling all produce this same error so that
// failure causes cannot be distinguished.
var ErrDenied = errors.New("login denied")

// rateLimiter bounds failed attempts per login key, satisfied by
// ratelimit.Limiter. It is defined consumer-side so the service never
// depends on a concrete rate-limit implementation.
type rateLimiter interface {
	Allow(context.Context, string, time.Time) (bool, error)
	RecordFailure(context.Context, string, time.Time) error
	Reset(context.Context, string) error
}

// lockChecker reports whether a subject is currently gated by a panic or
// administrative lock, satisfied by lock.Locks.
type lockChecker interface {
	IsLocked(context.Context, string) (bool, error)
}

// sessionCreator persists an authenticated session and returns its browser
// credential token, satisfied by session.Store.
type sessionCreator interface {
	Create(context.Context, session.CreateParams) (string, error)
}

// auditRecorder appends security-relevant events, satisfied by
// audit.Recorder.
type auditRecorder interface {
	Record(context.Context, audit.RecordParams) error
}

// Service authenticates users and creates their authoritative sessions.
type Service struct {
	users       []config.User
	rootSecret  [sha256.Size]byte
	rateLimiter rateLimiter
	locks       lockChecker
	sessions    sessionCreator
	audit       auditRecorder
}

// New returns a service that authenticates against users with the
// deterministic TOTP credentials derived from rootSecret, gates attempts
// through rateLimiter and locks, records sessions through sessions, and
// appends rate-limit events through audit.
func New(
	users []config.User,
	rootSecret [sha256.Size]byte,
	rateLimiter rateLimiter,
	locks lockChecker,
	sessions sessionCreator,
	audit auditRecorder,
) (*Service, error) {
	if rateLimiter == nil {
		return nil, errors.New("login rate limiter is nil")
	}
	if locks == nil {
		return nil, errors.New("login lock checker is nil")
	}
	if sessions == nil {
		return nil, errors.New("login session creator is nil")
	}
	if audit == nil {
		return nil, errors.New("login audit recorder is nil")
	}
	return &Service{
		users:       users,
		rootSecret:  rootSecret,
		rateLimiter: rateLimiter,
		locks:       locks,
		sessions:    sessions,
		audit:       audit,
	}, nil
}

// Params carries one login attempt.
type Params struct {
	// Identifier is the case-sensitive login identifier: the user's sub or,
	// when configured, their idp_login.
	Identifier string
	// Code is the strictly formatted six-digit TOTP code.
	Code string
	// IPAddress is the client address observed at session start. It is
	// omitted from the session record when empty.
	IPAddress string
	// UserAgent is the client user agent observed at session start. It is
	// omitted from the session record when empty.
	UserAgent string
	// Now is the authentication instant, in UTC.
	Now time.Time
}

// Login authenticates identifier with code at the given instant and, on
// success, creates and returns an authoritative SSO session token.
//
// The identifier is resolved case-sensitively against the configured users.
// Rate limits are applied before credential verification and keyed by the
// resolved user's stable subject, or by the exact identifier when it
// resolves to no user. The resolved user must be unexpired and unlocked
// before its deterministic TOTP credential is verified with bounded clock
// skew.
//
// Every denied attempt returns ErrDenied. Attempts that pass the rate-limit
// gate consume one failure from the identifier's counter; a successful
// login resets the counter and records a new session. A throttled attempt,
// one denied by the rate limiter before any verification, is recorded as a
// rate-limit audit event.
func (service *Service) Login(ctx context.Context, params Params) (string, error) {
	if params.Identifier == "" || len(params.Identifier) > maxIdentifierLength {
		return "", ErrDenied
	}

	user, known := service.resolve(params.Identifier)
	key := params.Identifier
	if known {
		key = user.Subject
	}

	allowed, err := service.rateLimiter.Allow(ctx, key, params.Now)
	if err != nil {
		return "", fmt.Errorf("check rate limit: %w", err)
	}
	if !allowed {
		subject := ""
		if known {
			subject = user.Subject
		}
		if err := service.recordRateLimitEvent(ctx, subject, key, params.Now); err != nil {
			return "", err
		}
		return "", ErrDenied
	}

	if !known || !user.ExpiresAt.IsZero() && !params.Now.Before(user.ExpiresAt) {
		if err := service.rateLimiter.RecordFailure(ctx, key, params.Now); err != nil {
			return "", fmt.Errorf("record rate limit failure: %w", err)
		}
		return "", ErrDenied
	}

	locked, err := service.locks.IsLocked(ctx, user.Subject)
	if err != nil {
		return "", fmt.Errorf("check user locks: %w", err)
	}
	if locked {
		if err := service.rateLimiter.RecordFailure(ctx, key, params.Now); err != nil {
			return "", fmt.Errorf("record rate limit failure: %w", err)
		}
		return "", ErrDenied
	}

	secret, err := totp.DeriveSharedSecret(service.rootSecret, user.Subject, user.TOTPRevision)
	if err != nil {
		return "", fmt.Errorf("derive totp secret: %w", err)
	}

	ok, err := totp.VerifyCode(secret, params.Code, params.Now)
	if err != nil {
		if err := service.rateLimiter.RecordFailure(ctx, key, params.Now); err != nil {
			return "", fmt.Errorf("record rate limit failure: %w", err)
		}
		return "", ErrDenied
	}
	if !ok {
		if err := service.rateLimiter.RecordFailure(ctx, key, params.Now); err != nil {
			return "", fmt.Errorf("record rate limit failure: %w", err)
		}
		return "", ErrDenied
	}

	if err := service.rateLimiter.Reset(ctx, key); err != nil {
		return "", fmt.Errorf("reset rate limit counter: %w", err)
	}

	token, err := service.sessions.Create(ctx, session.CreateParams{
		Subject:   user.Subject,
		TOTPRev:   user.TOTPRevision,
		IPAddress: params.IPAddress,
		UserAgent: params.UserAgent,
		Now:       params.Now,
	})
	if err != nil {
		return "", fmt.Errorf("create session: %w", err)
	}
	return token, nil
}

// resolve returns the configured user that owns identifier. Configuration
// validation guarantees that the shared identifier namespace has no
// collisions, so the first match is the only match.
func (service *Service) resolve(identifier string) (config.User, bool) {
	for _, user := range service.users {
		if user.MatchesLoginIdentifier(identifier) {
			return user, true
		}
	}
	return config.User{}, false
}

// recordRateLimitEvent appends a rate-limit audit event for a throttled
// attempt against the given counter key. The subject carries the stable sub
// of a known user and stays empty for an unknown identifier; the key always
// carries the exact counter key the limiter denied, which is the identifier
// itself when it resolves to no user.
func (service *Service) recordRateLimitEvent(
	ctx context.Context,
	subject, key string,
	now time.Time,
) error {
	err := service.audit.Record(ctx, audit.RecordParams{
		Category: audit.CategoryRateLimit,
		Subject:  subject,
		Details:  map[string]any{"key": key},
		Now:      now,
	})
	if err != nil {
		return fmt.Errorf("record rate limit event: %w", err)
	}
	return nil
}
