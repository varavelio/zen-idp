package admin

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/varavelio/zen-idp/internal/audit"
	"github.com/varavelio/zen-idp/internal/crypto"
	"github.com/varavelio/zen-idp/internal/session"
)

// rateLimitKey is the fixed counter key shared by every administrator
// authentication attempt. The administrator is a single credential, so one
// global counter is the right granularity.
const rateLimitKey = "admin-login"

// ErrDenied is the generic authentication failure returned for every denied
// administrator login attempt. Wrong credentials and throttling produce this
// same error so that failure causes cannot be distinguished.
var ErrDenied = errors.New("admin login denied")

// rateLimiter bounds failed attempts, satisfied by ratelimit.Limiter. It is
// defined consumer-side so the service never depends on a concrete
// rate-limit implementation.
type rateLimiter interface {
	Allow(context.Context, string, time.Time) (bool, error)
	RecordFailure(context.Context, string, time.Time) error
	Reset(context.Context, string) error
}

// sessionCreator persists an authenticated administrator session and
// returns its browser credential token, satisfied by session.Store.
type sessionCreator interface {
	CreateAdmin(context.Context, session.AdminParams) (string, error)
}

// auditRecorder appends security-relevant events, satisfied by
// audit.Recorder.
type auditRecorder interface {
	Record(context.Context, audit.RecordParams) error
}

// Service authenticates the administrator and creates the distinct
// administrator session.
type Service struct {
	passwordHash string
	rateLimiter  rateLimiter
	sessions     sessionCreator
	audit        auditRecorder
}

// New returns a service that authenticates the administrator against
// passwordHash, gates attempts through rateLimiter, records sessions
// through sessions, and appends authentication events through audit.
func New(
	passwordHash string,
	rateLimiter rateLimiter,
	sessions sessionCreator,
	audit auditRecorder,
) (*Service, error) {
	if err := crypto.ValidateCredentialHash(passwordHash); err != nil {
		return nil, fmt.Errorf("admin password hash: %w", err)
	}
	if rateLimiter == nil {
		return nil, errors.New("admin rate limiter is nil")
	}
	if sessions == nil {
		return nil, errors.New("admin session creator is nil")
	}
	if audit == nil {
		return nil, errors.New("admin audit recorder is nil")
	}
	return &Service{
		passwordHash: passwordHash,
		rateLimiter:  rateLimiter,
		sessions:     sessions,
		audit:        audit,
	}, nil
}

// Login authenticates the administrator with the given password at the
// given instant and, on success, creates and returns an administrator
// session token.
//
// The rate limit is applied before credential verification. Every denied
// attempt returns ErrDenied; attempts that pass the rate-limit gate consume
// one failure from the counter and are recorded as failed authentication
// events. A successful login resets the counter, records a new
// administrator session, and appends a successful authentication event.
func (service *Service) Login(ctx context.Context, password string, now time.Time) (string, error) {
	allowed, err := service.rateLimiter.Allow(ctx, rateLimitKey, now)
	if err != nil {
		return "", fmt.Errorf("check admin rate limit: %w", err)
	}
	if !allowed {
		return "", ErrDenied
	}

	match, err := crypto.VerifyCredential(password, service.passwordHash)
	if err != nil || !match {
		if err := service.rateLimiter.RecordFailure(ctx, rateLimitKey, now); err != nil {
			return "", fmt.Errorf("record admin rate limit failure: %w", err)
		}
		if err := service.recordEvent(ctx, "failure", now); err != nil {
			return "", err
		}
		return "", ErrDenied
	}

	if err := service.rateLimiter.Reset(ctx, rateLimitKey); err != nil {
		return "", fmt.Errorf("reset admin rate limit counter: %w", err)
	}

	token, err := service.sessions.CreateAdmin(ctx, session.AdminParams{Now: now})
	if err != nil {
		return "", fmt.Errorf("create admin session: %w", err)
	}

	if err := service.recordEvent(ctx, "success", now); err != nil {
		return "", err
	}
	return token, nil
}

// recordEvent appends an administrator-authentication audit event with the
// given outcome. The event carries no credential material and no subject:
// the administrator is a single configured identity.
func (service *Service) recordEvent(ctx context.Context, outcome string, now time.Time) error {
	err := service.audit.Record(ctx, audit.RecordParams{
		Category: audit.CategoryAdminAuthentication,
		Details:  map[string]any{"outcome": outcome},
		Now:      now,
	})
	if err != nil {
		return fmt.Errorf("record admin authentication event: %w", err)
	}
	return nil
}
