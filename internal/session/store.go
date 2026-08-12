package session

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/varavelio/zen-idp/internal/clock"
	"github.com/varavelio/zen-idp/internal/crypto"
	"github.com/varavelio/zen-idp/internal/statestore"
)

// sessionQueries is the SQLite-backed session persistence the store needs,
// satisfied by statestore.Queries. It is defined consumer-side so the store
// never depends on a concrete persistence implementation.
type sessionQueries interface {
	CreateSession(context.Context, statestore.CreateSessionParams) error
	GetSession(context.Context, string) (statestore.Session, error)
	RevokeSession(context.Context, string) error
	RevokeSessionsBySubject(context.Context, string) error
}

// idGenerator creates the opaque record identifiers embedded in browser
// tokens, satisfied by id.IDGenerator.
type idGenerator interface {
	NewID(context.Context) string
}

// Store owns the session lifecycle: creation after authentication for both
// the user and administrator domains, browser token validation, record
// validation by identifier, and revocation.
type Store struct {
	queries    sessionQueries
	ids        idGenerator
	rootSecret [sha256.Size]byte
	maxAge     time.Duration
}

// NewStore returns a store that persists sessions through queries, assigns
// identifiers with ids, digests secrets with the normalized root secret, and
// expires sessions after maxAge.
func NewStore(
	queries sessionQueries,
	ids idGenerator,
	rootSecret [sha256.Size]byte,
	maxAge time.Duration,
) (*Store, error) {
	if queries == nil {
		return nil, errors.New("session store queries are nil")
	}
	if ids == nil {
		return nil, errors.New("session store id generator is nil")
	}
	if maxAge <= 0 {
		return nil, errors.New("session max age must be positive")
	}
	return &Store{
		queries:    queries,
		ids:        ids,
		rootSecret: rootSecret,
		maxAge:     maxAge,
	}, nil
}

// CreateParams carries the authenticated identity and context recorded for a
// new session.
type CreateParams struct {
	// Subject is the authenticated user's stable subject.
	Subject string
	// TOTPRev is the TOTP revision that authenticated the user.
	TOTPRev uint64
	// IPAddress is the client address observed at session start. It is
	// omitted from the record when empty.
	IPAddress string
	// UserAgent is the client user agent observed at session start. It is
	// omitted from the record when empty.
	UserAgent string
	// Now is the issue instant, in UTC.
	Now time.Time
}

// Create records a new active user session for the authenticated identity
// and returns its browser credential token, formatted sess_{id}_{secret}.
// The token is the only value that can later authenticate the session; the
// secret half is persisted only as a domain-separated HMAC-SHA-256 digest.
func (store *Store) Create(ctx context.Context, params CreateParams) (string, error) {
	if params.Subject == "" {
		return "", errors.New("session subject must not be empty")
	}

	secret, err := crypto.GenerateMachineSecret()
	if err != nil {
		return "", fmt.Errorf("generate session secret: %w", err)
	}

	id := store.ids.NewID(ctx)
	err = store.queries.CreateSession(ctx, statestore.CreateSessionParams{
		ID:         id,
		Kind:       string(KindUser),
		SecretHash: hashSecret(store.rootSecret, secret, KindUser),
		Sub:        params.Subject,
		TotpRev:    int64(params.TOTPRev),
		CreatedAt:  clock.Format(params.Now),
		ExpiresAt:  clock.Format(params.Now.Add(store.maxAge)),
		IpAddress:  nullString(params.IPAddress),
		UserAgent:  nullString(params.UserAgent),
	})
	if err != nil {
		return "", fmt.Errorf("create session: %w", err)
	}

	return formatToken(id, secret), nil
}

// AdminParams carries the context recorded for a new administrator session.
type AdminParams struct {
	// IPAddress is the client address observed at session start. It is
	// omitted from the record when empty.
	IPAddress string
	// UserAgent is the client user agent observed at session start. It is
	// omitted from the record when empty.
	UserAgent string
	// Now is the issue instant, in UTC.
	Now time.Time
}

// CreateAdmin records a new active administrator session and returns its
// browser credential token. Administrator sessions are distinct from user
// SSO sessions: they carry the reserved adminSubject literal, no TOTP
// revision, and a secret digested with the administrator domain, so they can
// never authenticate any user-facing flow.
func (store *Store) CreateAdmin(ctx context.Context, params AdminParams) (string, error) {
	secret, err := crypto.GenerateMachineSecret()
	if err != nil {
		return "", fmt.Errorf("generate session secret: %w", err)
	}

	id := store.ids.NewID(ctx)
	err = store.queries.CreateSession(ctx, statestore.CreateSessionParams{
		ID:         id,
		Kind:       string(KindAdmin),
		SecretHash: hashSecret(store.rootSecret, secret, KindAdmin),
		Sub:        adminSubject,
		TotpRev:    0,
		CreatedAt:  clock.Format(params.Now),
		ExpiresAt:  clock.Format(params.Now.Add(store.maxAge)),
		IpAddress:  nullString(params.IPAddress),
		UserAgent:  nullString(params.UserAgent),
	})
	if err != nil {
		return "", fmt.Errorf("create session: %w", err)
	}

	return formatToken(id, secret), nil
}

// Validate authenticates a user-session browser token at the given instant
// and returns the authoritative session record it resolves to. The token
// must match the sess_{id}_{secret} format, its record must exist and be a
// user-kind session, its secret must match the stored digest, and the
// absolute expiration must not have passed. Administrator tokens are
// rejected as invalid user sessions.
func (store *Store) Validate(ctx context.Context, token string, now time.Time) (Session, error) {
	return store.validate(ctx, token, now, KindUser)
}

// ValidateAdmin authenticates an administrator-session browser token at the
// given instant and returns the authoritative session record it resolves
// to, with the same strictness as Validate but for admin-kind sessions.
// Regular user tokens are rejected as invalid administrator sessions.
func (store *Store) ValidateAdmin(
	ctx context.Context,
	token string,
	now time.Time,
) (Session, error) {
	return store.validate(ctx, token, now, KindAdmin)
}

// validate authenticates a browser token as a session of the given kind.
func (store *Store) validate(
	ctx context.Context,
	token string,
	now time.Time,
	kind Kind,
) (Session, error) {
	id, secret, err := parseToken(token)
	if err != nil {
		return Session{}, err
	}

	record, err := store.queries.GetSession(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrInvalidSession
	}
	if err != nil {
		return Session{}, fmt.Errorf("get session: %w", err)
	}

	expected := hashSecret(store.rootSecret, secret, kind)
	if subtle.ConstantTimeCompare(expected, record.SecretHash) != 1 {
		return Session{}, ErrInvalidSession
	}
	if Kind(record.Kind) != kind {
		return Session{}, ErrInvalidSession
	}

	expiresAt, err := clock.Parse(record.ExpiresAt)
	if err != nil {
		return Session{}, fmt.Errorf("parse session expiration: %w", err)
	}
	if !now.Before(expiresAt) {
		// The row can never become valid again; delete it opportunistically.
		_ = store.queries.RevokeSession(ctx, id)
		return Session{}, ErrExpiredSession
	}

	createdAt, err := clock.Parse(record.CreatedAt)
	if err != nil {
		return Session{}, fmt.Errorf("parse session creation: %w", err)
	}

	return Session{
		ID:        record.ID,
		Kind:      Kind(record.Kind),
		Subject:   record.Sub,
		TOTPRev:   uint64(record.TotpRev),
		CreatedAt: createdAt,
		ExpiresAt: expiresAt,
	}, nil
}

// ValidateID validates the active user-session record identified by id at
// the given instant and returns it. Unlike Validate it does not authenticate
// a browser credential: it is the record-side check for callers that only
// hold the session identifier, such as the jti binding of an access token.
// Administrator records are rejected.
//
// The record must exist and its absolute expiration must not have passed.
// A missing record maps to ErrInvalidSession, and an expired record is
// deleted opportunistically and maps to ErrExpiredSession.
func (store *Store) ValidateID(ctx context.Context, id string, now time.Time) (Session, error) {
	if id == "" {
		return Session{}, errors.New("session id must not be empty")
	}

	record, err := store.queries.GetSession(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrInvalidSession
	}
	if err != nil {
		return Session{}, fmt.Errorf("get session: %w", err)
	}

	if Kind(record.Kind) != KindUser {
		return Session{}, ErrInvalidSession
	}

	expiresAt, err := clock.Parse(record.ExpiresAt)
	if err != nil {
		return Session{}, fmt.Errorf("parse session expiration: %w", err)
	}
	if !now.Before(expiresAt) {
		// The row can never become valid again; delete it opportunistically.
		_ = store.queries.RevokeSession(ctx, id)
		return Session{}, ErrExpiredSession
	}

	createdAt, err := clock.Parse(record.CreatedAt)
	if err != nil {
		return Session{}, fmt.Errorf("parse session creation: %w", err)
	}

	return Session{
		ID:        record.ID,
		Kind:      Kind(record.Kind),
		Subject:   record.Sub,
		TOTPRev:   uint64(record.TotpRev),
		CreatedAt: createdAt,
		ExpiresAt: expiresAt,
	}, nil
}

// Revoke deletes the session identified by the browser token. Revoking an
// unknown token is not an error, so logout always succeeds.
func (store *Store) Revoke(ctx context.Context, token string) error {
	id, _, err := parseToken(token)
	if err != nil {
		return err
	}
	if err := store.queries.RevokeSession(ctx, id); err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	return nil
}

// RevokeAllForSubject deletes every active session of one subject. It is the
// revocation primitive behind administrative and panic lock actions.
func (store *Store) RevokeAllForSubject(ctx context.Context, sub string) error {
	if err := store.queries.RevokeSessionsBySubject(ctx, sub); err != nil {
		return fmt.Errorf("revoke sessions for subject: %w", err)
	}
	return nil
}

// nullString maps an empty value to SQL NULL.
func nullString(value string) sql.NullString {
	if value == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: value, Valid: true}
}
