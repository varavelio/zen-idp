package onetoken

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

// pkceMethodS256 is the only PKCE method Zen IdP supports.
const pkceMethodS256 = "S256"

// tokenQueries is the SQLite-backed one-use token persistence the store
// needs, satisfied by statestore.Queries. It is defined consumer-side so the
// store never depends on a concrete persistence implementation.
type tokenQueries interface {
	CreateOneUseToken(context.Context, statestore.CreateOneUseTokenParams) error
	GetOneUseToken(context.Context, string) (statestore.OneUseToken, error)
	ConsumeOneUseToken(context.Context, statestore.ConsumeOneUseTokenParams) (int64, error)
	DeleteOneUseToken(context.Context, string) error
	DeleteExpiredOneUseTokens(context.Context, string) (int64, error)
}

// idGenerator creates the opaque record identifiers embedded in tokens,
// satisfied by id.IDGenerator.
type idGenerator interface {
	NewID(context.Context) string
}

// Store owns the one-use token lifecycle: creation with its bindings, atomic
// single redemption, and expiry-based cleanup.
type Store struct {
	queries    tokenQueries
	ids        idGenerator
	rootSecret [sha256.Size]byte
}

// NewStore returns a store that persists tokens through queries, assigns
// identifiers with ids, and digests token secrets with the normalized root
// secret.
func NewStore(
	queries tokenQueries,
	ids idGenerator,
	rootSecret [sha256.Size]byte,
) (*Store, error) {
	if queries == nil {
		return nil, errors.New("one-use token queries are nil")
	}
	if ids == nil {
		return nil, errors.New("one-use token id generator is nil")
	}
	return &Store{
		queries:    queries,
		ids:        ids,
		rootSecret: rootSecret,
	}, nil
}

// EnrollmentParams carries the bindings recorded for a new enrollment token.
type EnrollmentParams struct {
	// Subject is the exact configured sub the token is bound to.
	Subject string
	// TOTPRev is the user's current TOTP revision at creation time.
	TOTPRev uint64
	// ExpiresAt is the absolute redemption deadline. It must be in the
	// future at creation time.
	ExpiresAt time.Time
	// Now is the creation instant, in UTC.
	Now time.Time
}

// CreateEnrollment records a new one-use enrollment token bound to the given
// subject and TOTP revision and returns its redeemable token, formatted
// tok_{id}_{secret}. The token is the only value that can later redeem it;
// the secret half is persisted only as a domain-separated HMAC-SHA-256
// digest.
func (store *Store) CreateEnrollment(ctx context.Context, params EnrollmentParams) (string, error) {
	if params.Subject == "" {
		return "", errors.New("enrollment subject must not be empty")
	}
	if !params.ExpiresAt.After(params.Now) {
		return "", errors.New("enrollment expiration must be in the future")
	}
	return store.create(
		ctx,
		params.Subject,
		params.TOTPRev,
		params.ExpiresAt,
		params.Now,
		kindEnrollment,
		codeBindings{},
	)
}

// ConsumeEnrollment authenticates an enrollment token at the given instant
// and atomically redeems it, returning its bindings. The token must match
// the tok_{id}_{secret} format, its record must exist, its secret must match
// the stored digest, the absolute expiration must not have passed, and the
// record must be an enrollment token rather than an authorization code.
func (store *Store) ConsumeEnrollment(
	ctx context.Context,
	token string,
	now time.Time,
) (Enrollment, error) {
	record, err := store.consume(ctx, token, now, kindEnrollment)
	if err != nil {
		return Enrollment{}, err
	}
	expiresAt, err := clock.Parse(record.ExpiresAt)
	if err != nil {
		return Enrollment{}, fmt.Errorf("parse one-use token expiration: %w", err)
	}
	return Enrollment{
		ID:        record.ID,
		Subject:   record.Sub,
		TOTPRev:   uint64(record.TotpRev),
		ExpiresAt: expiresAt,
	}, nil
}

// CodeParams carries every authorization-code binding recorded at issuance.
type CodeParams struct {
	// Subject is the authenticated subject the code is bound to.
	Subject string
	// TOTPRev is the authenticated TOTP revision at issuance.
	TOTPRev uint64
	// ClientID is the OIDC client the code is issued to.
	ClientID string
	// RedirectURI is the exact redirect URI the code is issued for.
	RedirectURI string
	// Scope is the scope string accepted in the authorization request.
	Scope string
	// Nonce is the request nonce, empty when the request carried none.
	Nonce string
	// PKCEChallenge is the S256 challenge the code is bound to. PKCE is
	// optional: either both PKCEChallenge and PKCEMethod are empty, or both
	// are present with method "S256".
	PKCEChallenge string
	// PKCEMethod is the PKCE method, "S256" when PKCE was used.
	PKCEMethod string
	// ExpiresAt is the absolute redemption deadline. It must be in the
	// future at creation time.
	ExpiresAt time.Time
	// Now is the issuance instant, in UTC.
	Now time.Time
}

// CreateCode records a new one-use authorization code carrying every binding
// of the accepted authorization request and returns its redeemable token,
// formatted tok_{id}_{secret}. The secret half is persisted only as a
// domain-separated HMAC-SHA-256 digest.
func (store *Store) CreateCode(ctx context.Context, params CodeParams) (string, error) {
	if params.Subject == "" {
		return "", errors.New("code subject must not be empty")
	}
	if params.ClientID == "" {
		return "", errors.New("code client id must not be empty")
	}
	if params.RedirectURI == "" {
		return "", errors.New("code redirect uri must not be empty")
	}
	if params.Scope == "" {
		return "", errors.New("code scope must not be empty")
	}
	if err := validatePKCE(params.PKCEChallenge, params.PKCEMethod); err != nil {
		return "", err
	}
	if !params.ExpiresAt.After(params.Now) {
		return "", errors.New("code expiration must be in the future")
	}
	return store.create(
		ctx,
		params.Subject,
		params.TOTPRev,
		params.ExpiresAt,
		params.Now,
		kindCode,
		codeBindings{
			clientID:      params.ClientID,
			redirectURI:   params.RedirectURI,
			scope:         params.Scope,
			nonce:         params.Nonce,
			pkceChallenge: params.PKCEChallenge,
			pkceMethod:    params.PKCEMethod,
		},
	)
}

// ConsumeCode authenticates an authorization code at the given instant and
// atomically redeems it, returning its bindings. The token must match the
// tok_{id}_{secret} format, its record must exist, its secret must match the
// stored digest, the absolute expiration must not have passed, and the
// record must be an authorization code rather than an enrollment token.
func (store *Store) ConsumeCode(ctx context.Context, token string, now time.Time) (Code, error) {
	record, err := store.consume(ctx, token, now, kindCode)
	if err != nil {
		return Code{}, err
	}
	expiresAt, err := clock.Parse(record.ExpiresAt)
	if err != nil {
		return Code{}, fmt.Errorf("parse one-use token expiration: %w", err)
	}
	return Code{
		ID:            record.ID,
		Subject:       record.Sub,
		TOTPRev:       uint64(record.TotpRev),
		ClientID:      record.CodeClientID.String,
		RedirectURI:   record.CodeRedirectUri.String,
		Scope:         record.CodeScope.String,
		Nonce:         record.CodeNonce.String,
		PKCEChallenge: record.CodePkceChallenge.String,
		PKCEMethod:    record.CodePkceMethod.String,
		ExpiresAt:     expiresAt,
	}, nil
}

// PurgeExpired deletes every token row whose absolute expiration has passed
// at the given instant and returns how many rows were removed. It keeps the
// one_use_tokens table bounded over time.
func (store *Store) PurgeExpired(ctx context.Context, now time.Time) (int64, error) {
	deleted, err := store.queries.DeleteExpiredOneUseTokens(ctx, clock.Format(now))
	if err != nil {
		return 0, fmt.Errorf("purge expired one-use tokens: %w", err)
	}
	return deleted, nil
}

// codeBindings are the authorization-code columns of a one-use token row;
// the zero value records an enrollment token.
type codeBindings struct {
	clientID      string
	redirectURI   string
	scope         string
	nonce         string
	pkceChallenge string
	pkceMethod    string
}

// create records a new one-use token of the given kind with its bindings
// and returns its redeemable token.
func (store *Store) create(
	ctx context.Context,
	subject string,
	totpRev uint64,
	expiresAt, now time.Time,
	kind string,
	bindings codeBindings,
) (string, error) {
	secret, err := crypto.GenerateMachineSecret()
	if err != nil {
		return "", fmt.Errorf("generate one-use token secret: %w", err)
	}

	id := store.ids.NewID(ctx)
	err = store.queries.CreateOneUseToken(ctx, statestore.CreateOneUseTokenParams{
		ID:                id,
		Kind:              kind,
		SecretHash:        hashSecret(store.rootSecret, kind, secret),
		Sub:               subject,
		TotpRev:           int64(totpRev),
		ExpiresAt:         clock.Format(expiresAt),
		CreatedAt:         clock.Format(now),
		CodeClientID:      nullString(bindings.clientID),
		CodeRedirectUri:   nullString(bindings.redirectURI),
		CodeScope:         nullString(bindings.scope),
		CodeNonce:         nullString(bindings.nonce),
		CodePkceChallenge: nullString(bindings.pkceChallenge),
		CodePkceMethod:    nullString(bindings.pkceMethod),
	})
	if err != nil {
		return "", fmt.Errorf("create one-use token: %w", err)
	}

	return formatToken(id, secret), nil
}

// consume authenticates a token at the given instant, atomically redeems it,
// and returns its authoritative record. wantKind selects the expected record
// kind: kindCode for authorization codes, kindEnrollment for enrollment
// tokens.
func (store *Store) consume(
	ctx context.Context,
	token string,
	now time.Time,
	wantKind string,
) (statestore.OneUseToken, error) {
	id, secret, err := parseToken(token)
	if err != nil {
		return statestore.OneUseToken{}, err
	}

	record, err := store.queries.GetOneUseToken(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return statestore.OneUseToken{}, ErrInvalidToken
	}
	if err != nil {
		return statestore.OneUseToken{}, fmt.Errorf("get one-use token: %w", err)
	}

	expected := hashSecret(store.rootSecret, wantKind, secret)
	if subtle.ConstantTimeCompare(expected, record.SecretHash) != 1 {
		return statestore.OneUseToken{}, ErrInvalidToken
	}

	expiresAt, err := clock.Parse(record.ExpiresAt)
	if err != nil {
		return statestore.OneUseToken{}, fmt.Errorf("parse one-use token expiration: %w", err)
	}
	if !now.Before(expiresAt) {
		// The row can never become valid again; delete it opportunistically.
		_ = store.queries.DeleteOneUseToken(ctx, id)
		return statestore.OneUseToken{}, ErrExpiredToken
	}

	// A record's kind decides which flow may redeem it; redeeming a token
	// through the wrong flow fails without consuming it.
	if record.Kind != wantKind {
		return statestore.OneUseToken{}, ErrInvalidToken
	}

	affected, err := store.queries.ConsumeOneUseToken(ctx, statestore.ConsumeOneUseTokenParams{
		ID:         id,
		ConsumedAt: nullString(clock.Format(now)),
	})
	if err != nil {
		return statestore.OneUseToken{}, fmt.Errorf("consume one-use token: %w", err)
	}
	if affected != 1 {
		// The row was consumed concurrently between the read and the
		// update; the atomic update won exactly once.
		return statestore.OneUseToken{}, ErrInvalidToken
	}

	return record, nil
}

// validatePKCE requires PKCE parameters to be supplied as a complete S256
// pair or not at all.
func validatePKCE(challenge, method string) error {
	if challenge == "" && method == "" {
		return nil
	}
	if challenge == "" || method == "" {
		return errors.New("PKCE challenge and method must be supplied together")
	}
	if method != pkceMethodS256 {
		return fmt.Errorf("unsupported PKCE method %q", method)
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
