package onetoken

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/varavelio/zen-idp/internal/clock"
	"github.com/varavelio/zen-idp/internal/id"
	"github.com/varavelio/zen-idp/internal/statestore"
)

const (
	testSubject     = "dev-01"
	testTOTPRev     = uint64(2)
	testClientID    = "web-app"
	testRedirectURI = "https://app.example.com/callback"
	testScope       = "openid profile"
	testNonce       = "n-0S6_WzA2Mj"
	// testPKCEChallenge is the RFC 7636 example S256 challenge.
	testPKCEChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

// testNow is the fixed instant used as the creation time in lifecycle tests.
var testNow = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

// newTestDB returns a migrated temporary SQLite database.
func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := statestore.Connect(context.Background(), path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	require.NoError(t, statestore.Migrate(context.Background(), db))
	return db
}

// newTestStore returns a store backed by a migrated temporary SQLite
// database, the anchored reference root secret, and its sqlc queries.
func newTestStore(t *testing.T) (*Store, *statestore.Queries) {
	t.Helper()
	queries := statestore.New(newTestDB(t))
	store, err := NewStore(queries, id.NewIDGenerator(), referenceRootSecret)
	require.NoError(t, err)
	return store, queries
}

// createEnrollmentToken records an enrollment token for the test identity at
// testNow and returns its redeemable token.
func createEnrollmentToken(t *testing.T, store *Store) string {
	t.Helper()
	token, err := store.CreateEnrollment(context.Background(), EnrollmentParams{
		Subject:   testSubject,
		TOTPRev:   testTOTPRev,
		ExpiresAt: testNow.Add(15 * time.Minute),
		Now:       testNow,
	})
	require.NoError(t, err)
	return token
}

// createCode records an authorization code for the test identity at testNow
// and returns its redeemable token.
func createCode(t *testing.T, store *Store) string {
	t.Helper()
	token, err := store.CreateCode(context.Background(), codeParams())
	require.NoError(t, err)
	return token
}

// splitToken returns the id and secret halves of a redeemable token.
func splitToken(t *testing.T, token string) (id, secret string) {
	t.Helper()
	parts := strings.Split(token, "_")
	require.Len(t, parts, 3)
	require.Equal(t, "tok", parts[0])
	require.NotEmpty(t, parts[1])
	require.NotEmpty(t, parts[2])
	return parts[1], parts[2]
}

func TestNewStore(t *testing.T) {
	queries := statestore.New(newTestDB(t))
	ids := id.NewIDGenerator()

	t.Run("rejects nil queries", func(t *testing.T) {
		store, err := NewStore(nil, ids, referenceRootSecret)
		require.Nil(t, store)
		require.EqualError(t, err, "one-use token queries are nil")
	})

	t.Run("rejects nil id generator", func(t *testing.T) {
		store, err := NewStore(queries, nil, referenceRootSecret)
		require.Nil(t, store)
		require.EqualError(t, err, "one-use token id generator is nil")
	})

	t.Run("returns a working store", func(t *testing.T) {
		store, err := NewStore(queries, ids, referenceRootSecret)
		require.NoError(t, err)
		require.NotNil(t, store)
	})
}

func TestCreateEnrollment(t *testing.T) {
	t.Run("persists the bindings and only the secret digest", func(t *testing.T) {
		store, queries := newTestStore(t)
		token := createEnrollmentToken(t, store)
		id, secret := splitToken(t, token)

		record, err := queries.GetOneUseToken(context.Background(), id)
		require.NoError(t, err)
		require.Equal(t, kindEnrollment, record.Kind)
		require.Equal(t, testSubject, record.Sub)
		require.Equal(t, int64(testTOTPRev), record.TotpRev)
		require.Equal(t, clock.Format(testNow.Add(15*time.Minute)), record.ExpiresAt)
		require.Equal(t, clock.Format(testNow), record.CreatedAt)
		require.False(t, record.ConsumedAt.Valid)
		require.False(t, record.CodeClientID.Valid, "enrollment tokens carry no client bindings")
		require.Equal(t,
			hex.EncodeToString(hashSecret(referenceRootSecret, kindEnrollment, secret)),
			hex.EncodeToString(record.SecretHash),
		)
	})

	t.Run("rejects an empty subject", func(t *testing.T) {
		store, _ := newTestStore(t)
		token, err := store.CreateEnrollment(context.Background(), EnrollmentParams{
			Subject:   "",
			TOTPRev:   testTOTPRev,
			ExpiresAt: testNow.Add(15 * time.Minute),
			Now:       testNow,
		})
		require.Empty(t, token)
		require.EqualError(t, err, "enrollment subject must not be empty")
	})

	t.Run("rejects a non-future expiration", func(t *testing.T) {
		store, _ := newTestStore(t)
		params := EnrollmentParams{
			Subject:   testSubject,
			TOTPRev:   testTOTPRev,
			ExpiresAt: testNow.Add(15 * time.Minute),
			Now:       testNow,
		}

		params.ExpiresAt = testNow
		token, err := store.CreateEnrollment(context.Background(), params)
		require.Empty(t, token)
		require.EqualError(t, err, "enrollment expiration must be in the future")

		params.ExpiresAt = testNow.Add(-time.Minute)
		token, err = store.CreateEnrollment(context.Background(), params)
		require.Empty(t, token)
		require.EqualError(t, err, "enrollment expiration must be in the future")
	})
}

func TestConsumeEnrollment(t *testing.T) {
	t.Run("redeems a valid token exactly once", func(t *testing.T) {
		store, queries := newTestStore(t)
		token := createEnrollmentToken(t, store)
		id, _ := splitToken(t, token)

		enrollment, err := store.ConsumeEnrollment(
			context.Background(),
			token,
			testNow.Add(time.Minute),
		)
		require.NoError(t, err)
		require.Equal(t, id, enrollment.ID)
		require.Equal(t, testSubject, enrollment.Subject)
		require.Equal(t, testTOTPRev, enrollment.TOTPRev)
		require.Equal(t, testNow.Add(15*time.Minute), enrollment.ExpiresAt)

		record, err := queries.GetOneUseToken(context.Background(), id)
		require.NoError(t, err)
		require.True(t, record.ConsumedAt.Valid)
		require.Equal(t, clock.Format(testNow.Add(time.Minute)), record.ConsumedAt.String)

		_, err = store.ConsumeEnrollment(context.Background(), token, testNow.Add(2*time.Minute))
		require.ErrorIs(t, err, ErrInvalidToken)
	})

	t.Run("rejects an expired token and deletes its row", func(t *testing.T) {
		store, queries := newTestStore(t)
		token := createEnrollmentToken(t, store)
		id, _ := splitToken(t, token)

		_, err := store.ConsumeEnrollment(
			context.Background(),
			token,
			testNow.Add(15*time.Minute+time.Second),
		)
		require.ErrorIs(t, err, ErrExpiredToken)

		_, err = queries.GetOneUseToken(context.Background(), id)
		require.ErrorIs(t, err, sql.ErrNoRows)
	})

	t.Run("rejects a tampered secret", func(t *testing.T) {
		store, _ := newTestStore(t)
		token := createEnrollmentToken(t, store)
		id, secret := splitToken(t, token)

		_, err := store.ConsumeEnrollment(
			context.Background(),
			formatToken(id, secret+"x"),
			testNow.Add(time.Minute),
		)
		require.ErrorIs(t, err, ErrInvalidToken)
	})

	t.Run("rejects an unknown record", func(t *testing.T) {
		store, _ := newTestStore(t)
		_, err := store.ConsumeEnrollment(
			context.Background(),
			formatToken("01h2v8d9q3m5t7w0x2y4a6c8e", "aZ9kM2pQ7sW4xR8vT3nB6cD1fG5hJ0kL9mN2pQ4s"),
			testNow.Add(time.Minute),
		)
		require.ErrorIs(t, err, ErrInvalidToken)
	})

	t.Run("rejects a malformed token", func(t *testing.T) {
		store, _ := newTestStore(t)
		_, err := store.ConsumeEnrollment(
			context.Background(),
			"sess_01h2v8d9q3m5t7w0x2y4a6c8e_secret",
			testNow,
		)
		require.ErrorIs(t, err, ErrMalformedToken)
	})

	t.Run("rejects an authorization code without consuming it", func(t *testing.T) {
		store, _ := newTestStore(t)
		code := createCode(t, store)

		_, err := store.ConsumeEnrollment(context.Background(), code, testNow.Add(time.Minute))
		require.ErrorIs(t, err, ErrInvalidToken)

		redeemed, err := store.ConsumeCode(context.Background(), code, testNow.Add(time.Minute))
		require.NoError(t, err)
		require.Equal(t, testClientID, redeemed.ClientID)
	})
}

func TestCreateCode(t *testing.T) {
	t.Run("persists every binding", func(t *testing.T) {
		store, queries := newTestStore(t)
		token := createCode(t, store)
		id, _ := splitToken(t, token)

		record, err := queries.GetOneUseToken(context.Background(), id)
		require.NoError(t, err)
		require.Equal(t, kindCode, record.Kind)
		require.Equal(t, testSubject, record.Sub)
		require.Equal(t, int64(testTOTPRev), record.TotpRev)
		require.Equal(t, testClientID, record.CodeClientID.String)
		require.Equal(t, testRedirectURI, record.CodeRedirectUri.String)
		require.Equal(t, testScope, record.CodeScope.String)
		require.Equal(t, testNonce, record.CodeNonce.String)
		require.Equal(t, clock.Format(testNow.Add(-2*time.Hour)), record.CodeAuthTime.String)
		require.False(t, record.CodePkceChallenge.Valid, "no PKCE bindings were requested")
		require.False(t, record.CodePkceMethod.Valid)
	})

	t.Run("rejects a zero authentication time", func(t *testing.T) {
		store, _ := newTestStore(t)
		params := codeParams()
		params.AuthTime = time.Time{}

		_, err := store.CreateCode(context.Background(), params)

		require.ErrorContains(t, err, "auth time")
	})

	t.Run("persists PKCE bindings when supplied", func(t *testing.T) {
		store, queries := newTestStore(t)
		params := codeParams()
		params.PKCEChallenge = testPKCEChallenge
		params.PKCEMethod = "S256"

		token, err := store.CreateCode(context.Background(), params)
		require.NoError(t, err)
		id, _ := splitToken(t, token)

		record, err := queries.GetOneUseToken(context.Background(), id)
		require.NoError(t, err)
		require.Equal(t, testPKCEChallenge, record.CodePkceChallenge.String)
		require.Equal(t, "S256", record.CodePkceMethod.String)
	})

	t.Run("rejects an empty subject", func(t *testing.T) {
		store, _ := newTestStore(t)
		params := codeParams()
		params.Subject = ""
		token, err := store.CreateCode(context.Background(), params)
		require.Empty(t, token)
		require.EqualError(t, err, "code subject must not be empty")
	})

	t.Run("rejects an empty client id", func(t *testing.T) {
		store, _ := newTestStore(t)
		params := codeParams()
		params.ClientID = ""
		token, err := store.CreateCode(context.Background(), params)
		require.Empty(t, token)
		require.EqualError(t, err, "code client id must not be empty")
	})

	t.Run("rejects an empty redirect uri", func(t *testing.T) {
		store, _ := newTestStore(t)
		params := codeParams()
		params.RedirectURI = ""
		token, err := store.CreateCode(context.Background(), params)
		require.Empty(t, token)
		require.EqualError(t, err, "code redirect uri must not be empty")
	})

	t.Run("rejects an empty scope", func(t *testing.T) {
		store, _ := newTestStore(t)
		params := codeParams()
		params.Scope = ""
		token, err := store.CreateCode(context.Background(), params)
		require.Empty(t, token)
		require.EqualError(t, err, "code scope must not be empty")
	})

	t.Run("rejects a non-future expiration", func(t *testing.T) {
		store, _ := newTestStore(t)
		params := codeParams()
		params.ExpiresAt = testNow
		token, err := store.CreateCode(context.Background(), params)
		require.Empty(t, token)
		require.EqualError(t, err, "code expiration must be in the future")
	})

	t.Run("accepts PKCE only as a complete S256 pair", func(t *testing.T) {
		store, _ := newTestStore(t)

		params := codeParams()
		params.PKCEChallenge = testPKCEChallenge
		token, err := store.CreateCode(context.Background(), params)
		require.Empty(t, token)
		require.EqualError(t, err, "PKCE challenge and method must be supplied together")

		params = codeParams()
		params.PKCEMethod = "S256"
		token, err = store.CreateCode(context.Background(), params)
		require.Empty(t, token)
		require.EqualError(t, err, "PKCE challenge and method must be supplied together")

		params = codeParams()
		params.PKCEChallenge = testPKCEChallenge
		params.PKCEMethod = "plain"
		token, err = store.CreateCode(context.Background(), params)
		require.Empty(t, token)
		require.EqualError(t, err, `unsupported PKCE method "plain"`)
	})
}

func TestConsumeCode(t *testing.T) {
	t.Run("redeems a valid code and returns every binding", func(t *testing.T) {
		store, _ := newTestStore(t)
		token := createCode(t, store)
		id, _ := splitToken(t, token)

		code, err := store.ConsumeCode(context.Background(), token, testNow.Add(time.Minute))
		require.NoError(t, err)
		require.Equal(t, id, code.ID)
		require.Equal(t, testSubject, code.Subject)
		require.Equal(t, testTOTPRev, code.TOTPRev)
		require.Equal(t, testClientID, code.ClientID)
		require.Equal(t, testRedirectURI, code.RedirectURI)
		require.Equal(t, testScope, code.Scope)
		require.Equal(t, testNonce, code.Nonce)
		require.Empty(t, code.PKCEChallenge)
		require.Empty(t, code.PKCEMethod)
		require.Equal(t, testNow.Add(5*time.Minute), code.ExpiresAt)
	})

	t.Run("redeems a PKCE-bound code preserving the challenge", func(t *testing.T) {
		store, _ := newTestStore(t)
		params := codeParams()
		params.PKCEChallenge = testPKCEChallenge
		params.PKCEMethod = "S256"
		token, err := store.CreateCode(context.Background(), params)
		require.NoError(t, err)

		code, err := store.ConsumeCode(context.Background(), token, testNow.Add(time.Minute))
		require.NoError(t, err)
		require.Equal(t, testPKCEChallenge, code.PKCEChallenge)
		require.Equal(t, "S256", code.PKCEMethod)
	})

	t.Run("redeems a code without a nonce", func(t *testing.T) {
		store, _ := newTestStore(t)
		params := codeParams()
		params.Nonce = ""
		token, err := store.CreateCode(context.Background(), params)
		require.NoError(t, err)

		code, err := store.ConsumeCode(context.Background(), token, testNow.Add(time.Minute))
		require.NoError(t, err)
		require.Empty(t, code.Nonce)
	})

	t.Run("redeems a valid code exactly once", func(t *testing.T) {
		store, _ := newTestStore(t)
		token := createCode(t, store)

		_, err := store.ConsumeCode(context.Background(), token, testNow.Add(time.Minute))
		require.NoError(t, err)

		_, err = store.ConsumeCode(context.Background(), token, testNow.Add(2*time.Minute))
		require.ErrorIs(t, err, ErrInvalidToken)
	})

	t.Run("rejects an expired code", func(t *testing.T) {
		store, _ := newTestStore(t)
		token := createCode(t, store)

		_, err := store.ConsumeCode(
			context.Background(),
			token,
			testNow.Add(5*time.Minute+time.Second),
		)
		require.ErrorIs(t, err, ErrExpiredToken)
	})

	t.Run("rejects an enrollment token without consuming it", func(t *testing.T) {
		store, _ := newTestStore(t)
		enrollment := createEnrollmentToken(t, store)

		_, err := store.ConsumeCode(context.Background(), enrollment, testNow.Add(time.Minute))
		require.ErrorIs(t, err, ErrInvalidToken)

		redeemed, err := store.ConsumeEnrollment(
			context.Background(),
			enrollment,
			testNow.Add(time.Minute),
		)
		require.NoError(t, err)
		require.Equal(t, testSubject, redeemed.Subject)
	})
}

func TestConcurrentConsumeCode(t *testing.T) {
	t.Run("redeems exactly one of many concurrent attempts", func(t *testing.T) {
		store, _ := newTestStore(t)
		token := createCode(t, store)

		const attempts = 32
		results := make(chan error, attempts)
		var group sync.WaitGroup
		for range attempts {
			group.Go(func() {
				_, err := store.ConsumeCode(context.Background(), token, testNow.Add(time.Minute))
				results <- err
			})
		}
		group.Wait()
		close(results)

		var succeeded int
		for err := range results {
			if err == nil {
				succeeded++
			} else {
				require.ErrorIs(t, err, ErrInvalidToken)
			}
		}
		require.Equal(t, 1, succeeded)
	})
}

func TestPurgeExpired(t *testing.T) {
	t.Run("removes only expired rows and reports the count", func(t *testing.T) {
		store, queries := newTestStore(t)

		expiredEnrollment := createEnrollmentToken(t, store)
		expiredCode := createCode(t, store)
		_, expiredEnrollmentID := splitToken(t, expiredEnrollment)
		_, expiredCodeID := splitToken(t, expiredCode)

		// Advance the clock past every created token's expiration.
		deleted, err := store.PurgeExpired(context.Background(), testNow.Add(time.Hour))
		require.NoError(t, err)
		require.Equal(t, int64(2), deleted)

		_, err = queries.GetOneUseToken(context.Background(), expiredEnrollmentID)
		require.ErrorIs(t, err, sql.ErrNoRows)
		_, err = queries.GetOneUseToken(context.Background(), expiredCodeID)
		require.ErrorIs(t, err, sql.ErrNoRows)

		// A token still inside its window survives the purge.
		params := codeParams()
		params.ExpiresAt = testNow.Add(time.Hour)
		token, err := store.CreateCode(context.Background(), params)
		require.NoError(t, err)
		id, _ := splitToken(t, token)

		deleted, err = store.PurgeExpired(context.Background(), testNow.Add(30*time.Minute))
		require.NoError(t, err)
		require.Equal(t, int64(0), deleted)

		_, err = queries.GetOneUseToken(context.Background(), id)
		require.NoError(t, err)
	})
}

// TestSchemaEnforcesKindConsistency anchors the table-level CHECK that
// guarantees every row's kind matches its bindings, the invariant the store
// relies on when it rejects cross-flow redemption.
func TestSchemaEnforcesKindConsistency(t *testing.T) {
	db := newTestDB(t)
	var sequence int
	insert := func(kind string, clientID sql.NullString) error {
		sequence++
		_, err := db.ExecContext(context.Background(), `
			INSERT INTO one_use_tokens (
				id, kind, secret_hash, sub, totp_rev, expires_at, created_at, code_client_id
			) VALUES (?, ?, X'00', ?, 0, ?, ?, ?)
		`,
			fmt.Sprintf("check-%d", sequence),
			kind,
			testSubject,
			clock.Format(testNow.Add(time.Minute)),
			clock.Format(testNow),
			clientID,
		)
		return err
	}

	t.Run("rejects an enrollment token with client bindings", func(t *testing.T) {
		err := insert(kindEnrollment, sql.NullString{String: testClientID, Valid: true})
		require.Error(t, err)
	})

	t.Run("rejects a code without client bindings", func(t *testing.T) {
		err := insert(kindCode, sql.NullString{})
		require.Error(t, err)
	})

	t.Run("rejects an unknown kind", func(t *testing.T) {
		err := insert("other", sql.NullString{})
		require.Error(t, err)
	})

	t.Run("accepts consistent rows", func(t *testing.T) {
		require.NoError(t, insert(kindEnrollment, sql.NullString{}))
		require.NoError(t, insert(kindCode, sql.NullString{String: testClientID, Valid: true}))
	})
}

// codeParams returns valid authorization-code parameters for the test
// identity at testNow.
func codeParams() CodeParams {
	return CodeParams{
		Subject:     testSubject,
		TOTPRev:     testTOTPRev,
		ClientID:    testClientID,
		RedirectURI: testRedirectURI,
		Scope:       testScope,
		Nonce:       testNonce,
		AuthTime:    testNow.Add(-2 * time.Hour),
		ExpiresAt:   testNow.Add(5 * time.Minute),
		Now:         testNow,
	}
}
