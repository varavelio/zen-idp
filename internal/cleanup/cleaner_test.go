package cleanup

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/varavelio/zen-idp/internal/audit"
	"github.com/varavelio/zen-idp/internal/clock"
	"github.com/varavelio/zen-idp/internal/id"
	"github.com/varavelio/zen-idp/internal/onetoken"
	"github.com/varavelio/zen-idp/internal/ratelimit"
	"github.com/varavelio/zen-idp/internal/session"
	"github.com/varavelio/zen-idp/internal/statestore"
)

// testNow is the fixed instant used as the reference time in cleanup tests.
var testNow = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

// testRetention is the audit retention used in cleanup tests.
const testRetention = 30 * 24 * time.Hour

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

// newTestCleaner returns a cleaner wired to every domain purger over the
// same migrated temporary SQLite database and its sqlc queries.
func newTestCleaner(t *testing.T) (*Cleaner, *statestore.Queries) {
	t.Helper()
	queries := statestore.New(newTestDB(t))
	rateLimiter, err := ratelimit.New(queries, 3, 5*time.Minute)
	require.NoError(t, err)
	codeStore, err := onetoken.NewStore(queries, id.NewIDGenerator(), testRootSecret)
	require.NoError(t, err)
	sessionStore, err := session.NewStore(
		queries,
		id.NewIDGenerator(),
		testRootSecret,
		72*time.Hour,
	)
	require.NoError(t, err)
	recorder, err := audit.NewRecorder(queries, id.NewIDGenerator())
	require.NoError(t, err)
	cleaner, err := New(rateLimiter, codeStore, sessionStore, recorder, testRetention)
	require.NoError(t, err)
	return cleaner, queries
}

func TestNew(t *testing.T) {
	t.Run("rejects nil rate limit purger", func(t *testing.T) {
		_, err := New(nil, stubPurger{}, stubPurger{}, stubPurger{}, testRetention)
		require.Error(t, err)
	})

	t.Run("rejects nil token purger", func(t *testing.T) {
		_, err := New(stubPurger{}, nil, stubPurger{}, stubPurger{}, testRetention)
		require.Error(t, err)
	})

	t.Run("rejects nil session purger", func(t *testing.T) {
		_, err := New(stubPurger{}, stubPurger{}, nil, stubPurger{}, testRetention)
		require.Error(t, err)
	})

	t.Run("rejects nil audit purger", func(t *testing.T) {
		_, err := New(stubPurger{}, stubPurger{}, stubPurger{}, nil, testRetention)
		require.Error(t, err)
	})

	t.Run("rejects negative audit retention", func(t *testing.T) {
		_, err := New(stubPurger{}, stubPurger{}, stubPurger{}, stubPurger{}, -time.Second)
		require.Error(t, err)
	})

	t.Run("accepts zero audit retention", func(t *testing.T) {
		cleaner, err := New(stubPurger{}, stubPurger{}, stubPurger{}, stubPurger{}, 0)
		require.NoError(t, err)
		require.NotNil(t, cleaner)
	})
}

func TestClean(t *testing.T) {
	t.Run("purges every expired record kind and keeps active ones", func(t *testing.T) {
		cleaner, queries := newTestCleaner(t)
		ctx := context.Background()

		// Expired and active rate-limit counters.
		require.NoError(
			t,
			queries.RecordRateLimitAttempt(ctx, statestore.RecordRateLimitAttemptParams{
				Key:       "expired",
				ResetAt:   clock.Format(testNow.Add(-time.Minute)),
				UpdatedAt: clock.Format(testNow.Add(-2 * time.Minute)),
			}),
		)
		require.NoError(
			t,
			queries.RecordRateLimitAttempt(ctx, statestore.RecordRateLimitAttemptParams{
				Key:       "active",
				ResetAt:   clock.Format(testNow.Add(time.Hour)),
				UpdatedAt: clock.Format(testNow),
			}),
		)

		// Expired and active one-use tokens.
		require.NoError(t, queries.CreateOneUseToken(ctx, statestore.CreateOneUseTokenParams{
			ID:           "expired-token",
			Kind:         "code",
			SecretHash:   []byte("hash"),
			Sub:          "alice",
			ExpiresAt:    clock.Format(testNow.Add(-time.Minute)),
			CreatedAt:    clock.Format(testNow.Add(-time.Hour)),
			CodeClientID: sql.NullString{String: "web-app", Valid: true},
		}))
		require.NoError(t, queries.CreateOneUseToken(ctx, statestore.CreateOneUseTokenParams{
			ID:           "active-token",
			Kind:         "code",
			SecretHash:   []byte("hash"),
			Sub:          "alice",
			ExpiresAt:    clock.Format(testNow.Add(time.Hour)),
			CreatedAt:    clock.Format(testNow),
			CodeClientID: sql.NullString{String: "web-app", Valid: true},
		}))

		// Expired and active sessions.
		require.NoError(t, queries.CreateSession(ctx, statestore.CreateSessionParams{
			ID:         "expired-session",
			Kind:       "user",
			SecretHash: []byte("hash"),
			Sub:        "alice",
			CreatedAt:  clock.Format(testNow.Add(-2 * time.Hour)),
			ExpiresAt:  clock.Format(testNow.Add(-time.Minute)),
		}))
		require.NoError(t, queries.CreateSession(ctx, statestore.CreateSessionParams{
			ID:         "active-session",
			Kind:       "user",
			SecretHash: []byte("hash"),
			Sub:        "alice",
			CreatedAt:  clock.Format(testNow),
			ExpiresAt:  clock.Format(testNow.Add(time.Hour)),
		}))

		// Audit records older and newer than the retention.
		require.NoError(t, queries.CreateAuditRecord(ctx, statestore.CreateAuditRecordParams{
			ID:        "old-audit",
			CreatedAt: clock.Format(testNow.Add(-testRetention - time.Minute)),
			Category:  "lock_change",
			Details:   "{}",
		}))
		require.NoError(t, queries.CreateAuditRecord(ctx, statestore.CreateAuditRecordParams{
			ID:        "recent-audit",
			CreatedAt: clock.Format(testNow.Add(-time.Minute)),
			Category:  "lock_change",
			Details:   "{}",
		}))

		require.NoError(t, cleaner.Clean(ctx, testNow))

		_, err := queries.GetRateLimitCounter(ctx, "expired")
		require.ErrorIs(t, err, sql.ErrNoRows)
		_, err = queries.GetRateLimitCounter(ctx, "active")
		require.NoError(t, err)

		_, err = queries.GetOneUseToken(ctx, "expired-token")
		require.ErrorIs(t, err, sql.ErrNoRows)
		_, err = queries.GetOneUseToken(ctx, "active-token")
		require.NoError(t, err)

		_, err = queries.GetSession(ctx, "expired-session")
		require.ErrorIs(t, err, sql.ErrNoRows)
		_, err = queries.GetSession(ctx, "active-session")
		require.NoError(t, err)

		records, err := queries.ListAuditRecords(ctx, 10)
		require.NoError(t, err)
		require.Len(t, records, 1)
		require.Equal(t, "recent-audit", records[0].ID)
	})

	t.Run("keeps locks untouched", func(t *testing.T) {
		cleaner, queries := newTestCleaner(t)
		ctx := context.Background()

		require.NoError(t, queries.CreatePanicLock(ctx, statestore.CreatePanicLockParams{
			Sub:       "alice",
			CreatedAt: clock.Format(testNow.Add(-time.Hour)),
		}))
		require.NoError(t, queries.CreateAdminLock(ctx, statestore.CreateAdminLockParams{
			Sub:       "alice",
			CreatedAt: clock.Format(testNow.Add(-time.Hour)),
		}))

		require.NoError(t, cleaner.Clean(ctx, testNow))

		panicked, err := queries.GetPanicLock(ctx, "alice")
		require.NoError(t, err)
		require.Equal(t, "alice", panicked.Sub)
		adminLocked, err := queries.GetAdminLock(ctx, "alice")
		require.NoError(t, err)
		require.Equal(t, "alice", adminLocked.Sub)
	})

	t.Run("keeps audit records when retention is zero", func(t *testing.T) {
		ctx := context.Background()
		queries := statestore.New(newTestDB(t))
		cleaner, err := New(
			stubPurger{},
			stubPurger{},
			stubPurger{},
			&auditRecorderStub{queries: queries},
			0,
		)
		require.NoError(t, err)

		require.NoError(t, queries.CreateAuditRecord(ctx, statestore.CreateAuditRecordParams{
			ID:        "ancient-audit",
			CreatedAt: clock.Format(testNow.Add(-10 * 365 * 24 * time.Hour)),
			Category:  "lock_change",
			Details:   "{}",
		}))

		require.NoError(t, cleaner.Clean(context.Background(), testNow))

		records, err := queries.ListAuditRecords(context.Background(), 10)
		require.NoError(t, err)
		require.Len(t, records, 1)
	})

	t.Run("wraps the failing purge", func(t *testing.T) {
		cleaner, err := New(
			failingPurger{},
			stubPurger{},
			stubPurger{},
			stubPurger{},
			testRetention,
		)
		require.NoError(t, err)
		err = cleaner.Clean(context.Background(), testNow)
		require.Error(t, err)
		require.Contains(t, err.Error(), "purge expired rate limit counters")
	})
}

// testRootSecret is the shared normalized root secret used by the domain
// stores of the test cleaner.
var testRootSecret = [32]byte{
	1,
	2,
	3,
	4,
	5,
	6,
	7,
	8,
	9,
	10,
	11,
	12,
	13,
	14,
	15,
	16,
	17,
	18,
	19,
	20,
	21,
	22,
	23,
	24,
	25,
	26,
	27,
	28,
	29,
	30,
	31,
	32,
}

// stubPurger records no purges and never fails.
type stubPurger struct{}

// PurgeExpired reports zero removed records.
func (stubPurger) PurgeExpired(context.Context, time.Time) (int64, error) {
	return 0, nil
}

// failingPurger always fails its purge.
type failingPurger struct{}

// PurgeExpired reports a purge failure.
func (failingPurger) PurgeExpired(context.Context, time.Time) (int64, error) {
	return 0, errors.New("boom")
}

// auditRecorderStub purges audit records through real queries, letting a
// zero-retention cleaner run over a real database without the other purgers.
type auditRecorderStub struct {
	queries *statestore.Queries
}

// PurgeExpired deletes audit records at or before the given instant.
func (stub *auditRecorderStub) PurgeExpired(ctx context.Context, before time.Time) (int64, error) {
	return stub.queries.DeleteAuditRecordsBefore(ctx, clock.Format(before))
}
