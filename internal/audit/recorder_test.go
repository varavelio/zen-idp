package audit

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/varavelio/zen-idp/internal/clock"
	"github.com/varavelio/zen-idp/internal/id"
	"github.com/varavelio/zen-idp/internal/statestore"
)

// testNow is the fixed instant used as the event time in lifecycle tests.
var testNow = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

// fixedID is an identifier generator that always returns one identifier.
type fixedID struct {
	id string
}

func (f fixedID) NewID(context.Context) string { return f.id }

// sequenceID is an identifier generator that yields its identifiers in
// order, repeating the last one.
type sequenceID struct {
	ids []string
}

func (s *sequenceID) NewID(context.Context) string {
	next := s.ids[0]
	if len(s.ids) > 1 {
		s.ids = s.ids[1:]
	}
	return next
}

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

// newTestRecorder returns a recorder backed by a migrated temporary SQLite
// database and its sqlc queries, assigning identifiers with ids.
func newTestRecorder(t *testing.T, ids idGenerator) (*Recorder, *statestore.Queries) {
	t.Helper()
	queries := statestore.New(newTestDB(t))
	recorder, err := NewRecorder(queries, ids)
	require.NoError(t, err)
	return recorder, queries
}

func TestNewRecorder(t *testing.T) {
	t.Run("rejects nil queries", func(t *testing.T) {
		_, err := NewRecorder(nil, fixedID{id: "01A"})
		require.Error(t, err)
	})

	t.Run("rejects nil id generator", func(t *testing.T) {
		_, queries := newTestRecorder(t, fixedID{id: "01A"})
		_, err := NewRecorder(queries, nil)
		require.Error(t, err)
	})

	t.Run("accepts valid dependencies", func(t *testing.T) {
		recorder, queries := newTestRecorder(t, fixedID{id: "01A"})
		require.NotNil(t, recorder)
		require.NotNil(t, queries)
	})
}

func TestRecord(t *testing.T) {
	t.Run("stores a complete event", func(t *testing.T) {
		recorder, queries := newTestRecorder(t, fixedID{id: "01A"})

		err := recorder.Record(context.Background(), RecordParams{
			Category: CategoryAdminAuthentication,
			Subject:  "admin",
			Details:  map[string]any{"method": "totp", "outcome": "success"},
			Now:      testNow,
		})
		require.NoError(t, err)

		rows, err := queries.ListAuditRecords(context.Background(), 10)
		require.NoError(t, err)
		require.Len(t, rows, 1)
		require.Equal(t, "01A", rows[0].ID)
		require.Equal(t, clock.Format(testNow), rows[0].CreatedAt)
		require.Equal(t, "admin_authentication", rows[0].Category)
		require.Equal(t, "admin", rows[0].Sub.String)
		require.True(t, rows[0].Sub.Valid)
		require.JSONEq(t, `{"method":"totp","outcome":"success"}`, rows[0].Details)
	})

	t.Run("stores a minimal event with NULL subject and empty details", func(t *testing.T) {
		recorder, queries := newTestRecorder(t, fixedID{id: "01A"})

		err := recorder.Record(context.Background(), RecordParams{
			Category: CategoryRateLimit,
			Now:      testNow,
		})
		require.NoError(t, err)

		rows, err := queries.ListAuditRecords(context.Background(), 10)
		require.NoError(t, err)
		require.Len(t, rows, 1)
		require.False(t, rows[0].Sub.Valid)
		require.Equal(t, "{}", rows[0].Details)
	})

	t.Run("sorts details keys deterministically", func(t *testing.T) {
		recorder, queries := newTestRecorder(t, &sequenceID{ids: []string{"01A", "01B"}})

		first := map[string]any{"b": 1, "a": 2}
		second := map[string]any{"a": 2, "b": 1}
		require.NoError(t, recorder.Record(context.Background(), RecordParams{
			Category: CategoryLockChanged,
			Subject:  "dev-01",
			Details:  first,
			Now:      testNow,
		}))
		require.NoError(t, recorder.Record(context.Background(), RecordParams{
			Category: CategoryLockChanged,
			Subject:  "dev-01",
			Details:  second,
			Now:      testNow.Add(time.Second),
		}))

		rows, err := queries.ListAuditRecords(context.Background(), 10)
		require.NoError(t, err)
		require.Len(t, rows, 2)
		require.JSONEq(t, `{"a":2,"b":1}`, rows[0].Details)
		require.JSONEq(t, `{"a":2,"b":1}`, rows[1].Details)
	})

	t.Run("rejects an empty category", func(t *testing.T) {
		recorder, _ := newTestRecorder(t, fixedID{id: "01A"})

		err := recorder.Record(context.Background(), RecordParams{Now: testNow})
		require.Error(t, err)
	})

	t.Run("rejects unmarshalable details", func(t *testing.T) {
		recorder, _ := newTestRecorder(t, fixedID{id: "01A"})

		err := recorder.Record(context.Background(), RecordParams{
			Category: CategoryPanicAction,
			Details:  map[string]any{"channel": make(chan int)},
			Now:      testNow,
		})
		require.Error(t, err)
	})
}

func TestList(t *testing.T) {
	t.Run("returns events newest first", func(t *testing.T) {
		recorder, _ := newTestRecorder(t, &sequenceID{ids: []string{"01A", "01B", "01C"}})
		for i, id := range []string{"01A", "01B", "01C"} {
			require.NoError(t, recorder.Record(context.Background(), RecordParams{
				Category: CategorySessionRevoked,
				Subject:  id,
				Now:      testNow.Add(time.Duration(i) * time.Second),
			}))
		}

		events, err := recorder.List(context.Background(), 10)
		require.NoError(t, err)
		require.Len(t, events, 3)
		require.Equal(t, "01C", events[0].Subject)
		require.Equal(t, "01B", events[1].Subject)
		require.Equal(t, "01A", events[2].Subject)
		require.Equal(t, testNow.Add(2*time.Second), events[0].CreatedAt)
		require.Equal(t, testNow, events[2].CreatedAt)
	})

	t.Run("breaks same-instant ties by identifier descending", func(t *testing.T) {
		recorder, _ := newTestRecorder(t, &sequenceID{ids: []string{"01A", "01B"}})
		for _, id := range []string{"01A", "01B"} {
			require.NoError(t, recorder.Record(context.Background(), RecordParams{
				Category: CategoryEnrollmentTokenCreated,
				Subject:  id,
				Now:      testNow,
			}))
		}

		events, err := recorder.List(context.Background(), 10)
		require.NoError(t, err)
		require.Len(t, events, 2)
		require.Equal(t, "01B", events[0].ID)
		require.Equal(t, "01A", events[1].ID)
	})

	t.Run("limits the result", func(t *testing.T) {
		recorder, _ := newTestRecorder(t, &sequenceID{ids: []string{"01A", "01B", "01C"}})
		for i, id := range []string{"01A", "01B", "01C"} {
			require.NoError(t, recorder.Record(context.Background(), RecordParams{
				Category: CategoryRateLimit,
				Subject:  id,
				Now:      testNow.Add(time.Duration(i) * time.Second),
			}))
		}

		events, err := recorder.List(context.Background(), 2)
		require.NoError(t, err)
		require.Len(t, events, 2)
		require.Equal(t, "01C", events[0].Subject)
		require.Equal(t, "01B", events[1].Subject)
	})

	t.Run("returns an empty slice from an empty store", func(t *testing.T) {
		recorder, _ := newTestRecorder(t, fixedID{id: "01A"})

		events, err := recorder.List(context.Background(), 10)
		require.NoError(t, err)
		require.Empty(t, events)
		require.NotNil(t, events)
	})

	t.Run("converts NULL subjects to empty strings", func(t *testing.T) {
		recorder, _ := newTestRecorder(t, fixedID{id: "01A"})
		require.NoError(t, recorder.Record(context.Background(), RecordParams{
			Category: CategoryPanicAction,
			Now:      testNow,
		}))

		events, err := recorder.List(context.Background(), 10)
		require.NoError(t, err)
		require.Len(t, events, 1)
		require.Equal(t, "", events[0].Subject)
		require.Equal(t, "{}", events[0].Details)
	})

	t.Run("rejects a non-positive limit", func(t *testing.T) {
		recorder, _ := newTestRecorder(t, fixedID{id: "01A"})

		_, err := recorder.List(context.Background(), 0)
		require.Error(t, err)
		_, err = recorder.List(context.Background(), -1)
		require.Error(t, err)
	})
}

func TestRecordListRoundTrip(t *testing.T) {
	t.Run("round-trips events with the real identifier generator", func(t *testing.T) {
		recorder, _ := newTestRecorder(t, id.NewIDGenerator())

		require.NoError(t, recorder.Record(context.Background(), RecordParams{
			Category: CategoryAdminAuthentication,
			Subject:  "admin",
			Details:  map[string]any{"outcome": "success"},
			Now:      testNow,
		}))

		events, err := recorder.List(context.Background(), 10)
		require.NoError(t, err)
		require.Len(t, events, 1)
		require.NotEmpty(t, events[0].ID)
		require.Equal(t, CategoryAdminAuthentication, events[0].Category)
		require.Equal(t, "admin", events[0].Subject)
		require.JSONEq(t, `{"outcome":"success"}`, events[0].Details)
		require.Equal(t, testNow, events[0].CreatedAt)
	})
}

func TestPurgeExpired(t *testing.T) {
	t.Run("deletes only records at or before the given instant", func(t *testing.T) {
		recorder, _ := newTestRecorder(t, &sequenceID{ids: []string{"first", "second"}})

		require.NoError(t, recorder.Record(context.Background(), RecordParams{
			Category: CategoryLockChanged,
			Now:      testNow.Add(-time.Hour),
		}))
		require.NoError(t, recorder.Record(context.Background(), RecordParams{
			Category: CategoryLockChanged,
			Now:      testNow.Add(time.Hour),
		}))

		deleted, err := recorder.PurgeExpired(context.Background(), testNow)
		require.NoError(t, err)
		require.Equal(t, int64(1), deleted)

		events, err := recorder.List(context.Background(), 10)
		require.NoError(t, err)
		require.Len(t, events, 1)
		require.Equal(t, testNow.Add(time.Hour), events[0].CreatedAt)
	})

	t.Run("reports zero when nothing is old enough", func(t *testing.T) {
		recorder, _ := newTestRecorder(t, fixedID{id: "fixed"})

		require.NoError(t, recorder.Record(context.Background(), RecordParams{
			Category: CategoryLockChanged,
			Now:      testNow,
		}))

		deleted, err := recorder.PurgeExpired(context.Background(), testNow.Add(-time.Hour))
		require.NoError(t, err)
		require.Zero(t, deleted)
	})
}
