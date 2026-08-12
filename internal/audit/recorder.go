package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/varavelio/zen-idp/internal/clock"
	"github.com/varavelio/zen-idp/internal/statestore"
)

// auditQueries is the SQLite-backed audit persistence the recorder needs,
// satisfied by statestore.Queries. It is defined consumer-side so the
// recorder never depends on a concrete persistence implementation.
type auditQueries interface {
	CreateAuditRecord(context.Context, statestore.CreateAuditRecordParams) error
	ListAuditRecords(context.Context, int64) ([]statestore.AuditRecord, error)
}

// idGenerator creates the opaque record identifiers, satisfied by
// id.IDGenerator.
type idGenerator interface {
	NewID(context.Context) string
}

// Recorder owns the audit event lifecycle: appending security-relevant
// events to SQLite and listing them newest first for administration.
type Recorder struct {
	queries auditQueries
	ids     idGenerator
}

// NewRecorder returns a recorder that persists events through queries and
// assigns identifiers with ids.
func NewRecorder(queries auditQueries, ids idGenerator) (*Recorder, error) {
	if queries == nil {
		return nil, errors.New("audit queries are nil")
	}
	if ids == nil {
		return nil, errors.New("audit id generator is nil")
	}
	return &Recorder{queries: queries, ids: ids}, nil
}

// RecordParams carries the facts of one security-relevant event.
type RecordParams struct {
	// Category identifies the kind of event; one of the package's
	// category constants.
	Category Category
	// Subject is the affected subject or administrator, empty when not
	// applicable; stored as NULL in that case.
	Subject string
	// Details is a JSON object with event-specific facts. It must never
	// carry credentials, TOTP shared secrets or codes, complete cookies,
	// complete tokens, or derived keys.
	Details map[string]any
	// Now is the event instant, in UTC.
	Now time.Time
}

// Record appends one audit event with the given facts. The details object
// is stored as deterministic JSON with sorted keys, and as the empty object
// when nil.
func (recorder *Recorder) Record(ctx context.Context, params RecordParams) error {
	if params.Category == "" {
		return errors.New("audit category must not be empty")
	}

	details, err := encodeDetails(params.Details)
	if err != nil {
		return err
	}

	err = recorder.queries.CreateAuditRecord(ctx, statestore.CreateAuditRecordParams{
		ID:        recorder.ids.NewID(ctx),
		CreatedAt: clock.Format(params.Now),
		Category:  string(params.Category),
		Sub:       nullString(params.Subject),
		Details:   details,
	})
	if err != nil {
		return fmt.Errorf("create audit record: %w", err)
	}
	return nil
}

// List returns the most recent events, newest first, up to limit. Events
// sharing the same instant are ordered by identifier descending.
func (recorder *Recorder) List(ctx context.Context, limit int) ([]Event, error) {
	if limit <= 0 {
		return nil, errors.New("audit list limit must be positive")
	}

	records, err := recorder.queries.ListAuditRecords(ctx, int64(limit))
	if err != nil {
		return nil, fmt.Errorf("list audit records: %w", err)
	}

	events := make([]Event, 0, len(records))
	for _, record := range records {
		createdAt, err := clock.Parse(record.CreatedAt)
		if err != nil {
			return nil, fmt.Errorf("parse audit timestamp: %w", err)
		}
		events = append(events, Event{
			ID:        record.ID,
			CreatedAt: createdAt,
			Category:  Category(record.Category),
			Subject:   record.Sub.String,
			Details:   record.Details,
		})
	}
	return events, nil
}

// encodeDetails renders the details object as deterministic JSON with
// sorted keys, storing the empty object when nil.
func encodeDetails(details map[string]any) (string, error) {
	if details == nil {
		return "{}", nil
	}
	encoded, err := json.Marshal(details)
	if err != nil {
		return "", fmt.Errorf("encode audit details: %w", err)
	}
	return string(encoded), nil
}

// nullString maps an empty value to SQL NULL.
func nullString(value string) sql.NullString {
	if value == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: value, Valid: true}
}
