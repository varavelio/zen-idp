package audit

import "time"

// Event is one stored audit record as returned by List.
type Event struct {
	// ID is the opaque record identifier.
	ID string
	// CreatedAt is the event instant, in UTC.
	CreatedAt time.Time
	// Category is the event category.
	Category Category
	// Subject is the affected subject or administrator, empty when the
	// event carries none.
	Subject string
	// Details is the stored JSON details object.
	Details string
}
