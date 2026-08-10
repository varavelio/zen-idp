package clock

import (
	"fmt"
	"time"
)

// layout is the canonical state timestamp layout: UTC with second
// precision. The trailing Z is a literal character, so offsets and
// fractional seconds are rejected by construction.
const layout = "2006-01-02T15:04:05Z"

// Format renders t as a canonical UTC RFC 3339 timestamp with second
// precision.
func Format(t time.Time) string {
	return t.UTC().Format(layout)
}

// Parse interprets s as a canonical UTC RFC 3339 timestamp with second
// precision. It rejects every other layout, including offsets, fractional
// seconds, and the SQLite space-separated format. The returned time is
// always in UTC.
func Parse(s string) (time.Time, error) {
	parsed, err := time.Parse(layout, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse timestamp %q: %w", s, err)
	}
	// time.Parse accepts fractional seconds even when the layout omits
	// them; the canonical round-trip check rejects them.
	if parsed.Format(layout) != s {
		return time.Time{}, fmt.Errorf("parse timestamp %q: not in canonical format", s)
	}
	// Normalize the location so callers never observe a non-UTC zone,
	// regardless of layout changes.
	return parsed.UTC(), nil
}

// Now returns the current instant as a canonical UTC RFC 3339 timestamp
// with second precision.
func Now() string {
	return Format(time.Now())
}
