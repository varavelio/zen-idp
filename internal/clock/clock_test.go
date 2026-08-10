package clock

import (
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestFormat(t *testing.T) {
	newYork, err := time.LoadLocation("America/New_York")
	require.NoError(t, err)

	tests := map[string]struct {
		input    time.Time
		expected string
	}{
		"utc instant": {
			input:    time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC),
			expected: "2026-08-10T12:00:00Z",
		},
		"non-utc location converts to utc": {
			input:    time.Date(2026, 8, 10, 8, 0, 0, 0, newYork),
			expected: "2026-08-10T12:00:00Z",
		},
		"fractional seconds are truncated": {
			input:    time.Date(2026, 8, 10, 12, 0, 0, 999_999_999, time.UTC),
			expected: "2026-08-10T12:00:00Z",
		},
		"midnight": {
			input:    time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC),
			expected: "2026-08-10T00:00:00Z",
		},
		"unix epoch": {
			input:    time.Unix(0, 0).UTC(),
			expected: "1970-01-01T00:00:00Z",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, test.expected, Format(test.input))
		})
	}
}

func TestParse(t *testing.T) {
	tests := map[string]struct {
		input    string
		expected time.Time
	}{
		"canonical timestamp": {
			input:    "2026-08-10T12:00:00Z",
			expected: time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC),
		},
		"unix epoch": {
			input:    "1970-01-01T00:00:00Z",
			expected: time.Unix(0, 0).UTC(),
		},
		"leap day": {
			input:    "2024-02-29T23:59:59Z",
			expected: time.Date(2024, 2, 29, 23, 59, 59, 0, time.UTC),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			parsed, err := Parse(test.input)
			require.NoError(t, err)
			require.True(t, parsed.Equal(test.expected))
			require.Equal(t, time.UTC, parsed.Location())
		})
	}
}

// TestParseReturnsUTC anchors the invariant that Parse never leaks a
// non-UTC zone to its callers, even for instants that would otherwise be
// representable with an offset.
func TestParseReturnsUTC(t *testing.T) {
	parsed, err := Parse("2026-08-10T12:00:00Z")
	require.NoError(t, err)
	require.Equal(t, time.UTC, parsed.Location())
	require.Equal(t, 12, parsed.Hour())
}

func TestParseRejectsNonCanonical(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{name: "empty", input: ""},
		{name: "not a timestamp", input: "not a timestamp"},
		{name: "sqlite space-separated format", input: "2026-08-10 12:00:00Z"},
		{name: "missing Z suffix", input: "2026-08-10T12:00:00"},
		{name: "utc offset instead of literal Z", input: "2026-08-10T12:00:00+00:00"},
		{name: "non-utc offset", input: "2026-08-10T12:00:00-05:00"},
		{name: "fractional seconds", input: "2026-08-10T12:00:00.5Z"},
		{name: "lowercase t", input: "2026-08-10t12:00:00Z"},
		{name: "lowercase z", input: "2026-08-10T12:00:00z"},
		{name: "missing zero padding", input: "2026-8-10T12:00:00Z"},
		{name: "invalid month", input: "2026-13-10T12:00:00Z"},
		{name: "invalid hour", input: "2026-08-10T25:00:00Z"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Parse(test.input)
			require.Error(t, err)
		})
	}
}

func TestFormatParseRoundTrip(t *testing.T) {
	instants := []time.Time{
		time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC),
		time.Date(2024, 2, 29, 23, 59, 59, 0, time.UTC),
		time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 8, 10, 12, 0, 0, 123_000_000, time.UTC), // sub-second precision is lost
	}
	for _, instant := range instants {
		parsed, err := Parse(Format(instant))
		require.NoError(t, err)
		require.True(t, parsed.Equal(instant.UTC().Truncate(time.Second)))
	}
}

func TestParseFormatRoundTrip(t *testing.T) {
	timestamps := []string{
		"2026-08-10T12:00:00Z",
		"1970-01-01T00:00:00Z",
		"2024-02-29T23:59:59Z",
	}
	for _, timestamp := range timestamps {
		parsed, err := Parse(timestamp)
		require.NoError(t, err)
		require.Equal(t, timestamp, Format(parsed))
	}
}

// TestCanonicalOrdering anchors the property the state store queries rely
// on: lexicographic string order equals chronological order.
func TestCanonicalOrdering(t *testing.T) {
	instants := []time.Time{
		time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC),
		time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 8, 10, 11, 59, 59, 0, time.UTC),
		time.Date(2025, 12, 31, 23, 59, 59, 0, time.UTC),
		time.Date(2026, 8, 10, 12, 0, 1, 0, time.UTC),
	}

	formatted := make([]string, len(instants))
	for i, instant := range instants {
		formatted[i] = Format(instant)
	}

	sort.Slice(instants, func(i, j int) bool { return instants[i].Before(instants[j]) })
	sortedStrings := append([]string(nil), formatted...)
	sort.Strings(sortedStrings)

	for i := range instants {
		require.Equal(t, Format(instants[i]), sortedStrings[i])
	}
}

func TestNow(t *testing.T) {
	before := time.Now()
	now, err := Parse(Now())
	require.NoError(t, err)
	after := time.Now()

	require.False(t, now.Before(before.Add(-time.Second)))
	require.False(t, now.After(after.Add(time.Second)))
}
