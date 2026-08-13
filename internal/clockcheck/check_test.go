package clockcheck

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCheck(t *testing.T) {
	t.Run("accepts a plausible instant", func(t *testing.T) {
		now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
		require.NoError(t, Check(now))
	})

	t.Run("accepts the minimum instant", func(t *testing.T) {
		require.NoError(t, Check(minimum))
	})

	t.Run("accepts the maximum instant", func(t *testing.T) {
		require.NoError(t, Check(maximum))
	})

	t.Run("accepts a plausible instant in any location", func(t *testing.T) {
		now := time.Date(2026, 8, 10, 14, 0, 0, 0, time.FixedZone("CEST", 2*60*60))
		require.NoError(t, Check(now))
	})

	t.Run("rejects an instant before the minimum", func(t *testing.T) {
		now := time.Date(2024, 12, 31, 23, 59, 59, 0, time.UTC)
		require.EqualError(t, Check(now),
			"clock check: system time 2024-12-31T23:59:59Z is earlier than the "+
				"plausible minimum 2025-01-01T00:00:00Z; synchronize the system "+
				"clock and restart")
	})

	t.Run("rejects the unix epoch", func(t *testing.T) {
		err := Check(time.Unix(0, 0).UTC())
		require.ErrorContains(t, err, "is earlier than the plausible minimum")
	})

	t.Run("rejects the zero time", func(t *testing.T) {
		err := Check(time.Time{})
		require.ErrorContains(t, err, "is earlier than the plausible minimum")
	})

	t.Run("rejects an instant after the maximum", func(t *testing.T) {
		now := time.Date(2100, 1, 1, 0, 0, 1, 0, time.UTC)
		require.EqualError(t, Check(now),
			"clock check: system time 2100-01-01T00:00:01Z is later than the "+
				"plausible maximum 2100-01-01T00:00:00Z; synchronize the system "+
				"clock and restart")
	})
}
