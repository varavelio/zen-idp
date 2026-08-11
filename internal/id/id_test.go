package id

import (
	"context"
	"regexp"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"go.jetify.com/typeid/v2"
)

// typeIDPattern matches a prefix-less TypeID: 26 Crockford base32
// characters in lowercase, excluding i, l, o, and u.
var typeIDPattern = regexp.MustCompile(`^[0-9a-hjkmnp-tv-z]{26}$`)

func TestNewID(t *testing.T) {
	generator := NewIDGenerator()

	t.Run("returns valid prefix-less TypeIDs", func(t *testing.T) {
		generated := generator.NewID(context.Background())

		require.Regexp(t, typeIDPattern, generated)

		parsed, err := typeid.Parse(generated)
		require.NoError(t, err)
		require.Equal(t, generated, parsed.String())
	})

	t.Run("generates distinct identifiers", func(t *testing.T) {
		const count = 100

		seen := make(map[string]struct{}, count)
		for range count {
			generated := generator.NewID(context.Background())
			require.NotContains(t, seen, generated)
			seen[generated] = struct{}{}
		}
		require.Len(t, seen, count)
	})

	t.Run("is safe for concurrent generation", func(t *testing.T) {
		const count = 100
		ids := make(chan string, count)

		var wg sync.WaitGroup
		for range count {
			wg.Go(func() {
				ids <- generator.NewID(context.Background())
			})
		}
		wg.Wait()
		close(ids)

		seen := make(map[string]struct{}, count)
		for generated := range ids {
			require.NotContains(t, seen, generated)
			seen[generated] = struct{}{}
		}
		require.Len(t, seen, count)
	})
}
