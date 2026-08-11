package server

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	t.Run("returns a handler that serves the JWKS route", func(t *testing.T) {
		handler := New(testPublicJWK()).Handler()

		require.NotNil(t, handler)
	})
}
