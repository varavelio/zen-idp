package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// stubHealthChecker is a health checker whose verdict is controlled by
// the test.
type stubHealthChecker struct {
	ok bool
}

func (c stubHealthChecker) OK(context.Context) bool {
	return c.ok
}

func TestHealth(t *testing.T) {
	t.Run("reports healthy with a live state database", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodGet,
			"/health",
			nil,
		)
		response := httptest.NewRecorder()

		app.server.Handler().ServeHTTP(response, request)

		require.Equal(t, http.StatusOK, response.Code)
		require.Equal(t, "application/json; charset=utf-8", response.Header().Get("Content-Type"))
		require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
		var body healthResponse
		require.NoError(t, json.Unmarshal(response.Body.Bytes(), &body))
		require.True(t, body.OK)
	})

	t.Run("reports unhealthy with a failing checker", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		app.server.health.Checker = stubHealthChecker{ok: false}
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodGet,
			"/health",
			nil,
		)
		response := httptest.NewRecorder()

		app.server.Handler().ServeHTTP(response, request)

		require.Equal(t, http.StatusServiceUnavailable, response.Code)
		var body healthResponse
		require.NoError(t, json.Unmarshal(response.Body.Bytes(), &body))
		require.False(t, body.OK)
	})
}
