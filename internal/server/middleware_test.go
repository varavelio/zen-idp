package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSecurityHeaders(t *testing.T) {
	response := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)

	securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(response, request)

	require.Equal(t, "nosniff", response.Header().Get("X-Content-Type-Options"))
	require.Equal(t, "no-referrer", response.Header().Get("Referrer-Policy"))
	require.Equal(t, contentSecurityPolicy, response.Header().Get("Content-Security-Policy"))
}

func TestContentSecurityPolicy(t *testing.T) {
	t.Run("covers every resource the pages rely on", func(t *testing.T) {
		for _, directive := range []string{
			"default-src 'self'",
			"img-src 'self' data: https:",
			"script-src 'self'",
			"style-src 'self'",
			"font-src 'self'",
			"form-action 'self'",
			"frame-ancestors 'none'",
			"base-uri 'none'",
		} {
			t.Run(directive, func(t *testing.T) {
				require.Contains(t, contentSecurityPolicy, directive)
			})
		}
	})

	t.Run("never relaxes to inline or eval execution", func(t *testing.T) {
		require.NotContains(t, contentSecurityPolicy, "unsafe-inline")
		require.NotContains(t, contentSecurityPolicy, "unsafe-eval")
	})
}
