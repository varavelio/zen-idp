package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestLimitRequestBody(t *testing.T) {
	t.Run("passes request bodies within the limit", func(t *testing.T) {
		handler := limitRequestBody(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			require.Equal(t, "hello", string(body))
			w.WriteHeader(http.StatusOK)
		}))
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodPost,
			"/",
			strings.NewReader("hello"),
		)

		handler.ServeHTTP(httptest.NewRecorder(), request)
	})

	t.Run("fails reads beyond the limit", func(t *testing.T) {
		handler := limitRequestBody(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := io.ReadAll(r.Body)
			var limitErr *http.MaxBytesError
			require.ErrorAs(t, err, &limitErr)
			require.Equal(t, int64(maxRequestBodyBytes), limitErr.Limit)
			w.WriteHeader(http.StatusOK)
		}))
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodPost,
			"/",
			strings.NewReader(strings.Repeat("a", maxRequestBodyBytes+1)),
		)

		handler.ServeHTTP(httptest.NewRecorder(), request)
	})
}

func TestCrossOriginAPI(t *testing.T) {
	t.Run("allows any origin on JSON API endpoints", func(t *testing.T) {
		for _, path := range []string{
			"/.well-known/openid-configuration",
			"/.well-known/jwks.json",
			"/token",
			"/userinfo",
		} {
			t.Run(path, func(t *testing.T) {
				response := httptest.NewRecorder()
				request := httptest.NewRequestWithContext(
					context.Background(),
					http.MethodGet,
					path,
					nil,
				)

				crossOriginAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
				})).ServeHTTP(response, request)

				require.Equal(t, "*", response.Header().Get("Access-Control-Allow-Origin"))
			})
		}
	})

	t.Run("does not add cross-origin headers to page endpoints", func(t *testing.T) {
		response := httptest.NewRecorder()
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodGet,
			"/login",
			nil,
		)

		crossOriginAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(response, request)

		require.Empty(t, response.Header().Get("Access-Control-Allow-Origin"))
	})

	t.Run("answers preflight requests on API endpoints", func(t *testing.T) {
		response := httptest.NewRecorder()
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodOptions,
			"/userinfo",
			nil,
		)
		request.Header.Set("Access-Control-Request-Method", "GET")
		request.Header.Set("Access-Control-Request-Headers", "authorization")

		crossOriginAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("the preflight must not reach the wrapped handler")
		})).ServeHTTP(response, request)

		require.Equal(t, http.StatusNoContent, response.Code)
		require.Equal(t, "*", response.Header().Get("Access-Control-Allow-Origin"))
		require.Contains(t, response.Header().Get("Access-Control-Allow-Methods"), "GET")
		require.Contains(t, response.Header().Get("Access-Control-Allow-Headers"), "Authorization")
	})

	t.Run("leaves preflight on non-API endpoints to the router", func(t *testing.T) {
		response := httptest.NewRecorder()
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodOptions,
			"/login",
			nil,
		)

		crossOriginAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(response, request)

		require.Equal(t, http.StatusOK, response.Code)
		require.Empty(t, response.Header().Get("Access-Control-Allow-Origin"))
	})
}
