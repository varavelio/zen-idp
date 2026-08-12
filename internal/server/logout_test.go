package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/varavelio/zen-idp/internal/session"
	"github.com/varavelio/zen-idp/internal/ui"
)

// failingSessionRevoker reports a persistence failure for every revocation.
type failingSessionRevoker struct{}

func (failingSessionRevoker) Revoke(context.Context, string) error {
	return errors.New("database unavailable")
}

func TestLogout(t *testing.T) {
	t.Run("revokes the session and clears the cookie", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		token := createSessionToken(t, app, "alice", time.Now())
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodGet,
			"/logout",
			nil,
		)
		request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
		response := httptest.NewRecorder()

		app.server.Handler().ServeHTTP(response, request)

		require.Equal(t, http.StatusOK, response.Code)
		require.Equal(t, "text/html; charset=utf-8", response.Header().Get("Content-Type"))
		require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
		require.Contains(t, response.Body.String(), "You have been signed out")
		setCookie := response.Header().Values("Set-Cookie")
		require.Len(t, setCookie, 1)
		require.Contains(t, setCookie[0], "Max-Age=0")
		require.Contains(t, setCookie[0], "HttpOnly")
		_, err := app.sessions.Validate(context.Background(), token, time.Now())
		require.ErrorIs(t, err, session.ErrInvalidSession)
	})

	t.Run("clears the cookie without a session cookie", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodGet,
			"/logout",
			nil,
		)
		response := httptest.NewRecorder()

		app.server.Handler().ServeHTTP(response, request)

		require.Equal(t, http.StatusOK, response.Code)
		require.Contains(t, response.Header().Values("Set-Cookie")[0], "Max-Age=0")
	})

	t.Run("succeeds with a malformed session cookie", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodGet,
			"/logout",
			nil,
		)
		request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "not-a-session-token"})
		response := httptest.NewRecorder()

		app.server.Handler().ServeHTTP(response, request)

		require.Equal(t, http.StatusOK, response.Code)
		require.Contains(t, response.Body.String(), "You have been signed out")
		require.Contains(t, response.Header().Values("Set-Cookie")[0], "Max-Age=0")
	})

	t.Run("marks the clearing cookie secure only when configured", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodGet,
			"/logout",
			nil,
		)
		response := httptest.NewRecorder()

		app.server.Handler().ServeHTTP(response, request)

		require.Contains(t, response.Header().Values("Set-Cookie")[0], "Secure")

		app.server.logout.SecureCookies = false
		response = httptest.NewRecorder()
		app.server.Handler().ServeHTTP(response, request)

		require.NotContains(t, response.Header().Values("Set-Cookie")[0], "Secure")
	})

	t.Run("returns an internal error when revocation fails", func(t *testing.T) {
		handler := New(
			testPublicJWK(),
			referenceIssuer,
			testClients(),
			ui.Assets(),
			LoginDependencies{},
			AuthorizeDependencies{},
			TokenDependencies{},
			UserinfoDependencies{},
			LogoutDependencies{Sessions: failingSessionRevoker{}},
			AdminDependencies{},
		).Handler()
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodGet,
			"/logout",
			nil,
		)
		request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "sess_abc_secret"})
		response := httptest.NewRecorder()

		handler.ServeHTTP(response, request)

		require.Equal(t, http.StatusInternalServerError, response.Code)
	})

	t.Run("rejects other methods", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodPost,
			"/logout",
			nil,
		)
		response := httptest.NewRecorder()

		app.server.Handler().ServeHTTP(response, request)

		require.Equal(t, http.StatusMethodNotAllowed, response.Code)
	})
}
