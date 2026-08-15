package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/varavelio/zen-idp/internal/audit"
	"github.com/varavelio/zen-idp/internal/csrf"
	"github.com/varavelio/zen-idp/internal/jwt"
	"github.com/varavelio/zen-idp/internal/session"
	"github.com/varavelio/zen-idp/internal/ui"
)

// failingSessionRevoker reports a persistence failure for every validation
// and revocation.
type failingSessionRevoker struct{}

func (failingSessionRevoker) Validate(context.Context, string, time.Time) (session.Session, error) {
	return session.Session{}, errors.New("database unavailable")
}

func (failingSessionRevoker) Revoke(context.Context, string) error {
	return errors.New("database unavailable")
}

// signIDToken signs a valid ID token of the reference identity issued to
// the given client, as an RP-Initiated Logout id_token_hint would carry.
func signIDToken(t *testing.T, clientID string, issuedAt, expiresAt time.Time) string {
	t.Helper()
	signer, err := jwt.NewSigner(referenceKey(), referenceKid())
	require.NoError(t, err)
	signed, err := signer.Sign(map[string]any{
		"iss": referenceIssuer,
		"sub": "alice",
		"aud": clientID,
		"iat": issuedAt.Unix(),
		"exp": expiresAt.Unix(),
	})
	require.NoError(t, err)
	return signed
}

// logoutCSRFToken fetches the local logout interaction and returns the
// anti-forgery token it issues, exactly as a browser would receive it.
func logoutCSRFToken(t *testing.T, app *testApp) string {
	t.Helper()
	request := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"/logout",
		nil,
	)
	response := httptest.NewRecorder()
	app.server.Handler().ServeHTTP(response, request)
	require.Equal(t, http.StatusOK, response.Code)
	return logoutCSRFCookie(t, response)
}

// logoutCSRFCookie returns the anti-forgery cookie value of an existing
// logout response.
func logoutCSRFCookie(t *testing.T, response *httptest.ResponseRecorder) string {
	t.Helper()
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == CSRFCookieName {
			return cookie.Value
		}
	}
	require.FailNow(t, "no CSRF cookie in response")
	return ""
}

// logoutRequest posts a sign-out confirmation carrying the given
// anti-forgery token and cookies, returning the response.
func logoutRequest(
	t *testing.T,
	handler http.Handler,
	token string,
	cookies ...*http.Cookie,
) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{csrf.FieldName: {token}}
	request := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		"/logout",
		strings.NewReader(form.Encode()),
	)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: token})
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestLogout(t *testing.T) {
	t.Run(
		"redirects to a registered post_logout_redirect_uri after confirmation",
		func(t *testing.T) {
			app := newTestApp(t, testUsers)
			cookie := createSessionToken(t, app, "alice", time.Now())
			now := time.Now()
			query := url.Values{
				"id_token_hint":            {signIDToken(t, "public-app", now, now.Add(time.Hour))},
				"post_logout_redirect_uri": {"https://app.example.com/callback"},
				"state":                    {"rp-state"},
			}.Encode()

			// The confirmation form preserves the request so the redirect
			// target survives the protected submission.
			request := httptest.NewRequestWithContext(
				context.Background(),
				http.MethodGet,
				"/logout?"+query,
				nil,
			)
			request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookie})
			response := httptest.NewRecorder()
			app.server.Handler().ServeHTTP(response, request)

			require.Equal(t, http.StatusOK, response.Code)
			escapedQuery := strings.ReplaceAll(query, "&", "&amp;")
			require.Contains(t, response.Body.String(), `action="/logout?`+escapedQuery+`"`)
			csrfToken := logoutCSRFCookie(t, response)

			// The protected submission revokes, clears, and redirects back
			// to the registered URI echoing the state.
			request = httptest.NewRequestWithContext(
				context.Background(),
				http.MethodPost,
				"/logout?"+query,
				strings.NewReader(url.Values{csrf.FieldName: {csrfToken}}.Encode()),
			)
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookie})
			request.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: csrfToken})
			response = httptest.NewRecorder()
			app.server.Handler().ServeHTTP(response, request)

			require.Equal(t, http.StatusSeeOther, response.Code)
			require.Equal(
				t,
				"https://app.example.com/callback?state=rp-state",
				response.Header().Get("Location"),
			)
			require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
			_, err := app.sessions.Validate(context.Background(), cookie, time.Now())
			require.ErrorIs(t, err, session.ErrInvalidSession)
		},
	)

	t.Run("never redirects to an unregistered post_logout_redirect_uri", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		cookie := createSessionToken(t, app, "alice", time.Now())
		now := time.Now()
		// The hint identifies a client that did not register the URI; the
		// URI belongs to another registered client only.
		query := url.Values{
			"id_token_hint": {
				signIDToken(t, "confidential-app", now, now.Add(time.Hour)),
			},
			"post_logout_redirect_uri": {"https://app.example.com/callback?tenant=1"},
		}.Encode()

		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodGet,
			"/logout?"+query,
			nil,
		)
		request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookie})
		response := httptest.NewRecorder()
		app.server.Handler().ServeHTTP(response, request)

		require.Equal(t, http.StatusOK, response.Code)
		require.Contains(t, response.Body.String(), `action="/logout"`)
		require.NotContains(t, response.Body.String(), `action="/logout?`)
		csrfToken := logoutCSRFCookie(t, response)

		request = httptest.NewRequestWithContext(
			context.Background(),
			http.MethodPost,
			"/logout?"+query,
			strings.NewReader(url.Values{csrf.FieldName: {csrfToken}}.Encode()),
		)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookie})
		request.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: csrfToken})
		response = httptest.NewRecorder()
		app.server.Handler().ServeHTTP(response, request)

		require.Equal(t, http.StatusOK, response.Code)
		require.Empty(t, response.Header().Get("Location"))
		require.Contains(t, response.Body.String(), "You have been signed out")
	})

	t.Run("ignores post_logout_redirect_uri without a valid id_token_hint", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		cookie := createSessionToken(t, app, "alice", time.Now())
		query := url.Values{
			"id_token_hint":            {"garbage"},
			"post_logout_redirect_uri": {"https://app.example.com/callback"},
		}.Encode()

		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodGet,
			"/logout?"+query,
			nil,
		)
		request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookie})
		response := httptest.NewRecorder()
		app.server.Handler().ServeHTTP(response, request)
		require.Equal(t, http.StatusOK, response.Code)
		csrfToken := logoutCSRFCookie(t, response)

		request = httptest.NewRequestWithContext(
			context.Background(),
			http.MethodPost,
			"/logout?"+query,
			strings.NewReader(url.Values{csrf.FieldName: {csrfToken}}.Encode()),
		)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookie})
		request.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: csrfToken})
		response = httptest.NewRecorder()
		app.server.Handler().ServeHTTP(response, request)

		require.Equal(t, http.StatusOK, response.Code)
		require.Empty(t, response.Header().Get("Location"))
		require.Contains(t, response.Body.String(), "You have been signed out")
	})

	t.Run("ignores an expired id_token_hint", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		cookie := createSessionToken(t, app, "alice", time.Now())
		now := time.Now()
		query := url.Values{
			"id_token_hint": {
				signIDToken(t, "public-app", now.Add(-2*time.Hour), now.Add(-time.Hour)),
			},
			"post_logout_redirect_uri": {"https://app.example.com/callback"},
		}.Encode()

		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodGet,
			"/logout?"+query,
			nil,
		)
		request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookie})
		response := httptest.NewRecorder()
		app.server.Handler().ServeHTTP(response, request)
		require.Equal(t, http.StatusOK, response.Code)
		csrfToken := logoutCSRFCookie(t, response)

		request = httptest.NewRequestWithContext(
			context.Background(),
			http.MethodPost,
			"/logout?"+query,
			strings.NewReader(url.Values{csrf.FieldName: {csrfToken}}.Encode()),
		)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookie})
		request.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: csrfToken})
		response = httptest.NewRecorder()
		app.server.Handler().ServeHTTP(response, request)

		require.Equal(t, http.StatusOK, response.Code)
		require.Empty(t, response.Header().Get("Location"))
	})

	t.Run("ignores post_logout_redirect_uri without a session", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		now := time.Now()
		query := url.Values{
			"id_token_hint":            {signIDToken(t, "public-app", now, now.Add(time.Hour))},
			"post_logout_redirect_uri": {"https://app.example.com/callback"},
		}.Encode()

		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodGet,
			"/logout?"+query,
			nil,
		)
		response := httptest.NewRecorder()
		app.server.Handler().ServeHTTP(response, request)

		require.Equal(t, http.StatusOK, response.Code)
		require.Contains(t, response.Body.String(), "You have been signed out")
		require.Empty(t, response.Header().Get("Location"))
	})

	t.Run("shows the confirmation page without revoking on GET", func(t *testing.T) {
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
		require.Contains(t, response.Body.String(), "End your session on this device?")
		require.Contains(t, response.Body.String(), `action="/logout"`)
		require.Contains(t, response.Body.String(), `name="csrf_token"`)
		require.NotContains(t, response.Body.String(), "You have been signed out")

		// The GET only confirms: the session stays active and only the
		// anti-forgery cookie is set, never the clearing cookie.
		setCookie := response.Header().Values("Set-Cookie")
		require.Len(t, setCookie, 1)
		require.Contains(t, setCookie[0], CSRFCookieName)
		require.NotContains(t, setCookie[0], "Max-Age=0")
		_, err := app.sessions.Validate(context.Background(), token, time.Now())
		require.NoError(t, err)
	})

	t.Run("completes the logout through the protected form", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		token := createSessionToken(t, app, "alice", time.Now())
		csrfToken := logoutCSRFToken(t, app)

		response := logoutRequest(
			t,
			app.server.Handler(),
			csrfToken,
			&http.Cookie{Name: sessionCookieName, Value: token},
		)

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

		// The live session revocation is recorded against its subject.
		events := auditEvents(t, app)
		require.Len(t, events, 1)
		require.Equal(t, audit.CategorySessionRevoked, events[0].Category)
		require.Equal(t, "alice", events[0].Subject)
		require.JSONEq(t, `{}`, events[0].Details)
	})

	t.Run("renders the signed-out page directly without a session cookie", func(t *testing.T) {
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
		require.Contains(t, response.Body.String(), "You have been signed out")
		require.NotContains(t, response.Body.String(), `action="/logout"`)

		// Without a session there is nothing to clear: only the
		// anti-forgery cookie is set.
		setCookie := response.Header().Values("Set-Cookie")
		require.Len(t, setCookie, 1)
		require.NotContains(t, setCookie[0], "Max-Age=0")
	})

	t.Run("confirms and completes with a malformed session cookie", func(t *testing.T) {
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
		require.Contains(t, response.Body.String(), "End your session on this device?")

		csrfToken := logoutCSRFToken(t, app)
		response = logoutRequest(
			t,
			app.server.Handler(),
			csrfToken,
			&http.Cookie{Name: sessionCookieName, Value: "not-a-session-token"},
		)

		require.Equal(t, http.StatusOK, response.Code)
		require.Contains(t, response.Body.String(), "You have been signed out")
		require.Contains(t, response.Header().Values("Set-Cookie")[0], "Max-Age=0")

		// Nothing live was revoked, so no revocation event is recorded.
		require.Empty(t, auditEvents(t, app))
	})

	t.Run("rejects a sign-out without a CSRF token", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		token := createSessionToken(t, app, "alice", time.Now())
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodPost,
			"/logout",
			nil,
		)
		request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
		response := httptest.NewRecorder()

		app.server.Handler().ServeHTTP(response, request)

		require.Equal(t, http.StatusForbidden, response.Code)
		require.Contains(t, response.Body.String(), "Forbidden")
		require.Equal(t, "no-store", response.Header().Get("Cache-Control"))

		// The session survives the rejected sign-out.
		_, err := app.sessions.Validate(context.Background(), token, time.Now())
		require.NoError(t, err)
	})

	t.Run("rejects a sign-out with a mismatched CSRF token", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		token := createSessionToken(t, app, "alice", time.Now())
		cookieToken := logoutCSRFToken(t, app)
		fieldToken := logoutCSRFToken(t, app)
		require.NotEqual(t, cookieToken, fieldToken)

		form := url.Values{
			csrf.FieldName: {fieldToken},
		}
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodPost,
			"/logout",
			strings.NewReader(form.Encode()),
		)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: cookieToken})
		request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
		response := httptest.NewRecorder()

		app.server.Handler().ServeHTTP(response, request)

		require.Equal(t, http.StatusForbidden, response.Code)
		_, err := app.sessions.Validate(context.Background(), token, time.Now())
		require.NoError(t, err)
	})

	t.Run("marks the clearing cookie secure only when configured", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		token := createSessionToken(t, app, "alice", time.Now())
		csrfToken := logoutCSRFToken(t, app)
		withSession := &http.Cookie{Name: sessionCookieName, Value: token}

		response := logoutRequest(t, app.server.Handler(), csrfToken, withSession)

		require.Contains(t, response.Header().Values("Set-Cookie")[0], "Secure")

		app.server.logout.SecureCookies = false
		response = logoutRequest(t, app.server.Handler(), csrfToken, withSession)

		require.NotContains(t, response.Header().Values("Set-Cookie")[0], "Secure")
	})

	t.Run("returns an internal error when revocation fails", func(t *testing.T) {
		csrfGuard, err := csrf.NewGuard(CSRFCookieName, false)
		require.NoError(t, err)
		handler := New(
			testPublicJWK(),
			referenceIssuer,
			testClients(),
			ui.Assets(),
			LoginDependencies{},
			AuthorizeDependencies{},
			TokenDependencies{},
			UserinfoDependencies{},
			LogoutDependencies{
				Sessions: failingSessionRevoker{},
				CSRF:     csrfGuard,
			},
			EnrollDependencies{},
			AdminDependencies{},
			PanicDependencies{},
			HealthDependencies{},
		).Handler()

		// Obtain the anti-forgery token from the confirmation interaction.
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodGet,
			"/logout",
			nil,
		)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		csrfToken := ""
		for _, cookie := range response.Result().Cookies() {
			if cookie.Name == CSRFCookieName {
				csrfToken = cookie.Value
			}
		}
		require.NotEmpty(t, csrfToken)

		response = logoutRequest(
			t,
			handler,
			csrfToken,
			&http.Cookie{Name: sessionCookieName, Value: "sess_abc_secret"},
		)

		require.Equal(t, http.StatusInternalServerError, response.Code)
	})

	t.Run("returns an internal error when recording the revocation fails", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		token := createSessionToken(t, app, "alice", time.Now())
		csrfToken := logoutCSRFToken(t, app)
		app.server.logout.Audit = failingPanicAudit{}

		response := logoutRequest(
			t,
			app.server.Handler(),
			csrfToken,
			&http.Cookie{Name: sessionCookieName, Value: token},
		)

		require.Equal(t, http.StatusInternalServerError, response.Code)

		// The session is revoked even though the event could not be
		// recorded.
		_, err := app.sessions.Validate(context.Background(), token, time.Now())
		require.ErrorIs(t, err, session.ErrInvalidSession)
	})

	t.Run("rejects other methods", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodPut,
			"/logout",
			nil,
		)
		response := httptest.NewRecorder()

		app.server.Handler().ServeHTTP(response, request)

		require.Equal(t, http.StatusMethodNotAllowed, response.Code)
	})
}
