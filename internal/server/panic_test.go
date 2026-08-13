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
	"github.com/varavelio/zen-idp/internal/session"
	"github.com/varavelio/zen-idp/internal/statestore"
	"github.com/varavelio/zen-idp/internal/totp"
)

// panicCSRFToken fetches the panic interaction and returns the anti-forgery
// token it issues, exactly as a browser would receive it.
func panicCSRFToken(t *testing.T, app *testApp) string {
	t.Helper()
	request := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"/panic",
		nil,
	)
	response := httptest.NewRecorder()
	app.server.Handler().ServeHTTP(response, request)
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == CSRFCookieName {
			return cookie.Value
		}
	}
	require.FailNow(t, "no CSRF cookie in response")
	return ""
}

// panicRequest builds a POST /panic request carrying the given session
// cookie and anti-forgery token, exactly as the confirmation form would.
func panicRequest(token, sessionCookie string) *http.Request {
	form := url.Values{csrf.FieldName: {token}}
	request := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		"/panic",
		strings.NewReader(form.Encode()),
	)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: token})
	if sessionCookie != "" {
		request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionCookie})
	}
	return request
}

// panicAuditRecords returns every panic-action audit event of the app,
// newest first.
func panicAuditRecords(t *testing.T, app *testApp) []statestore.AuditRecord {
	t.Helper()
	records, err := statestore.New(app.db).ListAuditRecords(context.Background(), 10)
	require.NoError(t, err)
	var panics []statestore.AuditRecord
	for _, record := range records {
		if record.Category == string(audit.CategoryPanicAction) {
			panics = append(panics, record)
		}
	}
	return panics
}

// failingPanicSessions fails every session validation, standing in for an
// unavailable session store.
type failingPanicSessions struct{}

// Validate always fails.
func (failingPanicSessions) Validate(
	context.Context,
	string,
	time.Time,
) (session.Session, error) {
	return session.Session{}, errors.New("session validation failed")
}

// failingPanicLocks fails every panic action, standing in for an unavailable
// lock manager.
type failingPanicLocks struct{}

// PanicSubject always fails.
func (failingPanicLocks) PanicSubject(context.Context, string, time.Time) error {
	return errors.New("panic action failed")
}

// failingPanicAudit fails every audit recording, standing in for an
// unavailable audit recorder.
type failingPanicAudit struct{}

// Record always fails.
func (failingPanicAudit) Record(context.Context, audit.RecordParams) error {
	return errors.New("audit recording failed")
}

func TestPanicForm(t *testing.T) {
	t.Run("renders the confirmation for a browser with a valid session", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		token := createSessionToken(t, app, "alice", time.Now())

		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodGet,
			"/panic",
			nil,
		)
		request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
		response := httptest.NewRecorder()
		app.server.Handler().ServeHTTP(response, request)

		require.Equal(t, http.StatusOK, response.Code)
		require.Equal(t, "text/html; charset=utf-8", response.Header().Get("Content-Type"))
		require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
		body := response.Body.String()
		require.Contains(t, body, "Trigger the panic action?")
		require.Contains(t, body, `form action="/panic"`)
		require.Contains(t, body, `name="csrf_token"`)
		require.Contains(t, body, "Trigger panic")
	})

	t.Run("renders the sign-in-required page for anonymous browsers", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		response := httptest.NewRecorder()
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodGet,
			"/panic",
			nil,
		)
		app.server.Handler().ServeHTTP(response, request)

		require.Equal(t, http.StatusOK, response.Code)
		body := response.Body.String()
		require.Contains(t, body, "Sign in is required to trigger the panic action.")
		require.NotContains(t, body, "Trigger panic")
	})

	t.Run("renders the sign-in-required page for a malformed session cookie", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodGet,
			"/panic",
			nil,
		)
		request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "not-a-session-token"})
		response := httptest.NewRecorder()
		app.server.Handler().ServeHTTP(response, request)

		require.Equal(t, http.StatusOK, response.Code)
		require.Contains(
			t,
			response.Body.String(),
			"Sign in is required to trigger the panic action.",
		)
	})

	t.Run("renders the sign-in-required page for an expired session", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		token := createSessionToken(t, app, "alice", time.Now().Add(-testMaxAge-time.Hour))

		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodGet,
			"/panic",
			nil,
		)
		request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
		response := httptest.NewRecorder()
		app.server.Handler().ServeHTTP(response, request)

		require.Equal(t, http.StatusOK, response.Code)
		require.Contains(
			t,
			response.Body.String(),
			"Sign in is required to trigger the panic action.",
		)
	})

	t.Run("renders the sign-in-required page for an administrator session", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		loginResponse := adminLoginRequest(t, app, testAdminPassword)
		require.Equal(t, http.StatusSeeOther, loginResponse.Code)
		adminToken := adminSessionCookie(t, loginResponse)
		require.NotEmpty(t, adminToken)

		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodGet,
			"/panic",
			nil,
		)
		request.AddCookie(&http.Cookie{Name: adminSessionCookieName, Value: adminToken})
		response := httptest.NewRecorder()
		app.server.Handler().ServeHTTP(response, request)

		require.Equal(t, http.StatusOK, response.Code)
		require.Contains(
			t,
			response.Body.String(),
			"Sign in is required to trigger the panic action.",
		)
	})

	t.Run("rejects other methods", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodPut,
			"/panic",
			nil,
		)
		response := httptest.NewRecorder()
		app.server.Handler().ServeHTTP(response, request)

		require.Equal(t, http.StatusMethodNotAllowed, response.Code)
	})
}

func TestProcessPanic(t *testing.T) {
	post := func(t *testing.T, app *testApp, sessionCookie string) *httptest.ResponseRecorder {
		t.Helper()
		token := panicCSRFToken(t, app)
		response := httptest.NewRecorder()
		app.server.Handler().ServeHTTP(response, panicRequest(token, sessionCookie))
		return response
	}

	t.Run(
		"revokes every session of the subject and creates the panic lock",
		func(t *testing.T) {
			app := newTestApp(t, testUsers)
			now := time.Now()
			aliceToken := createSessionToken(t, app, "alice", now)
			secondToken := createSessionToken(t, app, "alice", now)
			bobToken := createSessionToken(t, app, "bob", now)

			response := post(t, app, aliceToken)

			require.Equal(t, http.StatusOK, response.Code)
			require.Contains(t, response.Body.String(), "The panic action was triggered.")
			require.Equal(t, "no-store", response.Header().Get("Cache-Control"))

			_, err := app.sessions.Validate(context.Background(), aliceToken, now)
			require.ErrorIs(t, err, session.ErrInvalidSession)
			_, err = app.sessions.Validate(context.Background(), secondToken, now)
			require.ErrorIs(t, err, session.ErrInvalidSession)
			// Sessions of other subjects survive the panic action.
			_, err = app.sessions.Validate(context.Background(), bobToken, now)
			require.NoError(t, err)

			locked, err := app.locks.IsLocked(context.Background(), "alice")
			require.NoError(t, err)
			require.True(t, locked)
		},
	)

	t.Run("clears the session cookie", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		token := createSessionToken(t, app, "alice", time.Now())

		response := post(t, app, token)

		require.Equal(t, http.StatusOK, response.Code)
		var cleared *http.Cookie
		for _, cookie := range response.Result().Cookies() {
			if cookie.Name == sessionCookieName {
				cleared = cookie
			}
		}
		require.NotNil(t, cleared)
		require.LessOrEqual(t, cleared.MaxAge, 0)
		require.True(t, cleared.HttpOnly)
		require.True(t, cleared.Secure)
	})

	t.Run("records the panic audit event", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		token := createSessionToken(t, app, "alice", time.Now())

		response := post(t, app, token)
		require.Equal(t, http.StatusOK, response.Code)

		records := panicAuditRecords(t, app)
		require.Len(t, records, 1)
		require.Equal(t, string(audit.CategoryPanicAction), records[0].Category)
		require.True(t, records[0].Sub.Valid)
		require.Equal(t, "alice", records[0].Sub.String)
		require.Equal(t, "{}", records[0].Details)
	})

	t.Run("blocks a subsequent login attempt", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		token := createSessionToken(t, app, "alice", time.Now())
		require.Equal(t, http.StatusOK, post(t, app, token).Code)

		secret, err := totp.DeriveSharedSecret(referenceRootSecret, "alice", 0)
		require.NoError(t, err)
		form := url.Values{
			"identifier": {"alice"},
			"code":       {totpCode(t, secret, time.Now())},
		}
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodPost,
			"/login?"+loginQuery(),
			strings.NewReader(form.Encode()),
		)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response := httptest.NewRecorder()
		app.server.Handler().ServeHTTP(response, request)

		require.Equal(t, http.StatusOK, response.Code)
		require.Contains(t, response.Body.String(), loginFailureMessage)
	})

	t.Run("rejects a submission without a CSRF token", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		token := createSessionToken(t, app, "alice", time.Now())

		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodPost,
			"/panic",
			strings.NewReader(""),
		)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
		response := httptest.NewRecorder()
		app.server.Handler().ServeHTTP(response, request)

		require.Equal(t, http.StatusForbidden, response.Code)

		_, err := app.sessions.Validate(context.Background(), token, time.Now())
		require.NoError(t, err)
		locked, err := app.locks.IsLocked(context.Background(), "alice")
		require.NoError(t, err)
		require.False(t, locked)
	})

	t.Run("rejects a submission with a mismatched CSRF token", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		token := createSessionToken(t, app, "alice", time.Now())

		response := httptest.NewRecorder()
		app.server.Handler().ServeHTTP(response, panicRequest("wrong-token", token))

		require.Equal(t, http.StatusForbidden, response.Code)
		_, err := app.sessions.Validate(context.Background(), token, time.Now())
		require.NoError(t, err)
	})

	t.Run("renders the sign-in-required page without a valid session", func(t *testing.T) {
		app := newTestApp(t, testUsers)

		response := post(t, app, "")

		require.Equal(t, http.StatusOK, response.Code)
		require.Contains(
			t,
			response.Body.String(),
			"Sign in is required to trigger the panic action.",
		)
		require.Empty(t, panicAuditRecords(t, app))
		locked, err := app.locks.IsLocked(context.Background(), "alice")
		require.NoError(t, err)
		require.False(t, locked)
	})

	t.Run("renders the sign-in-required page for a malformed session cookie", func(t *testing.T) {
		app := newTestApp(t, testUsers)

		response := post(t, app, "not-a-session-token")

		require.Equal(t, http.StatusOK, response.Code)
		require.Contains(
			t,
			response.Body.String(),
			"Sign in is required to trigger the panic action.",
		)
		require.Empty(t, panicAuditRecords(t, app))
	})

	t.Run("renders the sign-in-required page for an administrator session", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		loginResponse := adminLoginRequest(t, app, testAdminPassword)
		require.Equal(t, http.StatusSeeOther, loginResponse.Code)
		adminToken := adminSessionCookie(t, loginResponse)
		require.NotEmpty(t, adminToken)

		response := post(t, app, adminToken)

		require.Equal(t, http.StatusOK, response.Code)
		require.Contains(
			t,
			response.Body.String(),
			"Sign in is required to trigger the panic action.",
		)
		require.Empty(t, panicAuditRecords(t, app))
	})

	t.Run("returns 500 when session validation fails", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		app.server.panics.Sessions = failingPanicSessions{}

		response := post(t, app, "any-token")

		require.Equal(t, http.StatusInternalServerError, response.Code)
	})

	t.Run("returns 500 when the panic action fails", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		app.server.panics.Locks = failingPanicLocks{}
		token := createSessionToken(t, app, "alice", time.Now())

		response := post(t, app, token)

		require.Equal(t, http.StatusInternalServerError, response.Code)
	})

	t.Run("returns 500 when the audit record fails", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		app.server.panics.Audit = failingPanicAudit{}
		token := createSessionToken(t, app, "alice", time.Now())

		response := post(t, app, token)

		require.Equal(t, http.StatusInternalServerError, response.Code)
	})
}
