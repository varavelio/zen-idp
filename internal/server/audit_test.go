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
	"github.com/varavelio/zen-idp/internal/clock"
	"github.com/varavelio/zen-idp/internal/session"
)

// auditLogRequest fetches the audit log page as the browser carrying the
// given administrator session cookie value, empty for an anonymous browser.
func auditLogRequest(t *testing.T, app *testApp, adminToken string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		adminAuditPath,
		nil,
	)
	if adminToken != "" {
		request.AddCookie(&http.Cookie{Name: adminSessionCookieName, Value: adminToken})
	}
	response := httptest.NewRecorder()
	app.server.Handler().ServeHTTP(response, request)
	return response
}

// adminAuditToken signs in as the test administrator and returns the
// resulting administrator session cookie value.
func adminAuditToken(t *testing.T, app *testApp) string {
	t.Helper()
	loginResponse := adminLoginRequest(t, app, testAdminPassword)
	require.Equal(t, http.StatusSeeOther, loginResponse.Code)
	token := adminSessionCookie(t, loginResponse)
	require.NotEmpty(t, token)
	return token
}

func TestAuditLog(t *testing.T) {
	t.Run("renders the most recent events newest first", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		recorder, ok := app.server.admin.Audit.(*audit.Recorder)
		require.True(t, ok)
		base := time.Now().UTC().Truncate(time.Second)
		require.NoError(t, recorder.Record(context.Background(), audit.RecordParams{
			Category: audit.CategoryRateLimit,
			Details:  map[string]any{"key": "older"},
			Now:      base.Add(-2 * time.Minute),
		}))
		require.NoError(t, recorder.Record(context.Background(), audit.RecordParams{
			Category: audit.CategorySessionRevoked,
			Subject:  "alice",
			Details:  map[string]any{"key": "newer"},
			Now:      base,
		}))

		response := auditLogRequest(t, app, adminAuditToken(t, app))

		require.Equal(t, http.StatusOK, response.Code)
		require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
		body := response.Body.String()
		require.Contains(t, body, "rate_limit")
		require.Contains(t, body, "session_revoked")
		require.Contains(t, body, "Subject: alice")
		require.Contains(t, body, "newer")
		require.Contains(t, body, "older")
		require.Contains(t, body, clock.Format(base))
		require.Less(
			t,
			strings.Index(body, "session_revoked"),
			strings.Index(body, "rate_limit"),
		)
	})

	t.Run("shows events recorded by administration actions", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		response := enrollmentTokenRequest(t, app, url.Values{
			"subject":  {"alice"},
			"duration": {"30m"},
		})
		require.Equal(t, http.StatusOK, response.Code)

		response = auditLogRequest(t, app, adminAuditToken(t, app))

		require.Equal(t, http.StatusOK, response.Code)
		body := response.Body.String()
		require.Contains(t, body, "admin_authentication")
		require.Contains(t, body, "enrollment_token_created")
		require.Contains(t, body, "Subject: alice")
		require.Contains(t, body, "expires_at")
	})

	t.Run("shows a placeholder when no events exist", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		// The session is created directly so that no authentication
		// event is recorded and the log is truly empty.
		adminToken, err := app.sessions.CreateAdmin(
			context.Background(),
			session.AdminParams{Now: time.Now()},
		)
		require.NoError(t, err)

		response := auditLogRequest(t, app, adminToken)

		require.Equal(t, http.StatusOK, response.Code)
		require.Contains(t, response.Body.String(), "No audit records yet.")
	})

	t.Run("shows the sign-in form to anonymous visitors", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		response := auditLogRequest(t, app, "")

		require.Equal(t, http.StatusOK, response.Code)
		body := response.Body.String()
		require.Contains(t, body, "Administrator sign-in")
		require.NotContains(t, body, "No audit records yet.")
	})

	t.Run("shows the sign-in form for a malformed admin cookie", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		response := auditLogRequest(t, app, "not-a-token")

		require.Equal(t, http.StatusOK, response.Code)
		require.Contains(t, response.Body.String(), "Administrator sign-in")
	})

	t.Run("shows the sign-in form for an expired admin session", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		expiredToken, err := app.sessions.CreateAdmin(
			context.Background(),
			session.AdminParams{Now: time.Now().Add(-testMaxAge - time.Hour)},
		)
		require.NoError(t, err)

		response := auditLogRequest(t, app, expiredToken)

		require.Equal(t, http.StatusOK, response.Code)
		require.Contains(t, response.Body.String(), "Administrator sign-in")
	})

	t.Run("rejects a user SSO cookie as the admin session", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		userToken, err := app.sessions.Create(context.Background(), session.CreateParams{
			Subject: "alice",
			Now:     time.Now(),
		})
		require.NoError(t, err)

		response := auditLogRequest(t, app, userToken)

		require.Equal(t, http.StatusOK, response.Code)
		require.Contains(t, response.Body.String(), "Administrator sign-in")
	})

	t.Run("returns 405 for POST requests", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodPost,
			adminAuditPath,
			nil,
		)
		response := httptest.NewRecorder()

		app.server.Handler().ServeHTTP(response, request)

		require.Equal(t, http.StatusMethodNotAllowed, response.Code)
	})

	t.Run("propagates audit listing failures", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		app.server.admin.AuditLog = failingAuditLister{err: errors.New("boom")}

		response := auditLogRequest(t, app, adminAuditToken(t, app))

		require.Equal(t, http.StatusInternalServerError, response.Code)
	})
}

// failingAuditLister is a stub implementation that always returns the
// configured error.
type failingAuditLister struct{ err error }

func (stub failingAuditLister) List(context.Context, int) ([]audit.Event, error) {
	return nil, stub.err
}
