package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/varavelio/zen-idp/internal/audit"
	"github.com/varavelio/zen-idp/internal/clock"
	"github.com/varavelio/zen-idp/internal/config"
	"github.com/varavelio/zen-idp/internal/csrf"
	"github.com/varavelio/zen-idp/internal/session"
	"github.com/varavelio/zen-idp/internal/statestore"
	"github.com/varavelio/zen-idp/internal/totp"
)

// lockChangeRequest signs in as the test administrator and posts the given
// lock-management action for the given subject, returning the response.
func lockChangeRequest(
	t *testing.T,
	app *testApp,
	subject, action string,
) *httptest.ResponseRecorder {
	t.Helper()
	loginResponse := adminLoginRequest(t, app, testAdminPassword)
	require.Equal(t, http.StatusSeeOther, loginResponse.Code)
	adminToken := adminSessionCookie(t, loginResponse)
	require.NotEmpty(t, adminToken)

	csrfToken := adminCSRFToken(t, app)
	form := url.Values{
		"subject":      {subject},
		"action":       {action},
		csrf.FieldName: {csrfToken},
	}
	request := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		adminLocksAction,
		strings.NewReader(form.Encode()),
	)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(&http.Cookie{Name: adminSessionCookieName, Value: adminToken})
	request.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: csrfToken})
	response := httptest.NewRecorder()
	app.server.Handler().ServeHTTP(response, request)
	return response
}

// lockAuditRecords returns every audit record of the test app, newest
// first.
func lockAuditRecords(t *testing.T, app *testApp) []statestore.AuditRecord {
	t.Helper()
	records, err := statestore.New(app.db).ListAuditRecords(context.Background(), 10)
	require.NoError(t, err)
	return records
}

func TestProcessLockChange(t *testing.T) {
	t.Run("renders the lock-management list on the home page", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		loginResponse := adminLoginRequest(t, app, testAdminPassword)
		require.Equal(t, http.StatusSeeOther, loginResponse.Code)
		adminToken := adminSessionCookie(t, loginResponse)
		require.NotEmpty(t, adminToken)

		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodGet,
			adminLoginPath,
			nil,
		)
		request.AddCookie(&http.Cookie{Name: adminSessionCookieName, Value: adminToken})
		response := httptest.NewRecorder()
		app.server.Handler().ServeHTTP(response, request)

		require.Equal(t, http.StatusOK, response.Code)
		body := response.Body.String()
		require.Contains(t, body, "Users")
		require.Contains(t, body, "alice")
		require.Contains(t, body, "Active")
		require.Contains(t, body, `action="/admin/locks"`)
		require.Contains(t, body, `name="action"`)
		require.Contains(t, body, `value="lock"`)
	})

	t.Run("shows the login identifier and lock status of every user", func(t *testing.T) {
		users := []config.User{
			{Subject: "alice", Login: "alice@example.com"},
			{Subject: "bob"},
			{Subject: "carol"},
		}
		app := newTestApp(t, users)
		require.NoError(t, app.locks.LockSubject(context.Background(), "bob", time.Now()))
		queries := statestore.New(app.db)
		require.NoError(
			t,
			queries.CreatePanicLock(context.Background(), statestore.CreatePanicLockParams{
				Sub:       "carol",
				CreatedAt: clock.Format(time.Now()),
			}),
		)

		loginResponse := adminLoginRequest(t, app, testAdminPassword)
		adminToken := adminSessionCookie(t, loginResponse)
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodGet,
			adminLoginPath,
			nil,
		)
		request.AddCookie(&http.Cookie{Name: adminSessionCookieName, Value: adminToken})
		response := httptest.NewRecorder()
		app.server.Handler().ServeHTTP(response, request)

		require.Equal(t, http.StatusOK, response.Code)
		body := response.Body.String()
		require.Contains(t, body, "alice")
		require.Contains(t, body, "alice@example.com")
		require.Contains(t, body, "Active")
		require.Contains(t, body, "bob")
		require.Contains(t, body, "Admin locked")
		require.Contains(t, body, "carol")
		require.Contains(t, body, "Panic locked")
		require.Contains(t, body, `value="lock"`)
		require.Contains(t, body, `value="unlock"`)
		require.Contains(t, body, `value="clear_panic"`)
	})

	t.Run("submits the rendered clear-panic form value end to end", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		queries := statestore.New(app.db)
		require.NoError(
			t,
			queries.CreatePanicLock(context.Background(), statestore.CreatePanicLockParams{
				Sub:       "alice",
				CreatedAt: clock.Format(time.Now()),
			}),
		)

		loginResponse := adminLoginRequest(t, app, testAdminPassword)
		adminToken := adminSessionCookie(t, loginResponse)
		require.NotEmpty(t, adminToken)

		// Render the home page and extract the exact action value the
		// rendered form submits for the panic lock, so the test exercises
		// the real UI-to-handler contract instead of a hand-written value.
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodGet,
			adminLoginPath,
			nil,
		)
		request.AddCookie(&http.Cookie{Name: adminSessionCookieName, Value: adminToken})
		response := httptest.NewRecorder()
		app.server.Handler().ServeHTTP(response, request)
		require.Equal(t, http.StatusOK, response.Code)
		action := extractFormValue(t, response.Body.String(), "Clear panic")
		require.Equal(t, lockActionClearPanic, action)

		csrfToken := adminCSRFToken(t, app)
		form := url.Values{
			"subject":      {"alice"},
			"action":       {action},
			csrf.FieldName: {csrfToken},
		}
		request = httptest.NewRequestWithContext(
			context.Background(),
			http.MethodPost,
			adminLocksAction,
			strings.NewReader(form.Encode()),
		)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.AddCookie(&http.Cookie{Name: adminSessionCookieName, Value: adminToken})
		request.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: csrfToken})
		response = httptest.NewRecorder()
		app.server.Handler().ServeHTTP(response, request)
		require.Equal(t, http.StatusOK, response.Code)
		require.NotContains(t, response.Body.String(), lockInvalidAction)

		panicked, err := app.locks.IsPanicked(context.Background(), "alice")
		require.NoError(t, err)
		require.False(t, panicked)
	})

	t.Run("shows a placeholder when no users are configured", func(t *testing.T) {
		app := newTestApp(t, nil)
		loginResponse := adminLoginRequest(t, app, testAdminPassword)
		adminToken := adminSessionCookie(t, loginResponse)
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodGet,
			adminLoginPath,
			nil,
		)
		request.AddCookie(&http.Cookie{Name: adminSessionCookieName, Value: adminToken})
		response := httptest.NewRecorder()
		app.server.Handler().ServeHTTP(response, request)

		require.Equal(t, http.StatusOK, response.Code)
		require.Contains(t, response.Body.String(), "No users are configured.")
	})

	t.Run("locks the subject and revokes its sessions", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		userToken, err := app.sessions.Create(context.Background(), session.CreateParams{
			Subject: "alice",
			Now:     time.Now(),
		})
		require.NoError(t, err)

		response := lockChangeRequest(t, app, "alice", lockActionLock)

		require.Equal(t, http.StatusOK, response.Code)
		require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
		require.Contains(t, response.Body.String(), "Admin locked")

		locked, err := app.locks.IsAdminLocked(context.Background(), "alice")
		require.NoError(t, err)
		require.True(t, locked)

		// The session created before the lock is revoked, so SSO use
		// stops immediately.
		_, err = app.sessions.Validate(context.Background(), userToken, time.Now().Add(time.Hour))
		require.ErrorIs(t, err, session.ErrInvalidSession)

		records := lockAuditRecords(t, app)
		require.Len(t, records, 2)
		require.Equal(t, string(audit.CategoryLockChanged), records[0].Category)
		require.Equal(t, "alice", records[0].Sub.String)
		require.Equal(t, `{"action":"lock"}`, records[0].Details)
	})

	t.Run("blocks the locked subject from signing in", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		response := lockChangeRequest(t, app, "alice", lockActionLock)
		require.Equal(t, http.StatusOK, response.Code)

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
		loginResponse := httptest.NewRecorder()
		app.server.Handler().ServeHTTP(loginResponse, request)

		require.Equal(t, http.StatusOK, loginResponse.Code)
		require.Contains(
			t,
			loginResponse.Body.String(),
			"Sign-in failed. Check your identifier and code.",
		)
		require.Empty(t, loginResponse.Result().Cookies())
	})

	t.Run("stops SSO continuation for the locked subject", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		userToken, err := app.sessions.Create(context.Background(), session.CreateParams{
			Subject: "alice",
			Now:     time.Now(),
		})
		require.NoError(t, err)

		// Before the lock, the session completes the authorization flow.
		authorize := func() *httptest.ResponseRecorder {
			request := buildAuthorizeRequest(t, validPublicRequest())
			request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: userToken})
			response := httptest.NewRecorder()
			app.server.Handler().ServeHTTP(response, request)
			return response
		}
		before := authorize()
		require.Equal(t, http.StatusFound, before.Code)
		location, err := url.Parse(before.Header().Get("Location"))
		require.NoError(t, err)
		require.Equal(t, "app.example.com", location.Host)
		require.Contains(t, location.Query(), "code")

		// After the lock, the revoked session cannot continue the flow.
		response := lockChangeRequest(t, app, "alice", lockActionLock)
		require.Equal(t, http.StatusOK, response.Code)

		after := authorize()
		require.Equal(t, http.StatusFound, after.Code)
		location, err = url.Parse(after.Header().Get("Location"))
		require.NoError(t, err)
		require.Equal(t, "/login", location.Path)
	})

	t.Run("unlocks the subject", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		response := lockChangeRequest(t, app, "alice", lockActionLock)
		require.Equal(t, http.StatusOK, response.Code)

		response = lockChangeRequest(t, app, "alice", lockActionUnlock)

		require.Equal(t, http.StatusOK, response.Code)
		require.Contains(t, response.Body.String(), "Active")

		locked, err := app.locks.IsAdminLocked(context.Background(), "alice")
		require.NoError(t, err)
		require.False(t, locked)

		// Each lock change request carries its own administrator
		// authentication event, so four records exist in total.
		records := lockAuditRecords(t, app)
		require.Len(t, records, 4)
		require.Equal(t, `{"action":"unlock"}`, records[0].Details)
		require.Equal(t, `{"action":"lock"}`, records[2].Details)
	})

	t.Run("unlock never clears a distinct panic lock", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		require.NoError(t, app.locks.LockSubject(context.Background(), "alice", time.Now()))
		queries := statestore.New(app.db)
		require.NoError(
			t,
			queries.CreatePanicLock(context.Background(), statestore.CreatePanicLockParams{
				Sub:       "alice",
				CreatedAt: clock.Format(time.Now()),
			}),
		)

		response := lockChangeRequest(t, app, "alice", lockActionUnlock)

		require.Equal(t, http.StatusOK, response.Code)
		require.Contains(t, response.Body.String(), "Panic locked")

		panicked, err := app.locks.IsPanicked(context.Background(), "alice")
		require.NoError(t, err)
		require.True(t, panicked)
		locked, err := app.locks.IsAdminLocked(context.Background(), "alice")
		require.NoError(t, err)
		require.False(t, locked)
	})

	t.Run("clear-panic clears only the panic lock", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		require.NoError(t, app.locks.LockSubject(context.Background(), "alice", time.Now()))
		queries := statestore.New(app.db)
		require.NoError(
			t,
			queries.CreatePanicLock(context.Background(), statestore.CreatePanicLockParams{
				Sub:       "alice",
				CreatedAt: clock.Format(time.Now()),
			}),
		)

		response := lockChangeRequest(t, app, "alice", lockActionClearPanic)

		require.Equal(t, http.StatusOK, response.Code)
		require.Contains(t, response.Body.String(), "Admin locked")

		panicked, err := app.locks.IsPanicked(context.Background(), "alice")
		require.NoError(t, err)
		require.False(t, panicked)
		locked, err := app.locks.IsAdminLocked(context.Background(), "alice")
		require.NoError(t, err)
		require.True(t, locked)

		records := lockAuditRecords(t, app)
		require.Len(t, records, 2)
		require.Equal(t, `{"action":"clear_panic"}`, records[0].Details)
	})

	t.Run("rejects an unknown subject", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		response := lockChangeRequest(t, app, "mallory", lockActionLock)

		require.Equal(t, http.StatusOK, response.Code)
		require.Contains(t, response.Body.String(), lockUnknownSubject)

		locked, err := app.locks.IsAdminLocked(context.Background(), "mallory")
		require.NoError(t, err)
		require.False(t, locked)

		records := lockAuditRecords(t, app)
		require.Len(t, records, 1)
		require.Equal(t, string(audit.CategoryAdminAuthentication), records[0].Category)
	})

	t.Run("rejects an unsupported action", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		response := lockChangeRequest(t, app, "alice", "ban")

		require.Equal(t, http.StatusOK, response.Code)
		require.Contains(t, response.Body.String(), lockInvalidAction)

		locked, err := app.locks.IsAdminLocked(context.Background(), "alice")
		require.NoError(t, err)
		require.False(t, locked)
	})

	t.Run("rejects a submission without a CSRF token", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		loginResponse := adminLoginRequest(t, app, testAdminPassword)
		adminToken := adminSessionCookie(t, loginResponse)
		require.NotEmpty(t, adminToken)

		form := url.Values{
			"subject": {"alice"},
			"action":  {lockActionLock},
		}
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodPost,
			adminLocksAction,
			strings.NewReader(form.Encode()),
		)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.AddCookie(&http.Cookie{Name: adminSessionCookieName, Value: adminToken})
		response := httptest.NewRecorder()

		app.server.Handler().ServeHTTP(response, request)

		require.Equal(t, http.StatusForbidden, response.Code)
		require.Contains(t, response.Body.String(), "Forbidden")
	})

	t.Run("redirects to the sign-in form without an admin session", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		csrfToken := adminCSRFToken(t, app)
		form := url.Values{
			"subject":      {"alice"},
			"action":       {lockActionLock},
			csrf.FieldName: {csrfToken},
		}
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodPost,
			adminLocksAction,
			strings.NewReader(form.Encode()),
		)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: csrfToken})
		response := httptest.NewRecorder()

		app.server.Handler().ServeHTTP(response, request)

		require.Equal(t, http.StatusSeeOther, response.Code)
		require.Equal(t, adminLoginPath, response.Header().Get("Location"))
	})

	t.Run("rejects a user SSO cookie as the admin session", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		userToken, err := app.sessions.Create(context.Background(), session.CreateParams{
			Subject: "alice",
			Now:     time.Now(),
		})
		require.NoError(t, err)
		csrfToken := adminCSRFToken(t, app)
		form := url.Values{
			"subject":      {"alice"},
			"action":       {lockActionLock},
			csrf.FieldName: {csrfToken},
		}
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodPost,
			adminLocksAction,
			strings.NewReader(form.Encode()),
		)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: userToken})
		request.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: csrfToken})
		response := httptest.NewRecorder()

		app.server.Handler().ServeHTTP(response, request)

		require.Equal(t, http.StatusSeeOther, response.Code)
		require.Equal(t, adminLoginPath, response.Header().Get("Location"))
	})

	t.Run("returns 405 for GET requests", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodGet,
			adminLocksAction,
			nil,
		)
		response := httptest.NewRecorder()

		app.server.Handler().ServeHTTP(response, request)

		require.Equal(t, http.StatusMethodNotAllowed, response.Code)
	})

	t.Run("propagates lock action failures", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		app.server.admin.Locks = failingSubjectLocks{err: errors.New("boom")}

		response := lockChangeRequest(t, app, "alice", lockActionLock)

		require.Equal(t, http.StatusInternalServerError, response.Code)
	})

	t.Run("propagates audit recording failures", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		app.server.admin.Audit = failingAuditRecorder{err: errors.New("boom")}

		response := lockChangeRequest(t, app, "alice", lockActionLock)

		require.Equal(t, http.StatusInternalServerError, response.Code)
	})
}

// failingSubjectLocks is a stub implementation that always returns the
// configured error.
type failingSubjectLocks struct{ err error }

// actionButtonPattern matches one rendered lock-management submit button,
// including any icon markup inside it.
var actionButtonPattern = regexp.MustCompile(
	`<button[^>]*name="action"[^>]*value="([^"]+)"[^>]*>[\s\S]*?</button>`,
)

// extractFormValue returns the value attribute of the first rendered submit
// button whose label contains labelText, or an empty string when no such
// button exists. It lets tests submit the exact action value the UI renders,
// keeping the UI-to-handler contract under test.
func extractFormValue(t *testing.T, html, labelText string) string {
	t.Helper()
	for _, match := range actionButtonPattern.FindAllStringSubmatch(html, -1) {
		if strings.Contains(match[0], labelText) {
			return match[1]
		}
	}
	return ""
}

func (stub failingSubjectLocks) LockSubject(context.Context, string, time.Time) error {
	return stub.err
}

func (stub failingSubjectLocks) UnlockSubject(context.Context, string) error {
	return stub.err
}

func (stub failingSubjectLocks) ClearPanic(context.Context, string) error {
	return stub.err
}

func (stub failingSubjectLocks) IsAdminLocked(context.Context, string) (bool, error) {
	return false, stub.err
}

func (stub failingSubjectLocks) IsPanicked(context.Context, string) (bool, error) {
	return false, stub.err
}
