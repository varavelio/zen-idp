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
	"github.com/varavelio/zen-idp/internal/config"
	"github.com/varavelio/zen-idp/internal/csrf"
	"github.com/varavelio/zen-idp/internal/onetoken"
	"github.com/varavelio/zen-idp/internal/session"
	"github.com/varavelio/zen-idp/internal/statestore"
	"github.com/varavelio/zen-idp/internal/totp"
)

// testAdminPassword is the plaintext administrator credential of the test
// app and testAdminPasswordHash is its precomputed Argon2id PHC hash,
// anchored as a regression vector.
const (
	testAdminPassword     = "test-admin-password"
	testAdminPasswordHash = "$argon2id$v=19$m=65536,t=2,p=2$INy39hwa9rMN8WhprspfDQ$45uH4EsaLtb2h9bUkVfgAAoLKsgPK1ALYprlwxm16B4"
)

// adminTestMaxAttempts and adminTestWindow bound the admin rate limiter of
// the test app.
const (
	adminTestMaxAttempts = 3
	adminTestWindow      = time.Hour
)

// adminCSRFToken fetches the administration landing page and returns the
// anti-forgery token it issues, exactly as a browser would receive it.
func adminCSRFToken(t *testing.T, app *testApp) string {
	t.Helper()
	request := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		adminLoginPath,
		nil,
	)
	response := httptest.NewRecorder()
	app.server.Handler().ServeHTTP(response, request)
	require.Equal(t, http.StatusOK, response.Code)
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == CSRFCookieName {
			return cookie.Value
		}
	}
	require.FailNow(t, "no CSRF cookie in response")
	return ""
}

// adminLoginRequest posts the given password to the administrator sign-in
// form, first obtaining the anti-forgery token from the landing page and
// echoing it back exactly as a browser would.
func adminLoginRequest(t *testing.T, app *testApp, password string) *httptest.ResponseRecorder {
	t.Helper()
	token := adminCSRFToken(t, app)
	form := url.Values{
		"password":     {password},
		csrf.FieldName: {token},
	}
	request := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		adminLoginAction,
		strings.NewReader(form.Encode()),
	)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: token})
	response := httptest.NewRecorder()
	app.server.Handler().ServeHTTP(response, request)
	return response
}

// adminSessionCookie returns the administrator session cookie set by a
// response, or an empty value when none was set.
func adminSessionCookie(t *testing.T, response *httptest.ResponseRecorder) string {
	t.Helper()
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == adminSessionCookieName {
			return cookie.Value
		}
	}
	return ""
}

// enrollmentTokenRequest signs in as the test administrator, obtains the
// anti-forgery token, and posts the given form values to the
// enrollment-token creation endpoint, returning the response.
func enrollmentTokenRequest(
	t *testing.T,
	app *testApp,
	form url.Values,
) *httptest.ResponseRecorder {
	t.Helper()
	loginResponse := adminLoginRequest(t, app, testAdminPassword)
	require.Equal(t, http.StatusSeeOther, loginResponse.Code)
	adminToken := adminSessionCookie(t, loginResponse)
	require.NotEmpty(t, adminToken)

	csrfToken := adminCSRFToken(t, app)
	form.Set(csrf.FieldName, csrfToken)

	request := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		adminTokensAction,
		strings.NewReader(form.Encode()),
	)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(&http.Cookie{Name: adminSessionCookieName, Value: adminToken})
	request.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: csrfToken})
	response := httptest.NewRecorder()
	app.server.Handler().ServeHTTP(response, request)
	return response
}

// enrollmentTokenFromBody extracts the tok_{id}_{secret} credential shown
// by an enrollment-token creation response.
func enrollmentTokenFromBody(t *testing.T, body string) string {
	t.Helper()
	start := strings.Index(body, "tok_")
	require.NotEqual(t, -1, start, "no enrollment token in response body")
	rest := body[start:]
	end := strings.IndexByte(rest, '<')
	require.NotEqual(t, -1, end, "enrollment token is not terminated")
	return rest[:end]
}

func TestAdminForm(t *testing.T) {
	t.Run("renders the sign-in form for anonymous visitors", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodGet,
			adminLoginPath,
			nil,
		)
		response := httptest.NewRecorder()

		app.server.Handler().ServeHTTP(response, request)

		require.Equal(t, http.StatusOK, response.Code)
		require.Contains(t, response.Body.String(), "Administrator sign-in")
		require.Contains(t, response.Body.String(), `action="/admin/login"`)
		require.Contains(t, response.Body.String(), `name="csrf_token"`)
		require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
	})

	t.Run("sets the anti-forgery cookie for anonymous visitors", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodGet,
			adminLoginPath,
			nil,
		)
		response := httptest.NewRecorder()

		app.server.Handler().ServeHTTP(response, request)

		cookie := response.Result().Cookies()
		require.Len(t, cookie, 1)
		require.Equal(t, CSRFCookieName, cookie[0].Name)
		require.NotEmpty(t, cookie[0].Value)
		require.True(t, cookie[0].HttpOnly)
		require.True(t, cookie[0].Secure)
		require.Equal(t, http.SameSiteLaxMode, cookie[0].SameSite)
		require.Equal(t, "/", cookie[0].Path)
	})

	t.Run("renders the administration home for a valid admin session", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		loginResponse := adminLoginRequest(t, app, testAdminPassword)
		require.Equal(t, http.StatusSeeOther, loginResponse.Code)
		token := adminSessionCookie(t, loginResponse)
		require.NotEmpty(t, token)

		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodGet,
			adminLoginPath,
			nil,
		)
		request.AddCookie(&http.Cookie{Name: adminSessionCookieName, Value: token})
		response := httptest.NewRecorder()

		app.server.Handler().ServeHTTP(response, request)

		require.Equal(t, http.StatusOK, response.Code)
		require.Contains(t, response.Body.String(), "Signed in as administrator.")
		require.Contains(t, response.Body.String(), `action="/admin/logout"`)
		require.Contains(t, response.Body.String(), `name="csrf_token"`)
		require.NotContains(t, response.Body.String(), "Administrator sign-in")
	})

	t.Run("renders the sign-in form for an invalid admin session cookie", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodGet,
			adminLoginPath,
			nil,
		)
		request.AddCookie(&http.Cookie{
			Name:  adminSessionCookieName,
			Value: "sess_forged_secret",
		})
		response := httptest.NewRecorder()

		app.server.Handler().ServeHTTP(response, request)

		require.Equal(t, http.StatusOK, response.Code)
		require.Contains(t, response.Body.String(), "Administrator sign-in")
	})

	t.Run("rejects a user SSO cookie as an admin session", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		userToken, err := app.sessions.Create(context.Background(), session.CreateParams{
			Subject: "alice",
			Now:     time.Now(),
		})
		require.NoError(t, err)

		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodGet,
			adminLoginPath,
			nil,
		)
		request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: userToken})
		response := httptest.NewRecorder()

		app.server.Handler().ServeHTTP(response, request)

		require.Equal(t, http.StatusOK, response.Code)
		require.Contains(t, response.Body.String(), "Administrator sign-in")
	})
}

func TestProcessAdminLogin(t *testing.T) {
	t.Run("authenticates and issues the admin session cookie", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		response := adminLoginRequest(t, app, testAdminPassword)

		require.Equal(t, http.StatusSeeOther, response.Code)
		require.Equal(t, adminLoginPath, response.Header().Get("Location"))

		cookie := response.Result().Cookies()
		require.Len(t, cookie, 1)
		require.Equal(t, adminSessionCookieName, cookie[0].Name)
		require.True(t, cookie[0].HttpOnly)
		require.True(t, cookie[0].Secure)
		require.Equal(t, http.SameSiteLaxMode, cookie[0].SameSite)
		require.Equal(t, int(testMaxAge.Seconds()), cookie[0].MaxAge)
		require.Equal(t, "/", cookie[0].Path)
	})

	t.Run("the issued session validates as an admin session", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		response := adminLoginRequest(t, app, testAdminPassword)
		token := adminSessionCookie(t, response)

		record, err := app.sessions.ValidateAdmin(
			context.Background(), token, time.Now().Add(time.Hour),
		)
		require.NoError(t, err)
		require.Equal(t, session.KindAdmin, record.Kind)

		_, err = app.sessions.Validate(context.Background(), token, time.Now().Add(time.Hour))
		require.ErrorIs(t, err, session.ErrInvalidSession)
	})

	t.Run("clears the Secure flag when the issuer is not HTTPS", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		app.server.admin.SecureCookies = false

		response := adminLoginRequest(t, app, testAdminPassword)

		cookie := response.Result().Cookies()
		require.Len(t, cookie, 1)
		require.False(t, cookie[0].Secure)
	})

	t.Run("rejects a submission without a CSRF token", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		form := url.Values{"password": {testAdminPassword}}
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodPost,
			adminLoginAction,
			strings.NewReader(form.Encode()),
		)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response := httptest.NewRecorder()

		app.server.Handler().ServeHTTP(response, request)

		require.Equal(t, http.StatusForbidden, response.Code)
		require.Contains(t, response.Body.String(), "Forbidden")
		require.Empty(t, adminSessionCookie(t, response))
		require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
	})

	t.Run("rejects a submission with a mismatched CSRF token", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		cookieToken := adminCSRFToken(t, app)
		fieldToken := adminCSRFToken(t, app)
		require.NotEqual(t, cookieToken, fieldToken)
		form := url.Values{
			"password":     {testAdminPassword},
			csrf.FieldName: {fieldToken},
		}
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodPost,
			adminLoginAction,
			strings.NewReader(form.Encode()),
		)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: cookieToken})
		response := httptest.NewRecorder()

		app.server.Handler().ServeHTTP(response, request)

		require.Equal(t, http.StatusForbidden, response.Code)
		require.Empty(t, adminSessionCookie(t, response))
	})

	t.Run("rejects a wrong password with the generic message", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		response := adminLoginRequest(t, app, "wrong-password")

		require.Equal(t, http.StatusOK, response.Code)
		require.Contains(t, response.Body.String(), "Administrator sign-in failed.")
		require.Empty(t, adminSessionCookie(t, response))
		require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
	})

	t.Run("rejects an empty password indistinguishably", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		response := adminLoginRequest(t, app, "")

		require.Equal(t, http.StatusOK, response.Code)
		require.Contains(t, response.Body.String(), "Administrator sign-in failed.")
		require.Empty(t, adminSessionCookie(t, response))
	})

	t.Run("throttles after exhausting the attempt budget", func(t *testing.T) {
		app := newTestApp(t, testUsers)

		for range adminTestMaxAttempts {
			response := adminLoginRequest(t, app, "wrong-password")
			require.Equal(t, http.StatusOK, response.Code)
		}

		// The budget is exhausted: even the correct password is denied.
		response := adminLoginRequest(t, app, testAdminPassword)
		require.Equal(t, http.StatusOK, response.Code)
		require.Contains(t, response.Body.String(), "Administrator sign-in failed.")
		require.Empty(t, adminSessionCookie(t, response))
	})

	t.Run("records audit events for denied and granted logins", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		adminLoginRequest(t, app, "wrong-password")
		adminLoginRequest(t, app, testAdminPassword)

		queries := statestore.New(app.db)
		records, err := queries.ListAuditRecords(context.Background(), 10)
		require.NoError(t, err)
		require.Len(t, records, 2)
		require.Equal(t, string(audit.CategoryAdminAuthentication), records[0].Category)
		require.Equal(t, `{"outcome":"success"}`, records[0].Details)
		require.Equal(t, string(audit.CategoryAdminAuthentication), records[1].Category)
		require.Equal(t, `{"outcome":"failure"}`, records[1].Details)
	})
}

func TestProcessEnrollmentToken(t *testing.T) {
	t.Run("renders the enrollment-token creation form on the home page", func(t *testing.T) {
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
		require.Contains(t, body, "Create enrollment token")
		require.Contains(t, body, `action="/admin/tokens"`)
		require.Contains(t, body, `name="subject"`)
		require.Contains(t, body, `name="duration"`)
		require.Contains(t, body, `name="deadline"`)
		require.Contains(t, body, `name="csrf_token"`)
	})

	t.Run("creates a token with a relative duration", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		form := url.Values{
			"subject":  {"alice"},
			"duration": {"24h"},
		}

		response := enrollmentTokenRequest(t, app, form)

		require.Equal(t, http.StatusOK, response.Code)
		require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
		body := response.Body.String()
		require.Contains(t, body, "Enrollment token created.")
		require.Contains(t, body, "Subject: alice")
		require.Contains(t, body, "Copy this token now. It will not be shown again.")
		require.Contains(t, body, `href="/admin"`)

		token := enrollmentTokenFromBody(t, body)
		require.True(t, strings.HasPrefix(token, "tok_"))

		// The shown credential redeems the enrollment exactly once, bound
		// to the configured subject and revision with the normalized
		// absolute expiration.
		enrollment, err := app.codes.ConsumeEnrollment(
			context.Background(), token, time.Now().Add(23*time.Hour),
		)
		require.NoError(t, err)
		require.Equal(t, "alice", enrollment.Subject)
		require.Zero(t, enrollment.TOTPRev)
		require.WithinDuration(t, time.Now().Add(24*time.Hour), enrollment.ExpiresAt, time.Minute)
	})

	t.Run("uses the configured TOTP revision of the subject", func(t *testing.T) {
		users := []config.User{{Subject: "alice", TOTPRevision: 3}}
		app := newTestApp(t, users)
		form := url.Values{
			"subject":  {"alice"},
			"duration": {"24h"},
		}

		response := enrollmentTokenRequest(t, app, form)

		require.Equal(t, http.StatusOK, response.Code)
		token := enrollmentTokenFromBody(t, response.Body.String())
		enrollment, err := app.codes.ConsumeEnrollment(
			context.Background(), token, time.Now().Add(23*time.Hour),
		)
		require.NoError(t, err)
		require.Equal(t, uint64(3), enrollment.TOTPRev)
	})

	t.Run("creates a token with an absolute deadline", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		form := url.Values{
			"subject":  {"alice"},
			"deadline": {"2099-01-02T15:04:05Z"},
		}

		response := enrollmentTokenRequest(t, app, form)

		require.Equal(t, http.StatusOK, response.Code)
		token := enrollmentTokenFromBody(t, response.Body.String())
		enrollment, err := app.codes.ConsumeEnrollment(
			context.Background(), token, time.Now().Add(time.Hour),
		)
		require.NoError(t, err)
		require.Equal(
			t,
			time.Date(2099, 1, 2, 15, 4, 5, 0, time.UTC),
			enrollment.ExpiresAt,
		)
	})

	t.Run("normalizes an offset deadline to UTC", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		form := url.Values{
			"subject":  {"alice"},
			"deadline": {"2099-01-02T17:04:05+02:00"},
		}

		response := enrollmentTokenRequest(t, app, form)

		require.Equal(t, http.StatusOK, response.Code)
		token := enrollmentTokenFromBody(t, response.Body.String())
		enrollment, err := app.codes.ConsumeEnrollment(
			context.Background(), token, time.Now().Add(time.Hour),
		)
		require.NoError(t, err)
		require.Equal(
			t,
			time.Date(2099, 1, 2, 15, 4, 5, 0, time.UTC),
			enrollment.ExpiresAt,
		)
	})

	t.Run("records an audit event with the absolute expiration only", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		form := url.Values{
			"subject":  {"alice"},
			"deadline": {"2099-01-02T15:04:05Z"},
		}

		response := enrollmentTokenRequest(t, app, form)
		require.Equal(t, http.StatusOK, response.Code)

		queries := statestore.New(app.db)
		records, err := queries.ListAuditRecords(context.Background(), 10)
		require.NoError(t, err)
		require.Len(t, records, 2)
		require.Equal(t, string(audit.CategoryEnrollmentTokenCreated), records[0].Category)
		require.Equal(t, "alice", records[0].Sub.String)
		require.Equal(t, `{"expires_at":"2099-01-02T15:04:05Z"}`, records[0].Details)
		require.NotContains(t, records[0].Details, "tok_")
	})

	t.Run("rejects an unknown subject", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		form := url.Values{
			"subject":  {"mallory"},
			"duration": {"24h"},
		}

		response := enrollmentTokenRequest(t, app, form)

		require.Equal(t, http.StatusOK, response.Code)
		require.Contains(t, response.Body.String(), enrollmentUnknownSubject)
		require.Contains(t, response.Body.String(), `name="csrf_token"`)
	})

	t.Run("rejects an empty subject", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		form := url.Values{"duration": {"24h"}}

		response := enrollmentTokenRequest(t, app, form)

		require.Equal(t, http.StatusOK, response.Code)
		require.Contains(t, response.Body.String(), enrollmentUnknownSubject)
	})

	t.Run("rejects both a duration and a deadline", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		form := url.Values{
			"subject":  {"alice"},
			"duration": {"24h"},
			"deadline": {"2099-01-02T15:04:05Z"},
		}

		response := enrollmentTokenRequest(t, app, form)

		require.Equal(t, http.StatusOK, response.Code)
		require.Contains(t, response.Body.String(), enrollmentBothExpirations)
	})

	t.Run("rejects neither a duration nor a deadline", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		form := url.Values{"subject": {"alice"}}

		response := enrollmentTokenRequest(t, app, form)

		require.Equal(t, http.StatusOK, response.Code)
		require.Contains(t, response.Body.String(), enrollmentMissingExpiration)
	})

	t.Run("rejects a malformed duration", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		form := url.Values{
			"subject":  {"alice"},
			"duration": {"not-a-duration"},
		}

		response := enrollmentTokenRequest(t, app, form)

		require.Equal(t, http.StatusOK, response.Code)
		require.Contains(t, response.Body.String(), enrollmentInvalidDuration)
	})

	t.Run("rejects a non-positive duration", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		form := url.Values{
			"subject":  {"alice"},
			"duration": {"0s"},
		}

		response := enrollmentTokenRequest(t, app, form)

		require.Equal(t, http.StatusOK, response.Code)
		require.Contains(t, response.Body.String(), enrollmentInvalidDuration)
	})

	t.Run("rejects a malformed deadline", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		form := url.Values{
			"subject":  {"alice"},
			"deadline": {"next week"},
		}

		response := enrollmentTokenRequest(t, app, form)

		require.Equal(t, http.StatusOK, response.Code)
		require.Contains(t, response.Body.String(), enrollmentInvalidDeadline)
	})

	t.Run("rejects a past deadline", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		form := url.Values{
			"subject":  {"alice"},
			"deadline": {"2020-01-01T00:00:00Z"},
		}

		response := enrollmentTokenRequest(t, app, form)

		require.Equal(t, http.StatusOK, response.Code)
		require.Contains(t, response.Body.String(), enrollmentPastDeadline)
	})

	t.Run("rejected submissions record no enrollment event", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		form := url.Values{
			"subject":  {"mallory"},
			"duration": {"24h"},
		}

		response := enrollmentTokenRequest(t, app, form)
		require.Equal(t, http.StatusOK, response.Code)

		queries := statestore.New(app.db)
		records, err := queries.ListAuditRecords(context.Background(), 10)
		require.NoError(t, err)
		require.Len(t, records, 1)
		require.Equal(t, string(audit.CategoryAdminAuthentication), records[0].Category)
	})

	t.Run("rejects a submission without a CSRF token", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		loginResponse := adminLoginRequest(t, app, testAdminPassword)
		adminToken := adminSessionCookie(t, loginResponse)
		require.NotEmpty(t, adminToken)

		form := url.Values{
			"subject":  {"alice"},
			"duration": {"24h"},
		}
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodPost,
			adminTokensAction,
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
			"duration":     {"24h"},
			csrf.FieldName: {csrfToken},
		}
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodPost,
			adminTokensAction,
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
			"duration":     {"24h"},
			csrf.FieldName: {csrfToken},
		}
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodPost,
			adminTokensAction,
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
			adminTokensAction,
			nil,
		)
		response := httptest.NewRecorder()

		app.server.Handler().ServeHTTP(response, request)

		require.Equal(t, http.StatusMethodNotAllowed, response.Code)
	})

	t.Run("propagates enrollment creation failures", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		app.server.admin.Enrollments = failingEnrollmentCreator{err: errors.New("boom")}
		form := url.Values{
			"subject":  {"alice"},
			"duration": {"24h"},
		}

		response := enrollmentTokenRequest(t, app, form)

		require.Equal(t, http.StatusInternalServerError, response.Code)
	})

	t.Run("propagates audit recording failures", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		app.server.admin.Audit = failingAuditRecorder{err: errors.New("boom")}
		form := url.Values{
			"subject":  {"alice"},
			"duration": {"24h"},
		}

		response := enrollmentTokenRequest(t, app, form)

		require.Equal(t, http.StatusInternalServerError, response.Code)
	})
}

func TestAdminInfrastructureErrors(t *testing.T) {
	t.Run("failing admin service returns 500", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		app.server.admin.Service = failingAdminService{err: errors.New("boom")}

		response := adminLoginRequest(t, app, testAdminPassword)

		require.Equal(t, http.StatusInternalServerError, response.Code)
	})

	t.Run("failing admin session validation returns 500", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		app.server.admin.Sessions = failingAdminSessions{err: errors.New("boom")}

		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodGet,
			adminLoginPath,
			nil,
		)
		request.AddCookie(&http.Cookie{
			Name:  adminSessionCookieName,
			Value: "sess_someid_somesecret",
		})
		response := httptest.NewRecorder()

		app.server.Handler().ServeHTTP(response, request)

		require.Equal(t, http.StatusInternalServerError, response.Code)
	})
}

// TestAdminLogOut covers the administrator sign-out interaction.
func TestAdminLogOut(t *testing.T) {
	// signInAndGetCookie performs an administrator sign-in and returns the
	// issued admin session cookie value.
	signInAndGetCookie := func(t *testing.T, app *testApp) string {
		t.Helper()
		response := adminLoginRequest(t, app, testAdminPassword)
		token := adminSessionCookie(t, response)
		require.NotEmpty(t, token)
		return token
	}

	// logOut issues a POST /admin/logout request with a valid anti-forgery
	// token and the given cookies, returning the response.
	logOut := func(t *testing.T, app *testApp, cookies ...*http.Cookie) *httptest.ResponseRecorder {
		t.Helper()
		token := adminCSRFToken(t, app)
		form := url.Values{csrf.FieldName: {token}}
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodPost,
			adminLogoutPath,
			strings.NewReader(form.Encode()),
		)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: token})
		for _, cookie := range cookies {
			request.AddCookie(cookie)
		}
		response := httptest.NewRecorder()
		app.server.Handler().ServeHTTP(response, request)
		return response
	}

	t.Run("revokes the admin session and returns to the sign-in form", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		token := signInAndGetCookie(t, app)

		response := logOut(t, app, &http.Cookie{Name: adminSessionCookieName, Value: token})

		require.Equal(t, http.StatusSeeOther, response.Code)
		require.Equal(t, adminLoginPath, response.Header().Get("Location"))
		require.Equal(t, "no-store", response.Header().Get("Cache-Control"))

		_, err := app.sessions.ValidateAdmin(
			context.Background(), token, time.Now().Add(time.Hour),
		)
		require.ErrorIs(t, err, session.ErrInvalidSession)
	})

	t.Run("clears the admin session cookie", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		token := signInAndGetCookie(t, app)

		response := logOut(t, app, &http.Cookie{Name: adminSessionCookieName, Value: token})

		cookie := response.Result().Cookies()
		require.Len(t, cookie, 1)
		require.Equal(t, adminSessionCookieName, cookie[0].Name)
		require.Empty(t, cookie[0].Value)
		require.Equal(t, -1, cookie[0].MaxAge)
		require.True(t, cookie[0].HttpOnly)
	})

	t.Run("succeeds without an admin session cookie", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		response := logOut(t, app)

		require.Equal(t, http.StatusSeeOther, response.Code)
		require.Equal(t, adminLoginPath, response.Header().Get("Location"))
		cookie := response.Result().Cookies()
		require.Len(t, cookie, 1)
		require.Empty(t, cookie[0].Value)
	})

	t.Run("ignores a malformed admin session cookie", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		response := logOut(t, app, &http.Cookie{Name: adminSessionCookieName, Value: "garbage"})

		require.Equal(t, http.StatusSeeOther, response.Code)
		require.Equal(t, adminLoginPath, response.Header().Get("Location"))
	})

	t.Run("leaves the user SSO session untouched", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		adminToken := signInAndGetCookie(t, app)

		userToken, err := app.sessions.Create(context.Background(), session.CreateParams{
			Subject: "alice",
			Now:     time.Now(),
		})
		require.NoError(t, err)

		response := logOut(
			t,
			app,
			&http.Cookie{Name: adminSessionCookieName, Value: adminToken},
			&http.Cookie{Name: sessionCookieName, Value: userToken},
		)

		require.Equal(t, http.StatusSeeOther, response.Code)
		require.Len(t, response.Result().Cookies(), 1)
		require.Equal(t, adminSessionCookieName, response.Result().Cookies()[0].Name)

		// The user session is still active after the admin sign-out.
		record, err := app.sessions.Validate(
			context.Background(), userToken, time.Now().Add(time.Hour),
		)
		require.NoError(t, err)
		require.Equal(t, "alice", record.Subject)
	})

	t.Run("rejects a sign-out without a valid CSRF token", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		token := signInAndGetCookie(t, app)

		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodPost,
			adminLogoutPath,
			nil,
		)
		request.AddCookie(&http.Cookie{Name: adminSessionCookieName, Value: token})
		response := httptest.NewRecorder()

		app.server.Handler().ServeHTTP(response, request)

		require.Equal(t, http.StatusForbidden, response.Code)
		require.Contains(t, response.Body.String(), "Forbidden")

		// The admin session survives the rejected sign-out.
		_, err := app.sessions.ValidateAdmin(
			context.Background(), token, time.Now().Add(time.Hour),
		)
		require.NoError(t, err)
	})

	t.Run("returns 405 for GET requests", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodGet,
			adminLogoutPath,
			nil,
		)
		response := httptest.NewRecorder()

		app.server.Handler().ServeHTTP(response, request)

		require.Equal(t, http.StatusMethodNotAllowed, response.Code)
	})

	t.Run("propagates revocation failures", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		app.server.admin.Sessions = failingAdminSessions{err: errors.New("boom")}

		response := logOut(
			t,
			app,
			&http.Cookie{Name: adminSessionCookieName, Value: "sess_someid_somesecret"},
		)

		require.Equal(t, http.StatusInternalServerError, response.Code)
	})
}

// TestAdminCookieIndependentOfUserLogin verifies the admin session cookie
// never grants SSO access: the /authorize flow ignores it entirely and
// continues to the login interaction.
func TestAdminCookieIndependentOfUserLogin(t *testing.T) {
	app := newTestApp(t, testUsers)
	response := adminLoginRequest(t, app, testAdminPassword)
	token := adminSessionCookie(t, response)
	require.NotEmpty(t, token)

	request := buildAuthorizeRequest(t, validPublicRequest())
	request.AddCookie(&http.Cookie{Name: adminSessionCookieName, Value: token})
	responseRecorder := httptest.NewRecorder()

	app.server.Handler().ServeHTTP(responseRecorder, request)

	// No valid user session: the flow continues to the login interaction.
	require.Equal(t, http.StatusFound, responseRecorder.Code)
	location, err := url.Parse(responseRecorder.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "/login", location.Path)
}

// TestAdminAndUserCookiesCoexist verifies that the administrator and the
// regular user can be signed in simultaneously in the same browser: the two
// credentials travel in distinct cookies, each session stays valid in its
// own domain, and neither cookie grants access to the other domain.
func TestAdminAndUserCookiesCoexist(t *testing.T) {
	app := newTestApp(t, testUsers)

	// Sign in as the administrator and as the regular user alice.
	adminResponse := adminLoginRequest(t, app, testAdminPassword)
	adminToken := adminSessionCookie(t, adminResponse)
	require.NotEmpty(t, adminToken)

	secret, err := totp.DeriveSharedSecret(referenceRootSecret, "alice", 0)
	require.NoError(t, err)
	userForm := url.Values{
		"identifier": {"alice"},
		"code":       {totpCode(t, secret, time.Now())},
	}
	userRequest := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		"/login?"+loginQuery(),
		strings.NewReader(userForm.Encode()),
	)
	userRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	userResponse := httptest.NewRecorder()
	app.server.Handler().ServeHTTP(userResponse, userRequest)
	require.Equal(t, http.StatusSeeOther, userResponse.Code)

	var userToken string
	for _, cookie := range userResponse.Result().Cookies() {
		require.Equal(t, sessionCookieName, cookie.Name)
		userToken = cookie.Value
	}
	require.NotEmpty(t, userToken)
	require.NotEqual(t, adminToken, userToken)

	// Both credentials validate simultaneously, each in its own domain.
	adminSession, err := app.sessions.ValidateAdmin(
		context.Background(), adminToken, time.Now().Add(time.Hour),
	)
	require.NoError(t, err)
	require.Equal(t, session.KindAdmin, adminSession.Kind)

	userSession, err := app.sessions.Validate(
		context.Background(), userToken, time.Now().Add(time.Hour),
	)
	require.NoError(t, err)
	require.Equal(t, session.KindUser, userSession.Kind)
	require.Equal(t, "alice", userSession.Subject)

	// A browser carrying both cookies at once: /admin honors the admin
	// cookie, and /authorize honors the user cookie for SSO.
	both := func() *http.Request {
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodGet,
			adminLoginPath,
			nil,
		)
		request.AddCookie(&http.Cookie{Name: adminSessionCookieName, Value: adminToken})
		request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: userToken})
		return request
	}

	adminPage := httptest.NewRecorder()
	app.server.Handler().ServeHTTP(adminPage, both())
	require.Equal(t, http.StatusOK, adminPage.Code)
	require.Contains(t, adminPage.Body.String(), "Signed in as administrator.")

	authorizeRequest := buildAuthorizeRequest(t, validPublicRequest())
	authorizeRequest.AddCookie(&http.Cookie{Name: adminSessionCookieName, Value: adminToken})
	authorizeRequest.AddCookie(&http.Cookie{Name: sessionCookieName, Value: userToken})
	authorizeResponse := httptest.NewRecorder()
	app.server.Handler().ServeHTTP(authorizeResponse, authorizeRequest)
	require.Equal(t, http.StatusFound, authorizeResponse.Code)
	location, err := url.Parse(authorizeResponse.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "app.example.com", location.Host)
	require.Contains(t, location.Query(), "code")
}

// failingAdminService and failingAdminSessions are stub implementations
// that always return the configured error.
type failingAdminService struct{ err error }

func (stub failingAdminService) Login(context.Context, string, time.Time) (string, error) {
	return "", stub.err
}

type failingAdminSessions struct{ err error }

func (stub failingAdminSessions) ValidateAdmin(
	context.Context,
	string,
	time.Time,
) (session.Session, error) {
	return session.Session{}, stub.err
}

func (stub failingAdminSessions) Revoke(context.Context, string) error {
	return stub.err
}

// failingEnrollmentCreator and failingAuditRecorder are stub
// implementations that always return the configured error.
type failingEnrollmentCreator struct{ err error }

func (stub failingEnrollmentCreator) CreateEnrollment(
	context.Context,
	onetoken.EnrollmentParams,
) (string, error) {
	return "", stub.err
}

type failingAuditRecorder struct{ err error }

func (stub failingAuditRecorder) Record(context.Context, audit.RecordParams) error {
	return stub.err
}
