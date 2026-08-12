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

// adminLoginRequest posts the given password to the administrator sign-in
// form.
func adminLoginRequest(t *testing.T, app *testApp, password string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"password": {password}}
	request := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		adminLoginAction,
		strings.NewReader(form.Encode()),
	)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
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
		require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
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

func TestAdminInfrastructureErrors(t *testing.T) {
	t.Run("failing admin service returns 500", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		app.server.admin.Service = failingAdminService{err: errors.New("boom")}

		response := adminLoginRequest(t, app, testAdminPassword)

		require.Equal(t, http.StatusInternalServerError, response.Code)
	})

	t.Run("failing admin session validation returns 500", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		app.server.admin.Sessions = failingAdminValidator{err: errors.New("boom")}

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

// failingAdminService and failingAdminValidator are stub implementations
// that always return the configured error.
type failingAdminService struct{ err error }

func (stub failingAdminService) Login(context.Context, string, time.Time) (string, error) {
	return "", stub.err
}

type failingAdminValidator struct{ err error }

func (stub failingAdminValidator) ValidateAdmin(
	context.Context,
	string,
	time.Time,
) (session.Session, error) {
	return session.Session{}, stub.err
}
