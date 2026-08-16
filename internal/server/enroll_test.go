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
)

// referenceSecret is the deterministic TOTP shared secret of sub "alice"
// at revision 0 with the reference root secret, matching the vector
// anchored by the crypto derivation chain tests.
const referenceSecret = "LQJ2MSFEHZMA4KVBU5SNJRDAJHEH7PCGYIADZIKUDNYNG4SD6XFQ"

// referenceAccountName is the human-readable authenticator account name
// shown for manual configuration on the enrollment of sub "alice" with
// the test display name "Example Auth".
const referenceAccountName = "Example Auth: alice"

func TestEnrollForm(t *testing.T) {
	t.Run("carries the shared link token into the protected form", func(t *testing.T) {
		app := newTestApp(t, testUsers)

		response := getEnroll(t, app, "?"+url.Values{enrollTokenParam: {"tok_abc123"}}.Encode())

		require.Equal(t, http.StatusOK, response.Code)
		require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
		body := response.Body.String()
		require.Contains(t, body, `name="token"`)
		require.Contains(t, body, `type="hidden"`)
		require.Contains(t, body, `value="tok_abc123"`)
		require.Contains(t, body, `name="csrf_token"`)
		require.Contains(t, body, "Show QR")
	})

	t.Run("carries an empty token field when no link token is present", func(t *testing.T) {
		app := newTestApp(t, testUsers)

		response := getEnroll(t, app, "")

		require.Equal(t, http.StatusOK, response.Code)
		body := response.Body.String()
		require.Contains(t, body, `name="token"`)
		require.Contains(t, body, `type="hidden"`)
		require.Contains(t, body, `value=""`)
		require.Contains(t, body, `name="csrf_token"`)
		require.Contains(t, body, "Show QR")
		require.NotContains(t, body, `type="text"`)
	})

	t.Run("does not consume the token on preview", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		token := enrollmentToken(t, app, "alice", 0)

		response := getEnroll(t, app, "?"+url.Values{enrollTokenParam: {token}}.Encode())

		require.Equal(t, http.StatusOK, response.Code)
		require.Contains(t, response.Body.String(), "Show QR")

		// The preview must not redeem the credential: the token is still
		// redeemable after the page view.
		_, err := app.codes.ConsumeEnrollment(context.Background(), token, time.Now())
		require.NoError(t, err)
	})
}

func TestProcessEnroll(t *testing.T) {
	t.Run("reveals the QR code and manual entry values for a valid token", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		token := enrollmentToken(t, app, "alice", 0)

		response := postEnroll(t, app, url.Values{enrollTokenParam: {token}})

		require.Equal(t, http.StatusOK, response.Code)
		require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
		body := response.Body.String()
		require.Contains(t, body, "data:image/png;base64,")
		require.Contains(t, body, "Scan the code with your authenticator app")

		// The manual entry values mirror the QR code exactly: the account
		// name, the secret, and the RFC 6238 profile, each behind a copy
		// button, and never the raw otpauth URI.
		require.Contains(t, body, `data-copy="`+referenceAccountName+`"`)
		require.Contains(t, body, `data-copy="`+referenceSecret+`"`)
		require.Contains(t, body, `data-copy="SHA1"`)
		require.Contains(t, body, `data-copy="6"`)
		require.Contains(t, body, `data-copy="30"`)
		require.NotContains(t, body, "otpauth://")

		// The reveal point records the consumption against the subject.
		events := auditEvents(t, app)
		require.Len(t, events, 1)
		require.Equal(t, audit.CategoryEnrollmentTokenConsumed, events[0].Category)
		require.Equal(t, "alice", events[0].Subject)
		require.JSONEq(t, `{}`, events[0].Details)
	})

	t.Run("redeems the token exactly once", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		token := enrollmentToken(t, app, "alice", 0)

		first := postEnroll(t, app, url.Values{enrollTokenParam: {token}})
		require.Equal(t, http.StatusOK, first.Code)
		require.Contains(t, first.Body.String(), "data:image/png;base64,")

		second := postEnroll(t, app, url.Values{enrollTokenParam: {token}})

		require.Equal(t, http.StatusOK, second.Code)
		body := second.Body.String()
		require.Contains(t, body, enrollDeniedMessage)
		require.NotContains(t, body, "data:image/png;base64,")
		require.NotContains(t, body, "otpauth://")

		// Only the successful redemption is recorded, never the replay.
		events := auditEvents(t, app)
		require.Len(t, events, 1)
		require.Equal(t, audit.CategoryEnrollmentTokenConsumed, events[0].Category)
	})

	t.Run("rejects a malformed token without echoing it", func(t *testing.T) {
		app := newTestApp(t, testUsers)

		response := postEnroll(t, app, url.Values{enrollTokenParam: {"not-a-token"}})

		require.Equal(t, http.StatusOK, response.Code)
		body := response.Body.String()
		require.Contains(t, body, enrollDeniedMessage)
		require.NotContains(t, body, "data:image/png;base64,")
		require.NotContains(t, body, "not-a-token")
	})

	t.Run("rejects a token bound to a removed user", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		token := enrollmentToken(t, app, "ghost", 0)

		response := postEnroll(t, app, url.Values{enrollTokenParam: {token}})

		require.Equal(t, http.StatusOK, response.Code)
		require.Contains(t, response.Body.String(), enrollDeniedMessage)
		require.NotContains(t, response.Body.String(), "data:image/png;base64,")
	})

	t.Run("rejects a token bound to an expired user", func(t *testing.T) {
		users := []config.User{{
			Subject:   "alice",
			ExpiresAt: time.Now().Add(-time.Hour),
		}}
		app := newTestApp(t, users)
		token := enrollmentToken(t, app, "alice", 0)

		response := postEnroll(t, app, url.Values{enrollTokenParam: {token}})

		require.Equal(t, http.StatusOK, response.Code)
		require.Contains(t, response.Body.String(), enrollDeniedMessage)
		require.NotContains(t, response.Body.String(), "data:image/png;base64,")
	})

	t.Run("rejects a token bound to a stale revision", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		token := enrollmentToken(t, app, "alice", 1)

		response := postEnroll(t, app, url.Values{enrollTokenParam: {token}})

		require.Equal(t, http.StatusOK, response.Code)
		require.Contains(t, response.Body.String(), enrollDeniedMessage)
		require.NotContains(t, response.Body.String(), "data:image/png;base64,")
	})

	t.Run("rejects an expired token", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		token, err := app.codes.CreateEnrollment(
			context.Background(),
			onetoken.EnrollmentParams{
				Subject:   "alice",
				TOTPRev:   0,
				ExpiresAt: time.Now().Add(-time.Minute),
				Now:       time.Now().Add(-2 * time.Minute),
			},
		)
		require.NoError(t, err)

		response := postEnroll(t, app, url.Values{enrollTokenParam: {token}})

		require.Equal(t, http.StatusOK, response.Code)
		require.Contains(t, response.Body.String(), enrollDeniedMessage)
		require.NotContains(t, response.Body.String(), "data:image/png;base64,")
	})

	t.Run("rejects an authorization code through the enrollment flow", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		code, err := app.codes.CreateCode(
			context.Background(),
			onetoken.CodeParams{
				AuthTime:    time.Now(),
				Subject:     "alice",
				ClientID:    "public-app",
				RedirectURI: "https://app.example.com/callback",
				Scope:       "openid",
				ExpiresAt:   time.Now().Add(time.Hour),
				Now:         time.Now(),
			},
		)
		require.NoError(t, err)

		response := postEnroll(t, app, url.Values{enrollTokenParam: {code}})

		require.Equal(t, http.StatusOK, response.Code)
		require.Contains(t, response.Body.String(), enrollDeniedMessage)
		require.NotContains(t, response.Body.String(), "data:image/png;base64,")
	})

	t.Run("requires the anti-forgery token", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		token := enrollmentToken(t, app, "alice", 0)

		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodPost,
			enrollPath,
			strings.NewReader(url.Values{enrollTokenParam: {token}}.Encode()),
		)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response := httptest.NewRecorder()
		app.server.Handler().ServeHTTP(response, request)

		require.Equal(t, http.StatusForbidden, response.Code)

		// The credential survives the rejected submission untouched.
		_, err := app.codes.ConsumeEnrollment(context.Background(), token, time.Now())
		require.NoError(t, err)
	})

	t.Run("returns 500 when redemption fails", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		app.server.enroll.Consume = failingEnrollmentConsumer{
			err: errors.New("database unavailable"),
		}

		response := postEnroll(t, app, url.Values{enrollTokenParam: {"tok_irrelevant"}})

		require.Equal(t, http.StatusInternalServerError, response.Code)
	})

	t.Run("returns 500 when secret derivation fails", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		token := enrollmentToken(t, app, "alice", 0)
		app.server.enroll.Deriver = failingTOTPDeriver{err: errors.New("derivation unavailable")}

		response := postEnroll(t, app, url.Values{enrollTokenParam: {token}})

		require.Equal(t, http.StatusInternalServerError, response.Code)
	})

	t.Run("returns 500 when the consumption event cannot be recorded", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		token := enrollmentToken(t, app, "alice", 0)
		app.server.enroll.Audit = failingPanicAudit{}

		response := postEnroll(t, app, url.Values{enrollTokenParam: {token}})

		require.Equal(t, http.StatusInternalServerError, response.Code)

		// The token is consumed even though the event could not be
		// recorded, so a retry cannot reveal the secret twice.
		second := postEnroll(t, app, url.Values{enrollTokenParam: {token}})
		require.Equal(t, http.StatusOK, second.Code)
		require.Contains(t, second.Body.String(), enrollDeniedMessage)
	})
}

// enrollmentToken creates a redeemable enrollment token for the given
// subject and revision, expiring in one hour.
func enrollmentToken(t *testing.T, app *testApp, subject string, revision uint64) string {
	t.Helper()
	token, err := app.codes.CreateEnrollment(
		context.Background(),
		onetoken.EnrollmentParams{
			Subject:   subject,
			TOTPRev:   revision,
			ExpiresAt: time.Now().Add(time.Hour),
			Now:       time.Now(),
		},
	)
	require.NoError(t, err)
	return token
}

// getEnroll fetches the enrollment form with the given query string.
func getEnroll(t *testing.T, app *testApp, query string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		enrollPath+query,
		nil,
	)
	response := httptest.NewRecorder()
	app.server.Handler().ServeHTTP(response, request)
	return response
}

// enrollCSRFToken fetches the enrollment form and returns the anti-forgery
// token it issues, exactly as a browser would receive it.
func enrollCSRFToken(t *testing.T, app *testApp) string {
	t.Helper()
	response := getEnroll(t, app, "")
	require.Equal(t, http.StatusOK, response.Code)
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == CSRFCookieName {
			return cookie.Value
		}
	}
	require.FailNow(t, "no CSRF cookie in response")
	return ""
}

// postEnroll submits the given form to the enrollment action, echoing the
// anti-forgery token obtained from the enrollment form exactly as a
// browser would.
func postEnroll(t *testing.T, app *testApp, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	csrfToken := enrollCSRFToken(t, app)
	form.Set(csrf.FieldName, csrfToken)

	request := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		enrollPath,
		strings.NewReader(form.Encode()),
	)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: csrfToken})
	response := httptest.NewRecorder()
	app.server.Handler().ServeHTTP(response, request)
	return response
}

// failingEnrollmentConsumer is a Consumer stub that always fails.
type failingEnrollmentConsumer struct {
	err error
}

// ConsumeEnrollment fails with the stub error.
func (stub failingEnrollmentConsumer) ConsumeEnrollment(
	context.Context,
	string,
	time.Time,
) (onetoken.Enrollment, error) {
	return onetoken.Enrollment{}, stub.err
}

// failingTOTPDeriver is a TOTPSecretDeriver stub that always fails.
type failingTOTPDeriver struct {
	err error
}

// DeriveTOTPSecret fails with the stub error.
func (stub failingTOTPDeriver) DeriveTOTPSecret(string, uint64) (string, error) {
	return "", stub.err
}

func TestEnrollmentURL(t *testing.T) {
	t.Run("derives the link from an issuer without a trailing slash", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		app.server.issuer = referenceIssuer

		link := app.server.enrollmentURL("tok_test")

		require.Equal(t, referenceIssuer+enrollPath+"?token=tok_test", link)
	})

	t.Run("trims a trailing slash from the issuer", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		app.server.issuer = referenceIssuer + "/"

		link := app.server.enrollmentURL("tok_test")

		require.Equal(t, referenceIssuer+enrollPath+"?token=tok_test", link)
	})
}
