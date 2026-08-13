package server

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/varavelio/zen-idp/internal/config"
	"github.com/varavelio/zen-idp/internal/jwt"
	"github.com/varavelio/zen-idp/internal/session"
	"github.com/varavelio/zen-idp/internal/token"
	"github.com/varavelio/zen-idp/internal/ui"
)

// obtainAccessToken runs the full authorization-code exchange against app
// and returns the issued access token.
func obtainAccessToken(t *testing.T, app *testApp) string {
	t.Helper()
	code := createCode(t, app, nil)
	response := tokenRequest(t, app.server.Handler(), validExchangeForm(code), "")
	require.Equal(t, http.StatusOK, response.Code)
	return decodeTokenResponse(t, response).AccessToken
}

// userinfoRequest performs a GET /userinfo request against handler with the
// given Authorization header value, absent when empty.
func userinfoRequest(
	t *testing.T,
	handler http.Handler,
	authorization string,
) *httptest.ResponseRecorder {
	t.Helper()
	response := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"/userinfo",
		nil,
	)
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	handler.ServeHTTP(response, request)
	return response
}

// signAccessToken signs a well-formed access token for subject with the
// reference signing identity, stamping the standard metadata and including
// the given extra claims.
func signAccessToken(t *testing.T, subject string, extra map[string]any) string {
	t.Helper()
	signer, err := jwt.NewSigner(referenceKey(), referenceKid())
	require.NoError(t, err)
	now := time.Now()
	claims := map[string]any{
		"iss": referenceIssuer,
		"sub": subject,
		"aud": referenceIssuer + "/userinfo",
		"iat": now.Unix(),
		"exp": now.Add(token.Lifetime).Unix(),
	}
	maps.Copy(claims, extra)
	signed, err := signer.Sign(claims)
	require.NoError(t, err)
	return signed
}

// requireUserinfoError asserts that response is a JSON /userinfo error
// response with the given status and error code.
func requireUserinfoError(
	t *testing.T,
	response *httptest.ResponseRecorder,
	status int,
	code string,
) {
	t.Helper()
	require.Equal(t, status, response.Code)
	require.Equal(t, "application/json; charset=utf-8", response.Header().Get("Content-Type"))
	require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
	if status == http.StatusUnauthorized {
		require.Equal(
			t,
			`Bearer realm="zen-idp", error="invalid_token"`,
			response.Header().Get("WWW-Authenticate"),
		)
	}
	var body userinfoErrorResponse
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &body))
	require.Equal(t, code, body.Error)
	require.NotEmpty(t, body.ErrorDescription)
}

func TestUserInfo(t *testing.T) {
	t.Run("returns the current claims of a valid access token", func(t *testing.T) {
		users := []config.User{{
			Subject: "alice",
			Claims: map[string]any{
				"groups": []string{"ops", "oncall"},
				"title":  "SRE",
			},
		}}
		app := newTestApp(t, users)
		accessToken := obtainAccessToken(t, app)
		response := userinfoRequest(t, app.server.Handler(), "Bearer "+accessToken)

		require.Equal(t, http.StatusOK, response.Code)
		require.Equal(t, "application/json; charset=utf-8", response.Header().Get("Content-Type"))
		require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
		require.Equal(t, "no-cache", response.Header().Get("Pragma"))
		var claims map[string]any
		require.NoError(t, json.Unmarshal(response.Body.Bytes(), &claims))
		require.Equal(t, "alice", claims["sub"])
		require.Equal(t, []any{"ops", "oncall"}, claims["groups"])
		require.Equal(t, "SRE", claims["title"])
	})

	t.Run("excludes internal idp_ claim keys", func(t *testing.T) {
		users := []config.User{{
			Subject: "alice",
			Claims: map[string]any{
				"role":      "admin",
				"idp_login": "internal-only",
			},
		}}
		app := newTestApp(t, users)
		accessToken := obtainAccessToken(t, app)
		response := userinfoRequest(t, app.server.Handler(), "Bearer "+accessToken)

		require.Equal(t, http.StatusOK, response.Code)
		var claims map[string]any
		require.NoError(t, json.Unmarshal(response.Body.Bytes(), &claims))
		require.Equal(t, "admin", claims["role"])
		require.NotContains(t, claims, "idp_login")
	})

	t.Run("resolves a session-bound access token", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		created, err := app.sessions.Create(context.Background(), session.CreateParams{
			Subject: "alice",
			Now:     time.Now(),
		})
		require.NoError(t, err)
		id, _, ok := strings.Cut(strings.TrimPrefix(created, "sess_"), "_")
		require.True(t, ok)
		accessToken := signAccessToken(t, "alice", map[string]any{"jti": id})
		response := userinfoRequest(t, app.server.Handler(), "Bearer "+accessToken)

		require.Equal(t, http.StatusOK, response.Code)
		var claims map[string]any
		require.NoError(t, json.Unmarshal(response.Body.Bytes(), &claims))
		require.Equal(t, "alice", claims["sub"])
	})

	t.Run("rejects a session-bound access token after revocation", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		created, err := app.sessions.Create(context.Background(), session.CreateParams{
			Subject: "alice",
			Now:     time.Now(),
		})
		require.NoError(t, err)
		id, _, ok := strings.Cut(strings.TrimPrefix(created, "sess_"), "_")
		require.True(t, ok)
		accessToken := signAccessToken(t, "alice", map[string]any{"jti": id})
		require.NoError(t, app.sessions.Revoke(context.Background(), created))

		response := userinfoRequest(t, app.server.Handler(), "Bearer "+accessToken)

		requireUserinfoError(t, response, http.StatusUnauthorized, "invalid_token")
	})

	t.Run("rejects a missing Authorization header", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		response := userinfoRequest(t, app.server.Handler(), "")

		requireUserinfoError(t, response, http.StatusBadRequest, "invalid_request")
	})

	t.Run("rejects a non-bearer authorization scheme", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		response := userinfoRequest(t, app.server.Handler(), "Basic dXNlcjpwYXNz")

		requireUserinfoError(t, response, http.StatusBadRequest, "invalid_request")
	})

	t.Run("accepts a lowercase bearer scheme", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		accessToken := obtainAccessToken(t, app)

		response := userinfoRequest(t, app.server.Handler(), "bearer "+accessToken)

		require.Equal(t, http.StatusOK, response.Code)
	})

	t.Run("accepts a mixed-case bearer scheme", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		accessToken := obtainAccessToken(t, app)

		response := userinfoRequest(t, app.server.Handler(), "BeArEr "+accessToken)

		require.Equal(t, http.StatusOK, response.Code)
	})

	t.Run("rejects an empty bearer token", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		response := userinfoRequest(t, app.server.Handler(), "Bearer ")

		requireUserinfoError(t, response, http.StatusBadRequest, "invalid_request")
	})

	t.Run("rejects a malformed access token", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		response := userinfoRequest(t, app.server.Handler(), "Bearer not-a-jwt")

		requireUserinfoError(t, response, http.StatusUnauthorized, "invalid_token")
	})

	t.Run("rejects an expired access token", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		signer, err := jwt.NewSigner(referenceKey(), referenceKid())
		require.NoError(t, err)
		expired, err := signer.Sign(map[string]any{
			"iss": referenceIssuer,
			"sub": "alice",
			"aud": referenceIssuer + "/userinfo",
			"iat": time.Now().Add(-2 * token.Lifetime).Unix(),
			"exp": time.Now().Add(-time.Minute).Unix(),
		})
		require.NoError(t, err)

		response := userinfoRequest(t, app.server.Handler(), "Bearer "+expired)

		requireUserinfoError(t, response, http.StatusUnauthorized, "invalid_token")
	})

	t.Run("rejects a token whose subject is locked", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		accessToken := obtainAccessToken(t, app)
		require.NoError(t, app.locks.LockSubject(context.Background(), "alice", time.Now()))

		response := userinfoRequest(t, app.server.Handler(), "Bearer "+accessToken)

		requireUserinfoError(t, response, http.StatusUnauthorized, "invalid_token")
	})

	t.Run("returns an internal error when resolution fails", func(t *testing.T) {
		handler := New(
			testPublicJWK(),
			referenceIssuer,
			testClients(),
			ui.Assets(),
			LoginDependencies{},
			AuthorizeDependencies{},
			TokenDependencies{},
			UserinfoDependencies{Service: failingUserinfoService{}},
			LogoutDependencies{},
			EnrollDependencies{},
			AdminDependencies{},
			PanicDependencies{},
		).Handler()
		response := userinfoRequest(t, handler, "Bearer anything")

		require.Equal(t, http.StatusInternalServerError, response.Code)
		require.Contains(t, response.Body.String(), "internal server error")
	})
}

// failingUserinfoService is a userinfo service whose resolution always
// fails with an infrastructure error.
type failingUserinfoService struct{}

func (failingUserinfoService) Resolve(
	context.Context,
	string,
	time.Time,
) (map[string]any, error) {
	return nil, errors.New("database unavailable")
}
