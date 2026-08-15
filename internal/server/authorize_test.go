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
	"github.com/varavelio/zen-idp/internal/clock"
	"github.com/varavelio/zen-idp/internal/config"
	"github.com/varavelio/zen-idp/internal/csrf"
	"github.com/varavelio/zen-idp/internal/onetoken"
	"github.com/varavelio/zen-idp/internal/session"
	"github.com/varavelio/zen-idp/internal/statestore"
	"github.com/varavelio/zen-idp/internal/totp"
	"github.com/varavelio/zen-idp/internal/ui"
)

// validCodeChallenge is the RFC 7636 appendix B example code challenge,
// which is exactly 43 characters of the unreserved base64url alphabet.
const referenceCodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

// testClientSecret is the plaintext secret of the confidential test clients
// and testClientSecretHash is its precomputed Argon2id PHC hash.
const (
	testClientSecret     = "test-client-secret"
	testClientSecretHash = "$argon2id$v=19$m=65536,t=2,p=2$5XEq+R1hozyGGEdvY7KVYA$cEyyXwpgnzm0IMtpsDu3+O6eBxBdO2VaFEpyLHUetIo"
)

func testClients() []config.Client {
	return []config.Client{
		{
			ID:           "public-app",
			RedirectURIs: []string{"https://app.example.com/callback"},
		},
		{
			ID:           "confidential-app",
			SecretHash:   testClientSecretHash,
			RedirectURIs: []string{"https://app.example.com/callback"},
		},
		{
			ID:           "query-app",
			SecretHash:   testClientSecretHash,
			RedirectURIs: []string{"https://app.example.com/callback?tenant=1"},
		},
	}
}

func buildAuthorizeRequest(t *testing.T, params map[string]string) *http.Request {
	t.Helper()
	query := url.Values{}
	for name, value := range params {
		query.Set(name, value)
	}
	return httptest.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"/authorize?"+query.Encode(),
		nil,
	)
}

func validPublicRequest() map[string]string {
	return map[string]string{
		"client_id":             "public-app",
		"redirect_uri":          "https://app.example.com/callback",
		"response_type":         "code",
		"scope":                 "openid profile",
		"state":                 "STATE",
		"nonce":                 "NONCE",
		"code_challenge":        referenceCodeChallenge,
		"code_challenge_method": "S256",
	}
}

// createSessionToken creates an active session for subject at the given
// instant and returns its browser credential token.
func createSessionToken(t *testing.T, app *testApp, subject string, now time.Time) string {
	t.Helper()
	token, err := app.sessions.Create(context.Background(), session.CreateParams{
		Subject: subject,
		Now:     now,
	})
	require.NoError(t, err)
	return token
}

// authorizeRequestWithSession builds a GET /authorize request carrying the
// given query string and an SSO session cookie.
func authorizeRequestWithSession(query, token string) *http.Request {
	request := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"/authorize?"+query,
		nil,
	)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	return request
}

func requireErrorRedirect(t *testing.T, response *httptest.ResponseRecorder, code, state string) {
	t.Helper()
	require.Equal(t, http.StatusFound, response.Code)
	location, err := url.Parse(response.Header().Get("Location"))
	require.NoError(t, err)
	query := location.Query()
	require.Equal(t, code, query.Get("error"))
	require.NotEmpty(t, query.Get("error_description"))
	require.Equal(t, state, query.Get("state"))
}

func requireInvalidRequestPage(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	require.Equal(t, http.StatusBadRequest, response.Code)
	require.Equal(t, "text/html; charset=utf-8", response.Header().Get("Content-Type"))
	require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
	require.Empty(t, response.Header().Get("Location"))
	require.Contains(t, response.Body.String(), "Invalid authorization request")
}

func TestAuthorize(t *testing.T) {
	handler := New(
		testPublicJWK(),
		referenceIssuer,
		testClients(),
		ui.Assets(),
		LoginDependencies{},
		AuthorizeDependencies{},
		TokenDependencies{},
		UserinfoDependencies{},
		LogoutDependencies{},
		EnrollDependencies{},
		AdminDependencies{},
		PanicDependencies{},
		HealthDependencies{},
	).Handler()

	t.Run("forwards a valid public client request to the login interaction", func(t *testing.T) {
		params := validPublicRequest()
		request := buildAuthorizeRequest(t, params)
		response := httptest.NewRecorder()

		handler.ServeHTTP(response, request)

		require.Equal(t, http.StatusFound, response.Code)
		require.Equal(t, "/login?"+request.URL.RawQuery, response.Header().Get("Location"))
	})

	t.Run("forwards a valid confidential client request without PKCE", func(t *testing.T) {
		request := buildAuthorizeRequest(t, map[string]string{
			"client_id":     "confidential-app",
			"redirect_uri":  "https://app.example.com/callback",
			"response_type": "code",
			"scope":         "openid",
			"state":         "STATE",
		})
		response := httptest.NewRecorder()

		handler.ServeHTTP(response, request)

		require.Equal(t, http.StatusFound, response.Code)
		require.Equal(t, "/login?"+request.URL.RawQuery, response.Header().Get("Location"))
	})

	t.Run("forwards a confidential client request with S256 PKCE", func(t *testing.T) {
		params := validPublicRequest()
		params["client_id"] = "confidential-app"
		request := buildAuthorizeRequest(t, params)
		response := httptest.NewRecorder()

		handler.ServeHTTP(response, request)

		require.Equal(t, http.StatusFound, response.Code)
		require.Equal(t, "/login?"+request.URL.RawQuery, response.Header().Get("Location"))
	})

	t.Run("forwards a request whose registered redirect URI has a query", func(t *testing.T) {
		request := buildAuthorizeRequest(t, map[string]string{
			"client_id":     "query-app",
			"redirect_uri":  "https://app.example.com/callback?tenant=1",
			"response_type": "code",
			"scope":         "openid",
			"state":         "STATE",
		})
		response := httptest.NewRecorder()

		handler.ServeHTTP(response, request)

		require.Equal(t, http.StatusFound, response.Code)
		require.Equal(t, "/login?"+request.URL.RawQuery, response.Header().Get("Location"))
	})

	t.Run("rejects an unknown client without redirecting", func(t *testing.T) {
		params := validPublicRequest()
		params["client_id"] = "unknown-app"
		request := buildAuthorizeRequest(t, params)
		response := httptest.NewRecorder()

		handler.ServeHTTP(response, request)

		requireInvalidRequestPage(t, response)
	})

	t.Run("rejects a missing redirect URI without redirecting", func(t *testing.T) {
		params := validPublicRequest()
		delete(params, "redirect_uri")
		request := buildAuthorizeRequest(t, params)
		response := httptest.NewRecorder()

		handler.ServeHTTP(response, request)

		requireInvalidRequestPage(t, response)
	})

	t.Run("rejects an unregistered redirect URI without redirecting", func(t *testing.T) {
		params := validPublicRequest()
		params["redirect_uri"] = "https://evil.example.com/callback"
		request := buildAuthorizeRequest(t, params)
		response := httptest.NewRecorder()

		handler.ServeHTTP(response, request)

		requireInvalidRequestPage(t, response)
	})

	t.Run("rejects a partial redirect URI match", func(t *testing.T) {
		for _, uri := range []string{
			"https://app.example.com/callback/extra",
			"https://app.example.com/callback?tenant=2",
		} {
			params := validPublicRequest()
			params["redirect_uri"] = uri
			request := buildAuthorizeRequest(t, params)
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			requireInvalidRequestPage(t, response)
		}
	})

	t.Run("rejects duplicated parameters", func(t *testing.T) {
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodGet,
			"/authorize?client_id=public-app&client_id=other&redirect_uri="+
				"https%3A%2F%2Fapp.example.com%2Fcallback&response_type=code&scope=openid&state=STATE",
			nil,
		)
		response := httptest.NewRecorder()

		handler.ServeHTTP(response, request)

		requireInvalidRequestPage(t, response)
	})

	t.Run("forwards a request without state", func(t *testing.T) {
		params := validPublicRequest()
		delete(params, "state")
		request := buildAuthorizeRequest(t, params)
		response := httptest.NewRecorder()

		handler.ServeHTTP(response, request)

		require.Equal(t, http.StatusFound, response.Code)
		require.Equal(t, "/login?"+request.URL.RawQuery, response.Header().Get("Location"))
	})

	t.Run("rejects a missing openid scope", func(t *testing.T) {
		params := validPublicRequest()
		params["scope"] = "profile"
		request := buildAuthorizeRequest(t, params)
		response := httptest.NewRecorder()

		handler.ServeHTTP(response, request)

		requireErrorRedirect(t, response, "invalid_scope", "STATE")
	})

	t.Run("rejects a scope containing openid only as a substring", func(t *testing.T) {
		params := validPublicRequest()
		params["scope"] = "myopenid"
		request := buildAuthorizeRequest(t, params)
		response := httptest.NewRecorder()

		handler.ServeHTTP(response, request)

		requireErrorRedirect(t, response, "invalid_scope", "STATE")
	})

	t.Run("rejects an unsupported response type", func(t *testing.T) {
		params := validPublicRequest()
		params["response_type"] = "token"
		request := buildAuthorizeRequest(t, params)
		response := httptest.NewRecorder()

		handler.ServeHTTP(response, request)

		requireErrorRedirect(t, response, "unsupported_response_type", "STATE")
	})

	t.Run("rejects a public client without PKCE", func(t *testing.T) {
		params := validPublicRequest()
		delete(params, "code_challenge")
		delete(params, "code_challenge_method")
		request := buildAuthorizeRequest(t, params)
		response := httptest.NewRecorder()

		handler.ServeHTTP(response, request)

		requireErrorRedirect(t, response, "invalid_request", "STATE")
	})

	t.Run("rejects the plain PKCE method", func(t *testing.T) {
		params := validPublicRequest()
		params["code_challenge_method"] = "plain"
		request := buildAuthorizeRequest(t, params)
		response := httptest.NewRecorder()

		handler.ServeHTTP(response, request)

		requireErrorRedirect(t, response, "invalid_request", "STATE")
	})

	t.Run("rejects a code challenge without a method", func(t *testing.T) {
		params := validPublicRequest()
		delete(params, "code_challenge_method")
		request := buildAuthorizeRequest(t, params)
		response := httptest.NewRecorder()

		handler.ServeHTTP(response, request)

		requireErrorRedirect(t, response, "invalid_request", "STATE")
	})

	t.Run("rejects a method without a code challenge", func(t *testing.T) {
		params := validPublicRequest()
		params["client_id"] = "confidential-app"
		delete(params, "code_challenge")
		request := buildAuthorizeRequest(t, params)
		response := httptest.NewRecorder()

		handler.ServeHTTP(response, request)

		requireErrorRedirect(t, response, "invalid_request", "STATE")
	})

	t.Run("rejects a malformed code challenge", func(t *testing.T) {
		for _, challenge := range []string{
			"too-short",
			"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-c",   // 42 characters
			"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM!", // invalid character
		} {
			params := validPublicRequest()
			params["code_challenge"] = challenge
			request := buildAuthorizeRequest(t, params)
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			requireErrorRedirect(t, response, "invalid_request", "STATE")
		}
	})

	t.Run("forwards the query response mode", func(t *testing.T) {
		params := validPublicRequest()
		params["response_mode"] = "query"
		request := buildAuthorizeRequest(t, params)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		require.Equal(t, http.StatusFound, response.Code)
		require.True(t, strings.HasPrefix(response.Header().Get("Location"), "/login"))
	})

	t.Run("rejects an unsupported response mode", func(t *testing.T) {
		params := validPublicRequest()
		params["response_mode"] = "form_post"
		request := buildAuthorizeRequest(t, params)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		requireErrorRedirect(t, response, "invalid_request", "STATE")
	})

	t.Run("rejects the request parameter", func(t *testing.T) {
		params := validPublicRequest()
		params["request"] = "eyJhbGciOiJub25lIn0.eyJzY29wZSI6Im9wZW5pZCJ9."
		request := buildAuthorizeRequest(t, params)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		requireErrorRedirect(t, response, "request_not_supported", "STATE")
	})

	t.Run("rejects the request_uri parameter", func(t *testing.T) {
		params := validPublicRequest()
		params["request_uri"] = "https://app.example.com/request.jwt"
		request := buildAuthorizeRequest(t, params)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		requireErrorRedirect(t, response, "request_uri_not_supported", "STATE")
	})

	t.Run("prompt=none without a session fails with login_required", func(t *testing.T) {
		params := validPublicRequest()
		params["prompt"] = "none"
		request := buildAuthorizeRequest(t, params)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		requireErrorRedirect(t, response, "login_required", "STATE")
	})

	t.Run("rejects prompt=none combined with another value", func(t *testing.T) {
		params := validPublicRequest()
		params["prompt"] = "none login"
		request := buildAuthorizeRequest(t, params)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		requireErrorRedirect(t, response, "invalid_request", "STATE")
	})

	t.Run("prompt=login without a session forwards to the login interaction", func(t *testing.T) {
		params := validPublicRequest()
		params["prompt"] = "login"
		request := buildAuthorizeRequest(t, params)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		require.Equal(t, http.StatusFound, response.Code)
		require.True(t, strings.HasPrefix(response.Header().Get("Location"), "/login"))
	})

	t.Run("prompt=consent without a session forwards to the login interaction", func(t *testing.T) {
		params := validPublicRequest()
		params["prompt"] = "consent"
		request := buildAuthorizeRequest(t, params)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		require.Equal(t, http.StatusFound, response.Code)
		require.True(t, strings.HasPrefix(response.Header().Get("Location"), "/login"))
	})

	t.Run(
		"prompt=select_account without a session forwards to the login interaction",
		func(t *testing.T) {
			params := validPublicRequest()
			params["prompt"] = "select_account"
			request := buildAuthorizeRequest(t, params)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			require.Equal(t, http.StatusFound, response.Code)
			require.True(t, strings.HasPrefix(response.Header().Get("Location"), "/login"))
		},
	)

	t.Run("rejects a malformed max_age", func(t *testing.T) {
		params := validPublicRequest()
		params["max_age"] = "soon"
		request := buildAuthorizeRequest(t, params)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		requireErrorRedirect(t, response, "invalid_request", "STATE")
	})

	t.Run("rejects a negative max_age", func(t *testing.T) {
		params := validPublicRequest()
		params["max_age"] = "-1"
		request := buildAuthorizeRequest(t, params)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		requireErrorRedirect(t, response, "invalid_request", "STATE")
	})

	t.Run(
		"preserves redirect URI query parameters and omits state in error redirects",
		func(t *testing.T) {
			request := buildAuthorizeRequest(t, map[string]string{
				"client_id":     "query-app",
				"redirect_uri":  "https://app.example.com/callback?tenant=1",
				"response_type": "code",
				"scope":         "profile",
			})
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			location, err := url.Parse(response.Header().Get("Location"))
			require.NoError(t, err)
			require.Equal(t, "1", location.Query().Get("tenant"))
			require.Equal(t, "invalid_scope", location.Query().Get("error"))
			require.Empty(t, location.Query().Get("state"))
		},
	)

	t.Run("rejects other methods", func(t *testing.T) {
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodPost,
			"/authorize",
			nil,
		)
		response := httptest.NewRecorder()

		handler.ServeHTTP(response, request)

		require.Equal(t, http.StatusMethodNotAllowed, response.Code)
	})
}

func TestAuthorizeIssuesCode(t *testing.T) {
	queryFor := func(params map[string]string) string {
		query := url.Values{}
		for name, value := range params {
			query.Set(name, value)
		}
		return query.Encode()
	}
	redirectTo := func(response *httptest.ResponseRecorder) *url.URL {
		t.Helper()
		location, err := url.Parse(response.Header().Get("Location"))
		require.NoError(t, err)
		return location
	}

	t.Run("redirects a valid session to the registered URI with a bound code", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		token := createSessionToken(t, app, "alice", time.Now())

		response := httptest.NewRecorder()
		app.server.Handler().ServeHTTP(
			response,
			authorizeRequestWithSession(queryFor(validPublicRequest()), token),
		)

		require.Equal(t, http.StatusFound, response.Code)
		require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
		location := redirectTo(response)
		base := location.Scheme + "://" + location.Host + location.Path
		require.Equal(t, "https://app.example.com/callback", base)
		require.Equal(t, "STATE", location.Query().Get("state"))

		code, err := app.codes.ConsumeCode(
			context.Background(),
			location.Query().Get("code"),
			time.Now(),
		)
		require.NoError(t, err)
		require.Equal(t, "alice", code.Subject)
		require.Zero(t, code.TOTPRev)
		require.Equal(t, "public-app", code.ClientID)
		require.Equal(t, "https://app.example.com/callback", code.RedirectURI)
		require.Equal(t, "openid profile", code.Scope)
		require.Equal(t, "NONCE", code.Nonce)
		require.Equal(t, referenceCodeChallenge, code.PKCEChallenge)
		require.Equal(t, "S256", code.PKCEMethod)
		require.WithinDuration(
			t,
			time.Now().Add(authorizationCodeLifetime),
			code.ExpiresAt,
			time.Minute,
		)
	})

	t.Run("omits state when the request carried none", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		token := createSessionToken(t, app, "alice", time.Now())
		params := validPublicRequest()
		delete(params, "state")

		response := httptest.NewRecorder()
		app.server.Handler().ServeHTTP(
			response,
			authorizeRequestWithSession(queryFor(params), token),
		)

		location := redirectTo(response)
		require.NotEmpty(t, location.Query().Get("code"))
		require.Empty(t, location.Query().Get("state"))
	})

	t.Run("prompt=none with a valid session issues a code silently", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		token := createSessionToken(t, app, "alice", time.Now())
		params := validPublicRequest()
		params["prompt"] = "none"

		response := httptest.NewRecorder()
		app.server.Handler().ServeHTTP(
			response,
			authorizeRequestWithSession(queryFor(params), token),
		)

		location := redirectTo(response)
		require.NotEmpty(t, location.Query().Get("code"))
		require.Equal(t, "STATE", location.Query().Get("state"))
	})

	t.Run("prompt=none with an unusable session fails with login_required", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		token := createSessionToken(t, app, "alice", time.Now())
		params := validPublicRequest()
		params["prompt"] = "none"

		response := httptest.NewRecorder()
		app.server.Handler().ServeHTTP(
			response,
			authorizeRequestWithSession(queryFor(params), token+"corrupted"),
		)

		requireErrorRedirect(t, response, "login_required", "STATE")
	})

	t.Run("prompt=login forces re-authentication despite a valid session", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		token := createSessionToken(t, app, "alice", time.Now())
		params := validPublicRequest()
		params["prompt"] = "login"

		response := httptest.NewRecorder()
		app.server.Handler().ServeHTTP(
			response,
			authorizeRequestWithSession(queryFor(params), token),
		)

		require.Equal(t, http.StatusFound, response.Code)
		require.True(t, strings.HasPrefix(response.Header().Get("Location"), "/login"))
	})

	t.Run("prompt=consent with a valid session issues a code", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		token := createSessionToken(t, app, "alice", time.Now())
		params := validPublicRequest()
		params["prompt"] = "consent"

		response := httptest.NewRecorder()
		app.server.Handler().ServeHTTP(
			response,
			authorizeRequestWithSession(queryFor(params), token),
		)

		location := redirectTo(response)
		require.NotEmpty(t, location.Query().Get("code"))
	})

	t.Run("prompt=select_account with a valid session issues a code", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		token := createSessionToken(t, app, "alice", time.Now())
		params := validPublicRequest()
		params["prompt"] = "select_account"

		response := httptest.NewRecorder()
		app.server.Handler().ServeHTTP(
			response,
			authorizeRequestWithSession(queryFor(params), token),
		)

		location := redirectTo(response)
		require.NotEmpty(t, location.Query().Get("code"))
	})

	t.Run("max_age with a session within the limit issues a code", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		token := createSessionToken(t, app, "alice", time.Now().Add(-time.Minute))
		params := validPublicRequest()
		params["max_age"] = "3600"

		response := httptest.NewRecorder()
		app.server.Handler().ServeHTTP(
			response,
			authorizeRequestWithSession(queryFor(params), token),
		)

		location := redirectTo(response)
		require.NotEmpty(t, location.Query().Get("code"))
	})

	t.Run("max_age with an older session forces re-authentication", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		token := createSessionToken(t, app, "alice", time.Now().Add(-2*time.Hour))
		params := validPublicRequest()
		params["max_age"] = "3600"

		response := httptest.NewRecorder()
		app.server.Handler().ServeHTTP(
			response,
			authorizeRequestWithSession(queryFor(params), token),
		)

		require.Equal(t, http.StatusFound, response.Code)
		require.True(t, strings.HasPrefix(response.Header().Get("Location"), "/login"))
	})

	t.Run("preserves the redirect URI's own query parameters", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		token := createSessionToken(t, app, "alice", time.Now())
		params := validPublicRequest()
		params["client_id"] = "query-app"
		params["redirect_uri"] = "https://app.example.com/callback?tenant=1"

		response := httptest.NewRecorder()
		app.server.Handler().ServeHTTP(
			response,
			authorizeRequestWithSession(queryFor(params), token),
		)

		location := redirectTo(response)
		require.Equal(t, "1", location.Query().Get("tenant"))
		require.NotEmpty(t, location.Query().Get("code"))
		require.Equal(t, "STATE", location.Query().Get("state"))
	})

	t.Run("binds a confidential request without PKCE to no PKCE material", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		token := createSessionToken(t, app, "alice", time.Now())
		params := map[string]string{
			"client_id":     "confidential-app",
			"redirect_uri":  "https://app.example.com/callback",
			"response_type": "code",
			"scope":         "openid",
			"state":         "STATE",
			"nonce":         "NONCE",
		}

		response := httptest.NewRecorder()
		app.server.Handler().ServeHTTP(
			response,
			authorizeRequestWithSession(queryFor(params), token),
		)

		location := redirectTo(response)
		code, err := app.codes.ConsumeCode(
			context.Background(),
			location.Query().Get("code"),
			time.Now(),
		)
		require.NoError(t, err)
		require.Empty(t, code.PKCEChallenge)
		require.Empty(t, code.PKCEMethod)
	})

	t.Run("sends an invalid session cookie to the login interaction", func(t *testing.T) {
		app := newTestApp(t, testUsers)

		response := httptest.NewRecorder()
		app.server.Handler().ServeHTTP(
			response,
			authorizeRequestWithSession(queryFor(validPublicRequest()), "not-a-token"),
		)

		require.Equal(t, http.StatusFound, response.Code)
		require.Equal(
			t,
			"/login?"+queryFor(validPublicRequest()),
			response.Header().Get("Location"),
		)
	})

	t.Run("sends a revoked session to the login interaction", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		token := createSessionToken(t, app, "alice", time.Now())
		require.NoError(t, app.sessions.Revoke(context.Background(), token))

		response := httptest.NewRecorder()
		app.server.Handler().ServeHTTP(
			response,
			authorizeRequestWithSession(queryFor(validPublicRequest()), token),
		)

		require.Equal(t, http.StatusFound, response.Code)
		require.Equal(
			t,
			"/login?"+queryFor(validPublicRequest()),
			response.Header().Get("Location"),
		)
	})

	t.Run("sends an expired session to the login interaction", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		token := createSessionToken(t, app, "alice", time.Now().Add(-(testMaxAge + time.Hour)))

		response := httptest.NewRecorder()
		app.server.Handler().ServeHTTP(
			response,
			authorizeRequestWithSession(queryFor(validPublicRequest()), token),
		)

		require.Equal(t, http.StatusFound, response.Code)
		require.Equal(
			t,
			"/login?"+queryFor(validPublicRequest()),
			response.Header().Get("Location"),
		)
	})

	t.Run("sends a removed user's session to the login interaction", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		token := createSessionToken(t, app, "ghost", time.Now())

		response := httptest.NewRecorder()
		app.server.Handler().ServeHTTP(
			response,
			authorizeRequestWithSession(queryFor(validPublicRequest()), token),
		)

		require.Equal(t, http.StatusFound, response.Code)
		require.Equal(
			t,
			"/login?"+queryFor(validPublicRequest()),
			response.Header().Get("Location"),
		)
		_, err := app.sessions.Validate(context.Background(), token, time.Now())
		require.ErrorIs(t, err, session.ErrInvalidSession)
	})

	t.Run("sends an expired user's session to the login interaction", func(t *testing.T) {
		users := []config.User{{Subject: "alice", ExpiresAt: time.Now().Add(-time.Hour)}}
		app := newTestApp(t, users)
		token := createSessionToken(t, app, "alice", time.Now())

		response := httptest.NewRecorder()
		app.server.Handler().ServeHTTP(
			response,
			authorizeRequestWithSession(queryFor(validPublicRequest()), token),
		)

		require.Equal(t, http.StatusFound, response.Code)
		require.Equal(
			t,
			"/login?"+queryFor(validPublicRequest()),
			response.Header().Get("Location"),
		)
		_, err := app.sessions.Validate(context.Background(), token, time.Now())
		require.ErrorIs(t, err, session.ErrInvalidSession)
	})

	t.Run("sends a stale-revision session to the login interaction", func(t *testing.T) {
		users := []config.User{{Subject: "alice", TOTPRevision: 1}}
		app := newTestApp(t, users)
		token := createSessionToken(t, app, "alice", time.Now())

		response := httptest.NewRecorder()
		app.server.Handler().ServeHTTP(
			response,
			authorizeRequestWithSession(queryFor(validPublicRequest()), token),
		)

		require.Equal(t, http.StatusFound, response.Code)
		require.Equal(
			t,
			"/login?"+queryFor(validPublicRequest()),
			response.Header().Get("Location"),
		)
		_, err := app.sessions.Validate(context.Background(), token, time.Now())
		require.ErrorIs(t, err, session.ErrInvalidSession)
	})

	t.Run("sends a locked subject's session to the login interaction", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		token := createSessionToken(t, app, "alice", time.Now())
		queries := statestore.New(app.db)
		require.NoError(
			t,
			queries.CreatePanicLock(context.Background(), statestore.CreatePanicLockParams{
				Sub:       "alice",
				CreatedAt: clock.Format(time.Now()),
			}),
		)

		response := httptest.NewRecorder()
		app.server.Handler().ServeHTTP(
			response,
			authorizeRequestWithSession(queryFor(validPublicRequest()), token),
		)

		require.Equal(t, http.StatusFound, response.Code)
		require.Equal(
			t,
			"/login?"+queryFor(validPublicRequest()),
			response.Header().Get("Location"),
		)
		_, err := app.sessions.Validate(context.Background(), token, time.Now())
		require.ErrorIs(t, err, session.ErrInvalidSession)
	})

	t.Run("reports session usability failures", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		app.server.authorization.Locks = failingLockChecker{}
		token := createSessionToken(t, app, "alice", time.Now())

		response := httptest.NewRecorder()
		app.server.Handler().ServeHTTP(
			response,
			authorizeRequestWithSession(queryFor(validPublicRequest()), token),
		)

		require.Equal(t, http.StatusInternalServerError, response.Code)
		require.Empty(t, response.Header().Get("Location"))
	})

	t.Run("validates the request before honoring a session", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		token := createSessionToken(t, app, "alice", time.Now())
		params := validPublicRequest()
		params["scope"] = "profile"

		response := httptest.NewRecorder()
		app.server.Handler().ServeHTTP(
			response,
			authorizeRequestWithSession(queryFor(params), token),
		)

		requireErrorRedirect(t, response, "invalid_scope", "STATE")
		require.Empty(t, redirectTo(response).Query().Get("code"))
	})

	t.Run("reports session validation failures", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		app.server.authorization.Sessions = failingSessionValidator{}

		response := httptest.NewRecorder()
		app.server.Handler().ServeHTTP(
			response,
			authorizeRequestWithSession(queryFor(validPublicRequest()), "sess_abc_def"),
		)

		require.Equal(t, http.StatusInternalServerError, response.Code)
		require.Empty(t, response.Header().Get("Location"))
	})

	t.Run("reports authorization code issuance failures", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		app.server.authorization.Codes = failingCodeIssuer{}
		token := createSessionToken(t, app, "alice", time.Now())

		response := httptest.NewRecorder()
		app.server.Handler().ServeHTTP(
			response,
			authorizeRequestWithSession(queryFor(validPublicRequest()), token),
		)

		require.Equal(t, http.StatusInternalServerError, response.Code)
		require.Empty(t, response.Header().Get("Location"))
	})

	t.Run("completes the login flow with a code redirect", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		secret, err := totp.DeriveSharedSecret(referenceRootSecret, "alice", 0)
		require.NoError(t, err)
		query := queryFor(validPublicRequest())
		csrfValue := loginCSRFToken(t, app, query)
		form := url.Values{
			"identifier":   {"alice"},
			"code":         {totpCode(t, secret, time.Now())},
			csrf.FieldName: {csrfValue},
		}
		response := httptest.NewRecorder()
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodPost,
			"/login?"+query,
			strings.NewReader(form.Encode()),
		)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: csrfValue})
		app.server.Handler().ServeHTTP(response, request)
		require.Equal(t, http.StatusSeeOther, response.Code)
		cookie := response.Result().Cookies()[0]

		response = httptest.NewRecorder()
		app.server.Handler().ServeHTTP(
			response,
			authorizeRequestWithSession(queryFor(validPublicRequest()), cookie.Value),
		)

		require.Equal(t, http.StatusFound, response.Code)
		location := redirectTo(response)
		base := location.Scheme + "://" + location.Host + location.Path
		require.Equal(t, "https://app.example.com/callback", base)
		require.Equal(t, "STATE", location.Query().Get("state"))
		require.NotEmpty(t, location.Query().Get("code"))
	})
}

// failingSessionValidator is a SessionStore that always fails validation
// with an infrastructure error.
type failingSessionValidator struct{}

func (failingSessionValidator) Validate(
	context.Context,
	string,
	time.Time,
) (session.Session, error) {
	return session.Session{}, errors.New("session store unavailable")
}

func (failingSessionValidator) Revoke(context.Context, string) error {
	return errors.New("session store unavailable")
}

// failingLockChecker is a LockChecker that always fails with an
// infrastructure error.
type failingLockChecker struct{}

func (failingLockChecker) IsLocked(context.Context, string) (bool, error) {
	return false, errors.New("lock store unavailable")
}

// failingCodeIssuer is a CodeIssuer that always fails with an
// infrastructure error.
type failingCodeIssuer struct{}

func (failingCodeIssuer) CreateCode(context.Context, onetoken.CodeParams) (string, error) {
	return "", errors.New("one-use token store unavailable")
}
