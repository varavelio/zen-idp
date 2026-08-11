package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/varavelio/zen-idp/internal/config"
)

// validCodeChallenge is the RFC 7636 appendix B example code challenge,
// which is exactly 43 characters of the unreserved base64url alphabet.
const referenceCodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

func testClients() []config.Client {
	return []config.Client{
		{
			ID:           "public-app",
			RedirectURIs: []string{"https://app.example.com/callback"},
		},
		{
			ID:           "confidential-app",
			SecretHash:   "HASH",
			RedirectURIs: []string{"https://app.example.com/callback"},
		},
		{
			ID:           "query-app",
			SecretHash:   "HASH",
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
	handler := New(testPublicJWK(), testClients()).Handler()

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

	t.Run("rejects a missing state parameter", func(t *testing.T) {
		params := validPublicRequest()
		delete(params, "state")
		request := buildAuthorizeRequest(t, params)
		response := httptest.NewRecorder()

		handler.ServeHTTP(response, request)

		requireErrorRedirect(t, response, "invalid_request", "")
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

	t.Run("preserves redirect URI query parameters in error redirects", func(t *testing.T) {
		request := buildAuthorizeRequest(t, map[string]string{
			"client_id":     "query-app",
			"redirect_uri":  "https://app.example.com/callback?tenant=1",
			"response_type": "code",
			"scope":         "openid",
		})
		response := httptest.NewRecorder()

		handler.ServeHTTP(response, request)

		location, err := url.Parse(response.Header().Get("Location"))
		require.NoError(t, err)
		require.Equal(t, "1", location.Query().Get("tenant"))
		require.Equal(t, "invalid_request", location.Query().Get("error"))
	})

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
