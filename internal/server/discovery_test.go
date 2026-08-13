package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/varavelio/zen-idp/internal/ui"
)

// referenceDiscoveryDocument is the exact discovery metadata this server
// advertises for the reference issuer, anchoring every advertised field.
const referenceDiscoveryDocument = `{
	"issuer": "https://auth.example.com",
	"authorization_endpoint": "https://auth.example.com/authorize",
	"token_endpoint": "https://auth.example.com/token",
	"userinfo_endpoint": "https://auth.example.com/userinfo",
	"end_session_endpoint": "https://auth.example.com/logout",
	"jwks_uri": "https://auth.example.com/.well-known/jwks.json",
	"response_types_supported": ["code"],
	"subject_types_supported": ["public"],
	"id_token_signing_alg_values_supported": ["RS256"],
	"scopes_supported": ["openid"],
	"token_endpoint_auth_methods_supported": ["none", "client_secret_basic"],
	"grant_types_supported": ["authorization_code"],
	"response_modes_supported": ["query"],
	"code_challenge_methods_supported": ["S256"]
}`

func TestDiscovery(t *testing.T) {
	newHandler := func(issuer string) http.Handler {
		return New(
			testPublicJWK(),
			issuer,
			testClients(),
			ui.Assets(),
			LoginDependencies{},
			AuthorizeDependencies{},
			TokenDependencies{},
			UserinfoDependencies{},
			LogoutDependencies{},
			EnrollDependencies{},
			AdminDependencies{},
		).Handler()
	}

	t.Run("serves the discovery metadata document", func(t *testing.T) {
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodGet,
			"/.well-known/openid-configuration",
			nil,
		)
		response := httptest.NewRecorder()

		newHandler(referenceIssuer).ServeHTTP(response, request)

		require.Equal(t, http.StatusOK, response.Code)
		require.Equal(t, "application/json", response.Header().Get("Content-Type"))
		require.JSONEq(t, referenceDiscoveryDocument, response.Body.String())
	})

	t.Run("derives endpoints from an issuer with a trailing slash", func(t *testing.T) {
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodGet,
			"/.well-known/openid-configuration",
			nil,
		)
		response := httptest.NewRecorder()

		newHandler("https://auth.example.com/").ServeHTTP(response, request)

		require.Equal(t, http.StatusOK, response.Code)
		require.JSONEq(t, `{
			"issuer": "https://auth.example.com/",
			"authorization_endpoint": "https://auth.example.com/authorize",
			"token_endpoint": "https://auth.example.com/token",
			"userinfo_endpoint": "https://auth.example.com/userinfo",
			"end_session_endpoint": "https://auth.example.com/logout",
			"jwks_uri": "https://auth.example.com/.well-known/jwks.json",
			"response_types_supported": ["code"],
			"subject_types_supported": ["public"],
			"id_token_signing_alg_values_supported": ["RS256"],
			"scopes_supported": ["openid"],
			"token_endpoint_auth_methods_supported": ["none", "client_secret_basic"],
			"grant_types_supported": ["authorization_code"],
			"response_modes_supported": ["query"],
			"code_challenge_methods_supported": ["S256"]
		}`, response.Body.String())
	})

	t.Run("rejects other methods", func(t *testing.T) {
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodPost,
			"/.well-known/openid-configuration",
			nil,
		)
		response := httptest.NewRecorder()

		newHandler(referenceIssuer).ServeHTTP(response, request)

		require.Equal(t, http.StatusMethodNotAllowed, response.Code)
	})

	t.Run("does not advertise endpoints that are not implemented", func(t *testing.T) {
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodGet,
			"/.well-known/openid-configuration",
			nil,
		)
		response := httptest.NewRecorder()

		newHandler(referenceIssuer).ServeHTTP(response, request)

		require.NotContains(t, response.Body.String(), "implicit")
		require.NotContains(t, response.Body.String(), "client_secret_post")
		require.NotContains(t, response.Body.String(), "plain")
	})
}
