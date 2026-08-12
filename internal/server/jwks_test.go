package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/varavelio/zen-idp/internal/jwk"
	"github.com/varavelio/zen-idp/internal/ui"
)

const testJWKJSON = `{"kty":"RSA","n":"MODULUS","e":"AQAB","alg":"RS256","use":"sig","kid":"KID"}`

func testPublicJWK() jwk.PublicJWK {
	return jwk.PublicJWK{
		Kty: "RSA",
		N:   "MODULUS",
		E:   "AQAB",
		Alg: "RS256",
		Use: "sig",
		Kid: "KID",
	}
}

func TestJWKS(t *testing.T) {
	t.Run("serves the public signing identity", func(t *testing.T) {
		handler := New(
			testPublicJWK(),
			nil,
			ui.Assets(),
			LoginDependencies{},
			AuthorizeDependencies{},
		).Handler()
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodGet,
			"/.well-known/jwks.json",
			nil,
		)
		response := httptest.NewRecorder()

		handler.ServeHTTP(response, request)

		require.Equal(t, http.StatusOK, response.Code)
		require.Equal(t, "application/json", response.Header().Get("Content-Type"))
		require.JSONEq(t, `{"keys":[`+testJWKJSON+`]}`, response.Body.String())
	})

	t.Run("rejects other methods", func(t *testing.T) {
		handler := New(
			testPublicJWK(),
			nil,
			ui.Assets(),
			LoginDependencies{},
			AuthorizeDependencies{},
		).Handler()
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodPost,
			"/.well-known/jwks.json",
			nil,
		)
		response := httptest.NewRecorder()

		handler.ServeHTTP(response, request)

		require.Equal(t, http.StatusMethodNotAllowed, response.Code)
	})

	t.Run("returns 404 for unknown paths", func(t *testing.T) {
		handler := New(
			testPublicJWK(),
			nil,
			ui.Assets(),
			LoginDependencies{},
			AuthorizeDependencies{},
		).Handler()
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodGet,
			"/unknown",
			nil,
		)
		response := httptest.NewRecorder()

		handler.ServeHTTP(response, request)

		require.Equal(t, http.StatusNotFound, response.Code)
	})
}
