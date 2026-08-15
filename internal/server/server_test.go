package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/require"
	"github.com/varavelio/zen-idp/internal/ui"
)

func TestNew(t *testing.T) {
	t.Run("returns a handler that serves the JWKS route", func(t *testing.T) {
		handler := New(
			testPublicJWK(),
			referenceIssuer,
			nil,
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

		require.NotNil(t, handler)
	})
}

func TestServeAssets(t *testing.T) {
	files := fstest.MapFS{
		"build/app.css": &fstest.MapFile{Data: []byte("body { color: red; }")},
		"vendor/app.js": &fstest.MapFile{Data: []byte("console.log(1)")},
	}

	newServer := func() http.Handler {
		return New(
			testPublicJWK(),
			referenceIssuer,
			nil,
			files,
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
	}

	t.Run("serves a built asset with a public cache policy", func(t *testing.T) {
		response := httptest.NewRecorder()
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodGet,
			"/build/app.css",
			nil,
		)
		newServer().ServeHTTP(response, request)

		require.Equal(t, http.StatusOK, response.Code)
		require.Equal(t, "text/css; charset=utf-8", response.Header().Get("Content-Type"))
		require.Equal(t, "public, max-age=3600", response.Header().Get("Cache-Control"))
		require.Equal(t, "body { color: red; }", response.Body.String())
	})

	t.Run("serves a vendored asset at its literal path", func(t *testing.T) {
		response := httptest.NewRecorder()
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodGet,
			"/vendor/app.js",
			nil,
		)
		newServer().ServeHTTP(response, request)

		require.Equal(t, http.StatusOK, response.Code)
		require.Equal(t, "text/javascript; charset=utf-8", response.Header().Get("Content-Type"))
		require.Equal(t, "console.log(1)", response.Body.String())
	})

	t.Run("reports missing assets with not found", func(t *testing.T) {
		response := httptest.NewRecorder()
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodGet,
			"/build/missing.css",
			nil,
		)
		newServer().ServeHTTP(response, request)

		require.Equal(t, http.StatusNotFound, response.Code)
	})

	t.Run("does not serve files outside the registered prefixes", func(t *testing.T) {
		response := httptest.NewRecorder()
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodGet,
			"/build/../vendor/app.js",
			nil,
		)
		newServer().ServeHTTP(response, request)

		require.NotEqual(t, http.StatusOK, response.Code)
	})

	t.Run("serves the compiled stylesheet from the real asset tree", func(t *testing.T) {
		handler := New(
			testPublicJWK(),
			referenceIssuer,
			nil,
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

		response := httptest.NewRecorder()
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodGet,
			"/build/app.css",
			nil,
		)
		handler.ServeHTTP(response, request)

		require.Equal(t, http.StatusOK, response.Code)
		require.Contains(t, response.Body.String(), "tailwindcss")
	})

	t.Run("serves the vendored fonts from the real asset tree", func(t *testing.T) {
		handler := New(
			testPublicJWK(),
			referenceIssuer,
			nil,
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

		response := httptest.NewRecorder()
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodGet,
			"/vendor/fonts/Geist-Variable.woff2",
			nil,
		)
		handler.ServeHTTP(response, request)

		require.Equal(t, http.StatusOK, response.Code)
		require.Equal(t, "font/woff2", response.Header().Get("Content-Type"))
	})
}
