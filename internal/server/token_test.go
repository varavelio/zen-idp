package server

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/varavelio/zen-idp/internal/audit"
	"github.com/varavelio/zen-idp/internal/clock"
	"github.com/varavelio/zen-idp/internal/config"
	"github.com/varavelio/zen-idp/internal/jwk"
	"github.com/varavelio/zen-idp/internal/jwt"
	"github.com/varavelio/zen-idp/internal/onetoken"
	"github.com/varavelio/zen-idp/internal/rsakeygen"
	"github.com/varavelio/zen-idp/internal/token"
	"github.com/varavelio/zen-idp/internal/ui"
)

// referenceIssuer is the issuer origin stamped on tokens by the test token
// issuer.
const referenceIssuer = "https://auth.example.com"

// referenceCodeVerifier is the RFC 7636 appendix B example verifier whose
// SHA-256 digest is referenceCodeChallenge.
const referenceCodeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

// referenceKey is the deterministic RSA-2048 signing key shared by every
// test token issuer, derived from referenceRootSecret.
var referenceKey = sync.OnceValue(func() *rsa.PrivateKey {
	key, err := rsakeygen.GeneratePrivateKey(referenceRootSecret)
	if err != nil {
		panic(err)
	}
	return key
})

// referenceKid is the RFC 7638 thumbprint of the reference signing identity.
var referenceKid = sync.OnceValue(func() string {
	public, err := jwk.FromPublicKey(&referenceKey().PublicKey)
	if err != nil {
		panic(err)
	}
	return public.Kid
})

// createCode records an authorization code for the alice test user with the
// given field overrides and returns its redeemable token.
func createCode(t *testing.T, app *testApp, override func(*onetoken.CodeParams)) string {
	t.Helper()
	now := time.Now()
	params := onetoken.CodeParams{
		Subject:     "alice",
		ClientID:    "public-app",
		RedirectURI: "https://app.example.com/callback",
		Scope:       "openid profile",
		Nonce:       "NONCE",
		AuthTime:    now,
		ExpiresAt:   now.Add(time.Hour),
		Now:         now,
	}
	if override != nil {
		override(&params)
	}
	code, err := app.codes.CreateCode(context.Background(), params)
	require.NoError(t, err)
	return code
}

// validExchangeForm builds the form values of a valid public-client code
// exchange for the given code.
func validExchangeForm(code string) url.Values {
	return url.Values{
		"grant_type":   {"authorization_code"},
		"client_id":    {"public-app"},
		"code":         {code},
		"redirect_uri": {"https://app.example.com/callback"},
	}
}

// tokenRequest performs a POST /token request against handler with the given
// form values and optional HTTP Basic authorization header.
func tokenRequest(
	t *testing.T,
	handler http.Handler,
	form url.Values,
	authorization string,
) *httptest.ResponseRecorder {
	t.Helper()
	response := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		"/token",
		strings.NewReader(form.Encode()),
	)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	handler.ServeHTTP(response, request)
	return response
}

// basicAuth builds the HTTP Basic authorization header value for the given
// client credentials.
func basicAuth(clientID, secret string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(clientID+":"+secret))
}

// tokenResponseBody is the JSON body of a successful token response.
type tokenResponseBody struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	IDToken     string `json:"id_token"`
	Scope       string `json:"scope"`
}

// decodeTokenResponse parses a successful token response body.
func decodeTokenResponse(t *testing.T, response *httptest.ResponseRecorder) tokenResponseBody {
	t.Helper()
	var body tokenResponseBody
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &body))
	return body
}

// requireTokenError asserts that response is a JSON token error response with
// the given status and OIDC error code.
func requireTokenError(t *testing.T, response *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	require.Equal(t, status, response.Code)
	require.Equal(t, "application/json; charset=utf-8", response.Header().Get("Content-Type"))
	require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
	if status == http.StatusUnauthorized {
		require.Equal(t, `Basic realm="zen-idp"`, response.Header().Get("WWW-Authenticate"))
	}
	var body tokenErrorResponse
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &body))
	require.Equal(t, code, body.Error)
	require.NotEmpty(t, body.ErrorDescription)
}

func TestToken(t *testing.T) {
	verifier := func(t *testing.T) *jwt.Verifier {
		t.Helper()
		verifier, err := jwt.NewVerifier(&referenceKey().PublicKey, referenceKid())
		require.NoError(t, err)
		return verifier
	}

	t.Run("issues ID and access tokens for a public client with PKCE", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		code := createCode(t, app, func(params *onetoken.CodeParams) {
			params.PKCEChallenge = referenceCodeChallenge
			params.PKCEMethod = "S256"
		})
		form := validExchangeForm(code)
		form.Set("code_verifier", referenceCodeVerifier)
		response := tokenRequest(t, app.server.Handler(), form, "")

		require.Equal(t, http.StatusOK, response.Code)
		require.Equal(t, "application/json; charset=utf-8", response.Header().Get("Content-Type"))
		require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
		require.Equal(t, "no-cache", response.Header().Get("Pragma"))

		body := decodeTokenResponse(t, response)
		require.NotEmpty(t, body.AccessToken)
		require.NotEmpty(t, body.IDToken)
		require.Equal(t, "Bearer", body.TokenType)
		require.Equal(t, int64(token.Lifetime.Seconds()), body.ExpiresIn)
		require.Equal(t, "openid profile", body.Scope)

		idClaims, err := verifier(t).Verify(body.IDToken)
		require.NoError(t, err)
		require.Equal(t, referenceIssuer, idClaims["iss"])
		require.Equal(t, "alice", idClaims["sub"])
		require.Equal(t, "public-app", idClaims["aud"])
		require.Equal(t, "NONCE", idClaims["nonce"])
		require.Equal(t, float64(900), idClaims["exp"].(float64)-idClaims["iat"].(float64))

		accessClaims, err := verifier(t).Verify(body.AccessToken)
		require.NoError(t, err)
		require.Equal(t, referenceIssuer, accessClaims["iss"])
		require.Equal(t, "alice", accessClaims["sub"])
		require.Equal(t, referenceIssuer+"/userinfo", accessClaims["aud"])
		require.Equal(t, float64(900), accessClaims["exp"].(float64)-accessClaims["iat"].(float64))
		require.Len(t, accessClaims, 5)
		require.NotContains(t, accessClaims, "nonce")
	})

	t.Run("issues tokens for a confidential client with client_secret_basic", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		code := createCode(t, app, func(params *onetoken.CodeParams) {
			params.ClientID = "confidential-app"
		})
		response := tokenRequest(
			t,
			app.server.Handler(),
			validExchangeForm(code),
			basicAuth("confidential-app", testClientSecret),
		)

		require.Equal(t, http.StatusOK, response.Code)
		body := decodeTokenResponse(t, response)
		require.NotEmpty(t, body.AccessToken)
		require.NotEmpty(t, body.IDToken)

		claims, err := verifier(t).Verify(body.IDToken)
		require.NoError(t, err)
		require.Equal(t, "confidential-app", claims["aud"])
	})

	t.Run("accepts a lowercase client_secret_basic scheme", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		code := createCode(t, app, func(params *onetoken.CodeParams) {
			params.ClientID = "confidential-app"
		})
		credentials := base64.StdEncoding.EncodeToString(
			[]byte("confidential-app:" + testClientSecret),
		)
		response := tokenRequest(
			t,
			app.server.Handler(),
			validExchangeForm(code),
			"basic "+credentials,
		)

		require.Equal(t, http.StatusOK, response.Code)
		body := decodeTokenResponse(t, response)
		require.NotEmpty(t, body.AccessToken)
	})

	t.Run("rejects an oversized request body", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodPost,
			"/token",
			strings.NewReader(strings.Repeat("a", maxRequestBodyBytes+1)),
		)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response := httptest.NewRecorder()

		app.server.Handler().ServeHTTP(response, request)

		requireTokenError(t, response, http.StatusBadRequest, "invalid_request")
	})

	t.Run("accepts a confidential client secret over HTTPS in production", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		app.server.tokens.RequireClientSecretTLS = true
		code := createCode(t, app, func(params *onetoken.CodeParams) {
			params.ClientID = "confidential-app"
		})

		server := httptest.NewTLSServer(app.server.Handler())
		defer server.Close()
		request, err := http.NewRequestWithContext(
			context.Background(),
			http.MethodPost,
			server.URL+"/token",
			strings.NewReader(validExchangeForm(code).Encode()),
		)
		require.NoError(t, err)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.Header.Set("Authorization", basicAuth("confidential-app", testClientSecret))
		response, err := server.Client().Do(request)
		require.NoError(t, err)
		t.Cleanup(func() { _ = response.Body.Close() })

		require.Equal(t, http.StatusOK, response.StatusCode)
	})

	t.Run("rejects a confidential client secret over plain HTTP in production", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		app.server.tokens.RequireClientSecretTLS = true
		code := createCode(t, app, func(params *onetoken.CodeParams) {
			params.ClientID = "confidential-app"
		})

		server := httptest.NewServer(app.server.Handler())
		defer server.Close()
		request, err := http.NewRequestWithContext(
			context.Background(),
			http.MethodPost,
			server.URL+"/token",
			strings.NewReader(validExchangeForm(code).Encode()),
		)
		require.NoError(t, err)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.Header.Set("Authorization", basicAuth("confidential-app", testClientSecret))
		response, err := server.Client().Do(request)
		require.NoError(t, err)
		t.Cleanup(func() { _ = response.Body.Close() })

		require.Equal(t, http.StatusUnauthorized, response.StatusCode)
		var body tokenErrorResponse
		require.NoError(t, json.NewDecoder(response.Body).Decode(&body))
		require.Equal(t, "invalid_client", body.Error)
	})

	t.Run("rejects a confidential client without credentials", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		code := createCode(t, app, func(params *onetoken.CodeParams) {
			params.ClientID = "confidential-app"
		})
		form := validExchangeForm(code)
		form.Set("client_id", "confidential-app")
		response := tokenRequest(t, app.server.Handler(), form, "")

		requireTokenError(t, response, http.StatusUnauthorized, "invalid_client")
	})

	t.Run("rejects a confidential client with the wrong secret", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		code := createCode(t, app, func(params *onetoken.CodeParams) {
			params.ClientID = "confidential-app"
		})
		response := tokenRequest(
			t,
			app.server.Handler(),
			validExchangeForm(code),
			basicAuth("confidential-app", "wrong-secret"),
		)

		requireTokenError(t, response, http.StatusUnauthorized, "invalid_client")
	})

	t.Run("rejects a public client that presents a client secret", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		code := createCode(t, app, nil)
		response := tokenRequest(
			t,
			app.server.Handler(),
			validExchangeForm(code),
			basicAuth("public-app", testClientSecret),
		)

		requireTokenError(t, response, http.StatusUnauthorized, "invalid_client")
	})

	t.Run("rejects an unknown client", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		code := createCode(t, app, nil)
		form := validExchangeForm(code)
		form.Set("client_id", "unknown")
		response := tokenRequest(t, app.server.Handler(), form, "")

		requireTokenError(t, response, http.StatusUnauthorized, "invalid_client")
	})

	t.Run("rejects an unsupported client authentication method", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		code := createCode(t, app, nil)
		response := tokenRequest(t, app.server.Handler(), validExchangeForm(code), "Bearer token")

		requireTokenError(t, response, http.StatusUnauthorized, "invalid_client")
	})

	t.Run("rejects a missing grant type", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		code := createCode(t, app, nil)
		form := validExchangeForm(code)
		form.Del("grant_type")
		response := tokenRequest(t, app.server.Handler(), form, "")

		requireTokenError(t, response, http.StatusBadRequest, "invalid_request")
	})

	t.Run("rejects an unsupported grant type", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		code := createCode(t, app, nil)
		form := validExchangeForm(code)
		form.Set("grant_type", "refresh_token")
		response := tokenRequest(t, app.server.Handler(), form, "")

		requireTokenError(t, response, http.StatusBadRequest, "unsupported_grant_type")
	})

	t.Run("rejects a missing code", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		response := tokenRequest(t, app.server.Handler(), validExchangeForm(""), "")

		requireTokenError(t, response, http.StatusBadRequest, "invalid_request")
	})

	t.Run("rejects a missing redirect URI", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		code := createCode(t, app, nil)
		form := validExchangeForm(code)
		form.Del("redirect_uri")
		response := tokenRequest(t, app.server.Handler(), form, "")

		requireTokenError(t, response, http.StatusBadRequest, "invalid_request")
	})

	t.Run("rejects a code issued to another client", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		code := createCode(t, app, nil)
		response := tokenRequest(
			t,
			app.server.Handler(),
			validExchangeForm(code),
			basicAuth("confidential-app", testClientSecret),
		)

		requireTokenError(t, response, http.StatusBadRequest, "invalid_grant")
	})

	t.Run("rejects a mismatched redirect URI", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		code := createCode(t, app, nil)
		form := validExchangeForm(code)
		form.Set("redirect_uri", "https://evil.example.com/callback")
		response := tokenRequest(t, app.server.Handler(), form, "")

		requireTokenError(t, response, http.StatusBadRequest, "invalid_grant")
	})

	t.Run("rejects a missing PKCE verifier", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		code := createCode(t, app, func(params *onetoken.CodeParams) {
			params.PKCEChallenge = referenceCodeChallenge
			params.PKCEMethod = "S256"
		})
		response := tokenRequest(t, app.server.Handler(), validExchangeForm(code), "")

		requireTokenError(t, response, http.StatusBadRequest, "invalid_grant")
	})

	t.Run("rejects a wrong PKCE verifier", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		code := createCode(t, app, func(params *onetoken.CodeParams) {
			params.PKCEChallenge = referenceCodeChallenge
			params.PKCEMethod = "S256"
		})
		form := validExchangeForm(code)
		form.Set("code_verifier", referenceCodeChallenge)
		response := tokenRequest(t, app.server.Handler(), form, "")

		requireTokenError(t, response, http.StatusBadRequest, "invalid_grant")
	})

	t.Run("rejects a malformed PKCE verifier", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		code := createCode(t, app, func(params *onetoken.CodeParams) {
			params.PKCEChallenge = referenceCodeChallenge
			params.PKCEMethod = "S256"
		})
		form := validExchangeForm(code)
		form.Set("code_verifier", "short")
		response := tokenRequest(t, app.server.Handler(), form, "")

		requireTokenError(t, response, http.StatusBadRequest, "invalid_grant")
	})

	t.Run("rejects a redeemed code", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		code := createCode(t, app, nil)
		form := validExchangeForm(code)
		first := tokenRequest(t, app.server.Handler(), form, "")
		require.Equal(t, http.StatusOK, first.Code)

		second := tokenRequest(t, app.server.Handler(), form, "")

		requireTokenError(t, second, http.StatusBadRequest, "invalid_grant")
	})

	t.Run("rejects an expired code", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		code := createCode(t, app, nil)
		id, _, ok := strings.Cut(strings.TrimPrefix(code, "tok_"), "_")
		require.True(t, ok)
		_, err := app.db.ExecContext(
			context.Background(),
			"UPDATE one_use_tokens SET expires_at = ? WHERE id = ?",
			clock.Format(time.Now().Add(-time.Minute)),
			id,
		)
		require.NoError(t, err)

		response := tokenRequest(t, app.server.Handler(), validExchangeForm(code), "")

		requireTokenError(t, response, http.StatusBadRequest, "invalid_grant")
	})

	t.Run("rejects a malformed code", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		response := tokenRequest(t, app.server.Handler(), validExchangeForm("not-a-token"), "")

		requireTokenError(t, response, http.StatusBadRequest, "invalid_grant")
	})

	t.Run("rejects a code whose subject is no longer declared", func(t *testing.T) {
		app := newTestApp(t, nil)
		code := createCode(t, app, nil)
		response := tokenRequest(t, app.server.Handler(), validExchangeForm(code), "")

		requireTokenError(t, response, http.StatusBadRequest, "invalid_grant")
	})

	t.Run("rejects a code whose subject is expired", func(t *testing.T) {
		users := []config.User{{Subject: "alice", ExpiresAt: time.Now().Add(-time.Hour)}}
		app := newTestApp(t, users)
		code := createCode(t, app, nil)
		response := tokenRequest(t, app.server.Handler(), validExchangeForm(code), "")

		requireTokenError(t, response, http.StatusBadRequest, "invalid_grant")
	})

	t.Run("rejects a code whose subject is locked", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		require.NoError(t, app.locks.LockSubject(context.Background(), "alice", time.Now()))
		code := createCode(t, app, nil)
		response := tokenRequest(t, app.server.Handler(), validExchangeForm(code), "")

		requireTokenError(t, response, http.StatusBadRequest, "invalid_grant")
	})

	t.Run("rejects a code bound to a stale TOTP revision", func(t *testing.T) {
		users := []config.User{{Subject: "alice", TOTPRevision: 1}}
		app := newTestApp(t, users)
		code := createCode(t, app, func(params *onetoken.CodeParams) {
			params.TOTPRev = 0
		})
		response := tokenRequest(t, app.server.Handler(), validExchangeForm(code), "")

		requireTokenError(t, response, http.StatusBadRequest, "invalid_grant")
	})

	t.Run("accepts a code bound to the current TOTP revision", func(t *testing.T) {
		users := []config.User{{Subject: "alice", TOTPRevision: 3}}
		app := newTestApp(t, users)
		code := createCode(t, app, func(params *onetoken.CodeParams) {
			params.TOTPRev = 3
		})
		response := tokenRequest(t, app.server.Handler(), validExchangeForm(code), "")

		require.Equal(t, http.StatusOK, response.Code)
		body := decodeTokenResponse(t, response)
		require.NotEmpty(t, body.AccessToken)
		require.NotEmpty(t, body.IDToken)
	})

	t.Run("rejects requests that carry query parameters", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		response := httptest.NewRecorder()
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodPost,
			"/token?foo=bar",
			strings.NewReader(url.Values{"grant_type": {"authorization_code"}}.Encode()),
		)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		app.server.Handler().ServeHTTP(response, request)

		requireTokenError(t, response, http.StatusBadRequest, "invalid_request")
	})

	t.Run(
		"blocks a confidential client after repeated failed authentication attempts",
		func(t *testing.T) {
			app := newTestApp(t, testUsers)
			code := createCode(t, app, func(params *onetoken.CodeParams) {
				params.ClientID = "confidential-app"
			})
			form := validExchangeForm(code)

			for range 5 {
				response := tokenRequest(
					t,
					app.server.Handler(),
					form,
					basicAuth("confidential-app", "wrong-secret"),
				)
				requireTokenError(t, response, http.StatusUnauthorized, "invalid_client")
			}

			// The budget is exhausted: even the correct secret is rejected until
			// the window ends.
			response := tokenRequest(
				t,
				app.server.Handler(),
				form,
				basicAuth("confidential-app", testClientSecret),
			)
			requireTokenError(t, response, http.StatusUnauthorized, "invalid_client")

			// Only the blocked attempt is recorded, against the client key;
			// the failed authentications themselves produce no events.
			events := auditEvents(t, app)
			require.Len(t, events, 1)
			require.Equal(t, audit.CategoryRateLimit, events[0].Category)
			require.Empty(t, events[0].Subject)
			require.JSONEq(t, `{"key":"confidential-app"}`, events[0].Details)
		},
	)

	t.Run("resets the failure budget after a successful authentication", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		code := createCode(t, app, func(params *onetoken.CodeParams) {
			params.ClientID = "confidential-app"
		})
		form := validExchangeForm(code)

		// Four failures leave one attempt of the five-attempt budget.
		for range 4 {
			response := tokenRequest(
				t,
				app.server.Handler(),
				form,
				basicAuth("confidential-app", "wrong-secret"),
			)
			requireTokenError(t, response, http.StatusUnauthorized, "invalid_client")
		}

		// A successful authentication resets the budget.
		response := tokenRequest(
			t,
			app.server.Handler(),
			form,
			basicAuth("confidential-app", testClientSecret),
		)
		require.Equal(t, http.StatusOK, response.Code)

		// The full budget is available again.
		for range 5 {
			response := tokenRequest(
				t,
				app.server.Handler(),
				form,
				basicAuth("confidential-app", "wrong-secret"),
			)
			requireTokenError(t, response, http.StatusUnauthorized, "invalid_client")
		}
		response = tokenRequest(
			t,
			app.server.Handler(),
			form,
			basicAuth("confidential-app", testClientSecret),
		)
		requireTokenError(t, response, http.StatusUnauthorized, "invalid_client")
	})

	t.Run("rejects a request without a client id", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		form := url.Values{
			"grant_type":   {"authorization_code"},
			"code":         {"tok_whatever"},
			"redirect_uri": {"https://app.example.com/callback"},
		}

		response := tokenRequest(t, app.server.Handler(), form, "")

		requireTokenError(t, response, http.StatusUnauthorized, "invalid_client")
	})

	t.Run(
		"returns an internal error when the client auth rate limit cannot be checked",
		func(t *testing.T) {
			handler := New(
				testPublicJWK(),
				referenceIssuer,
				testClients(),
				ui.Assets(),
				LoginDependencies{},
				AuthorizeDependencies{},
				TokenDependencies{
					Codes:      failingCodeConsumer{},
					Issuer:     failingTokenIssuer{},
					ClientAuth: failingClientAuthLimiter{},
				},
				UserinfoDependencies{},
				LogoutDependencies{},
				EnrollDependencies{},
				AdminDependencies{},
				PanicDependencies{},
			).Handler()
			response := tokenRequest(t, handler, validExchangeForm("anything"), "")

			require.Equal(t, http.StatusInternalServerError, response.Code)
			require.Contains(t, response.Body.String(), "internal server error")
		},
	)

	t.Run(
		"returns an internal error when recording a client auth failure fails",
		func(t *testing.T) {
			handler := New(
				testPublicJWK(),
				referenceIssuer,
				testClients(),
				ui.Assets(),
				LoginDependencies{},
				AuthorizeDependencies{},
				TokenDependencies{
					Codes:      failingCodeConsumer{},
					Issuer:     failingTokenIssuer{},
					ClientAuth: failingClientAuthRecorder{},
				},
				UserinfoDependencies{},
				LogoutDependencies{},
				EnrollDependencies{},
				AdminDependencies{},
				PanicDependencies{},
			).Handler()
			form := validExchangeForm("anything")
			form.Set("client_id", "unknown")
			response := tokenRequest(t, handler, form, "")

			require.Equal(t, http.StatusInternalServerError, response.Code)
			require.Contains(t, response.Body.String(), "internal server error")
		},
	)

	t.Run(
		"returns an internal error when recording a client auth rate limit event fails",
		func(t *testing.T) {
			app := newTestApp(t, testUsers)
			app.server.tokens.Audit = failingPanicAudit{}
			form := validExchangeForm("anything")
			form.Set("client_id", "unknown")

			// Exhaust the budget of the unknown client.
			for range 5 {
				response := tokenRequest(
					t,
					app.server.Handler(),
					form,
					basicAuth("unknown", "wrong-secret"),
				)
				requireTokenError(t, response, http.StatusUnauthorized, "invalid_client")
			}

			response := tokenRequest(
				t,
				app.server.Handler(),
				form,
				basicAuth("unknown", "wrong-secret"),
			)

			require.Equal(t, http.StatusInternalServerError, response.Code)
			require.Contains(t, response.Body.String(), "internal server error")
		},
	)

	t.Run("returns an internal error when code redemption fails", func(t *testing.T) {
		handler := New(
			testPublicJWK(),
			referenceIssuer,
			testClients(),
			ui.Assets(),
			LoginDependencies{},
			AuthorizeDependencies{},
			TokenDependencies{
				Codes:  failingCodeConsumer{},
				Issuer: failingTokenIssuer{},
			},
			UserinfoDependencies{},
			LogoutDependencies{},
			EnrollDependencies{},
			AdminDependencies{},
			PanicDependencies{},
		).Handler()
		response := tokenRequest(t, handler, validExchangeForm("anything"), "")

		require.Equal(t, http.StatusInternalServerError, response.Code)
		require.Contains(t, response.Body.String(), "internal server error")
	})

	t.Run("returns an internal error when token issuance fails", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		code := createCode(t, app, nil)
		handler := New(
			testPublicJWK(),
			referenceIssuer,
			testClients(),
			ui.Assets(),
			LoginDependencies{},
			AuthorizeDependencies{},
			TokenDependencies{
				Codes:  app.codes,
				Issuer: failingTokenIssuer{},
				Users:  testUsers,
			},
			UserinfoDependencies{},
			LogoutDependencies{},
			EnrollDependencies{},
			AdminDependencies{},
			PanicDependencies{},
		).Handler()
		response := tokenRequest(t, handler, validExchangeForm(code), "")

		require.Equal(t, http.StatusInternalServerError, response.Code)
		require.Contains(t, response.Body.String(), "internal server error")
	})
}

// failingClientAuthLimiter is a client-auth limiter whose checks always
// fail with an infrastructure error.
type failingClientAuthLimiter struct{}

func (failingClientAuthLimiter) Allow(context.Context, string, time.Time) (bool, error) {
	return false, errors.New("database unavailable")
}

func (failingClientAuthLimiter) RecordFailure(context.Context, string, time.Time) error {
	return nil
}

func (failingClientAuthLimiter) Reset(context.Context, string) error {
	return nil
}

// failingClientAuthRecorder is a client-auth limiter whose failure
// recording always fails with an infrastructure error.
type failingClientAuthRecorder struct{}

func (failingClientAuthRecorder) Allow(context.Context, string, time.Time) (bool, error) {
	return true, nil
}

func (failingClientAuthRecorder) RecordFailure(context.Context, string, time.Time) error {
	return errors.New("database unavailable")
}

func (failingClientAuthRecorder) Reset(context.Context, string) error {
	return nil
}

// failingCodeConsumer is a code consumer whose redemption always fails with
// an infrastructure error.
type failingCodeConsumer struct{}

func (failingCodeConsumer) ConsumeCode(
	context.Context,
	string,
	time.Time,
) (onetoken.Code, error) {
	return onetoken.Code{}, errors.New("database unavailable")
}

// failingTokenIssuer is a token issuer whose issuance always fails with an
// infrastructure error.
type failingTokenIssuer struct{}

func (failingTokenIssuer) IssueIDToken(context.Context, token.IDTokenParams) (string, error) {
	return "", errors.New("signing unavailable")
}

func (failingTokenIssuer) IssueAccessToken(
	context.Context,
	token.AccessTokenParams,
) (string, error) {
	return "", errors.New("signing unavailable")
}
