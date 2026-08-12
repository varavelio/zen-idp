package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"database/sql"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/varavelio/zen-idp/internal/admin"
	"github.com/varavelio/zen-idp/internal/audit"
	"github.com/varavelio/zen-idp/internal/config"
	"github.com/varavelio/zen-idp/internal/id"
	"github.com/varavelio/zen-idp/internal/jwt"
	"github.com/varavelio/zen-idp/internal/lock"
	"github.com/varavelio/zen-idp/internal/login"
	"github.com/varavelio/zen-idp/internal/onetoken"
	"github.com/varavelio/zen-idp/internal/ratelimit"
	"github.com/varavelio/zen-idp/internal/session"
	"github.com/varavelio/zen-idp/internal/statestore"
	"github.com/varavelio/zen-idp/internal/token"
	"github.com/varavelio/zen-idp/internal/totp"
	"github.com/varavelio/zen-idp/internal/ui"
	"github.com/varavelio/zen-idp/internal/userinfo"
)

// referenceRootSecret is the fixed normalized root secret anchored by the
// crypto derivation chain tests (bytes 0x01 through 0x20).
var referenceRootSecret = func() (secret [sha256.Size]byte) {
	for i := range secret {
		secret[i] = byte(i + 1)
	}
	return secret
}()

// testMaxAge is the session lifetime used by the login test server.
const testMaxAge = 72 * time.Hour

// testUsers declares one current, unexpired, unlocked user.
var testUsers = []config.User{{Subject: "alice"}}

// testApp bundles a fully wired test server with the real stores behind its
// login, authorization, and token dependencies.
type testApp struct {
	server   *Server
	db       *sql.DB
	sessions *session.Store
	codes    *onetoken.Store
	locks    *lock.Locks
}

// newTestApp builds a server with a real migrated SQLite state store and the
// real login service, one-use token store, and token issuer wired on top of
// it.
func newTestApp(t *testing.T, users []config.User) *testApp {
	t.Helper()
	db := newLoginTestDB(t)
	queries := statestore.New(db)
	limiter, err := ratelimit.New(queries, 5, 5*time.Minute)
	require.NoError(t, err)
	locks, err := lock.NewLocks(queries)
	require.NoError(t, err)
	store, err := session.NewStore(queries, id.NewIDGenerator(), referenceRootSecret, testMaxAge)
	require.NoError(t, err)
	codes, err := onetoken.NewStore(queries, id.NewIDGenerator(), referenceRootSecret)
	require.NoError(t, err)
	service, err := login.New(users, referenceRootSecret, limiter, locks, store)
	require.NoError(t, err)
	signer, err := jwt.NewSigner(referenceKey(), referenceKid())
	require.NoError(t, err)
	issuer, err := token.NewIssuer(signer, referenceIssuer, users, locks)
	require.NoError(t, err)
	verifier, err := jwt.NewVerifier(&referenceKey().PublicKey, referenceKid())
	require.NoError(t, err)
	userinfoService, err := userinfo.New(verifier, referenceIssuer, users, locks, store)
	require.NoError(t, err)

	adminLimiter, err := ratelimit.New(queries, adminTestMaxAttempts, adminTestWindow)
	require.NoError(t, err)
	recorder, err := audit.NewRecorder(queries, id.NewIDGenerator())
	require.NoError(t, err)
	adminService, err := admin.New(testAdminPasswordHash, adminLimiter, store, recorder)
	require.NoError(t, err)

	server := New(
		testPublicJWK(),
		referenceIssuer,
		testClients(),
		ui.Assets(),
		LoginDependencies{
			Service:       service,
			UI:            config.UI{Name: "Example Auth"},
			SecureCookies: true,
			SessionMaxAge: testMaxAge,
		},
		AuthorizeDependencies{
			Sessions: store,
			Codes:    codes,
		},
		TokenDependencies{
			Codes:  codes,
			Issuer: issuer,
		},
		UserinfoDependencies{
			Service: userinfoService,
		},
		LogoutDependencies{
			Sessions:      store,
			UI:            config.UI{Name: "Example Auth"},
			SecureCookies: true,
		},
		AdminDependencies{
			Service:       adminService,
			Sessions:      store,
			UI:            config.UI{Name: "Example Auth"},
			SecureCookies: true,
			SessionMaxAge: testMaxAge,
		},
	)
	return &testApp{server: server, db: db, sessions: store, codes: codes, locks: locks}
}

// newLoginTestDB opens and migrates a fresh SQLite state store.
func newLoginTestDB(t *testing.T) *sql.DB {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := statestore.Connect(ctx, path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	require.NoError(t, statestore.Migrate(ctx, db))
	return db
}

// loginQuery builds a valid pending authorization request for the public-app
// test client.
func loginQuery() string {
	return url.Values{
		"client_id":             {"public-app"},
		"redirect_uri":          {"https://app.example.com/callback"},
		"response_type":         {"code"},
		"scope":                 {"openid"},
		"state":                 {"xyz"},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
	}.Encode()
}

// totpCode computes the RFC 6238 six-digit code for secret at the given
// instant with an independent implementation (HMAC-SHA-1, 30-second step).
func totpCode(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	require.NoError(t, err)

	counter := make([]byte, 8)
	binary.BigEndian.PutUint64(counter, uint64(at.Unix()/30))
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(counter)
	digest := mac.Sum(nil)

	offset := digest[len(digest)-1] & 0x0f
	code := binary.BigEndian.Uint32(digest[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", code%1_000_000)
}

func TestLoginForm(t *testing.T) {
	t.Run("renders the login form for a valid pending request", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		response := httptest.NewRecorder()
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodGet,
			"/login?"+loginQuery(),
			nil,
		)
		app.server.Handler().ServeHTTP(response, request)

		require.Equal(t, http.StatusOK, response.Code)
		require.Equal(t, "text/html; charset=utf-8", response.Header().Get("Content-Type"))
		require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
		require.Contains(t, response.Body.String(), "Example Auth")
		require.Contains(t, response.Body.String(), "Login identifier")
		require.Contains(t, response.Body.String(), "One-time code")
		require.Contains(
			t,
			response.Body.String(),
			`form action="/login?`+strings.ReplaceAll(loginQuery(), "&", "&amp;")+`"`,
		)
	})

	t.Run("rejects requests without a pending authorization request", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		response := httptest.NewRecorder()
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodGet,
			"/login",
			nil,
		)
		app.server.Handler().ServeHTTP(response, request)

		require.Equal(t, http.StatusBadRequest, response.Code)
		require.Contains(t, response.Body.String(), "Invalid authorization request")
	})

	t.Run("rejects requests with an untrusted client", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		query := url.Values{
			"client_id":     {"unknown"},
			"redirect_uri":  {"https://app.example.com/callback"},
			"response_type": {"code"},
			"scope":         {"openid"},
		}.Encode()
		response := httptest.NewRecorder()
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodGet,
			"/login?"+query,
			nil,
		)
		app.server.Handler().ServeHTTP(response, request)

		require.Equal(t, http.StatusBadRequest, response.Code)
	})

	t.Run("rejects requests with an invalid pending request", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		query := url.Values{
			"client_id":     {"public-app"},
			"redirect_uri":  {"https://app.example.com/callback"},
			"response_type": {"token"},
			"scope":         {"openid"},
		}.Encode()
		response := httptest.NewRecorder()
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodGet,
			"/login?"+query,
			nil,
		)
		app.server.Handler().ServeHTTP(response, request)

		require.Equal(t, http.StatusBadRequest, response.Code)
	})
}

func TestProcessLogin(t *testing.T) {
	post := func(t *testing.T, server *Server, query, identifier, code string) *httptest.ResponseRecorder {
		t.Helper()
		form := url.Values{"identifier": {identifier}, "code": {code}}
		response := httptest.NewRecorder()
		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodPost,
			"/login?"+query,
			strings.NewReader(form.Encode()),
		)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.RemoteAddr = "192.0.2.10:54321"
		request.Header.Set("User-Agent", "test-agent")
		server.Handler().ServeHTTP(response, request)
		return response
	}

	codeFor := func(t *testing.T, sub string) string {
		t.Helper()
		secret, err := totp.DeriveSharedSecret(referenceRootSecret, sub, 0)
		require.NoError(t, err)
		return totpCode(t, secret, time.Now())
	}

	t.Run(
		"authenticates a valid identifier and code and issues the session cookie",
		func(t *testing.T) {
			app := newTestApp(t, testUsers)
			response := post(t, app.server, loginQuery(), "alice", codeFor(t, "alice"))

			require.Equal(t, http.StatusSeeOther, response.Code)
			require.Equal(t, "/authorize?"+loginQuery(), response.Header().Get("Location"))

			cookies := response.Result().Cookies()
			require.Len(t, cookies, 1)
			cookie := cookies[0]
			require.Equal(t, sessionCookieName, cookie.Name)
			require.True(t, cookie.HttpOnly)
			require.True(t, cookie.Secure)
			require.Equal(t, http.SameSiteLaxMode, cookie.SameSite)
			require.Equal(t, "/", cookie.Path)
			require.Equal(t, int(testMaxAge.Seconds()), cookie.MaxAge)

			sessions, err := app.sessions.Validate(context.Background(), cookie.Value, time.Now())
			require.NoError(t, err)
			require.Equal(t, "alice", sessions.Subject)
		},
	)

	t.Run("authenticates a user by its configured login identifier", func(t *testing.T) {
		users := []config.User{{Subject: "alice", Login: "alice@example.com"}}
		app := newTestApp(t, users)
		response := post(t, app.server, loginQuery(), "alice@example.com", codeFor(t, "alice"))

		require.Equal(t, http.StatusSeeOther, response.Code)
	})

	t.Run("marks the cookie secure only when configured", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		app.server.login.SecureCookies = false
		response := post(t, app.server, loginQuery(), "alice", codeFor(t, "alice"))

		cookies := response.Result().Cookies()
		require.Len(t, cookies, 1)
		require.False(t, cookies[0].Secure)
	})

	t.Run("re-renders the form with a generic failure for a wrong code", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		response := post(t, app.server, loginQuery(), "alice", "000000")

		require.Equal(t, http.StatusOK, response.Code)
		require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
		require.Contains(
			t,
			response.Body.String(),
			"Sign-in failed. Check your identifier and code.",
		)
		require.Empty(t, response.Result().Cookies())
	})

	t.Run("returns the same failure for an unknown identifier", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		response := post(t, app.server, loginQuery(), "mallory", "000000")

		require.Equal(t, http.StatusOK, response.Code)
		require.Contains(
			t,
			response.Body.String(),
			"Sign-in failed. Check your identifier and code.",
		)
	})

	t.Run("returns the same failure for a malformed code", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		response := post(t, app.server, loginQuery(), "alice", "not-a-code")

		require.Equal(t, http.StatusOK, response.Code)
		require.Contains(
			t,
			response.Body.String(),
			"Sign-in failed. Check your identifier and code.",
		)
	})

	t.Run("denies attempts once the rate limit is exhausted", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		for range 5 {
			response := post(t, app.server, loginQuery(), "alice", "000000")
			require.Equal(t, http.StatusOK, response.Code)
		}
		response := post(t, app.server, loginQuery(), "alice", codeFor(t, "alice"))

		require.Equal(t, http.StatusOK, response.Code)
		require.Contains(
			t,
			response.Body.String(),
			"Sign-in failed. Check your identifier and code.",
		)
		require.Empty(t, response.Result().Cookies())
	})

	t.Run("rejects submissions without a pending authorization request", func(t *testing.T) {
		app := newTestApp(t, testUsers)
		response := post(t, app.server, "", "alice", codeFor(t, "alice"))

		require.Equal(t, http.StatusBadRequest, response.Code)
		require.Contains(t, response.Body.String(), "Invalid authorization request")
	})
}
