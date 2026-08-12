package csrf

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// testCookieName is the cookie name used by every test guard.
const testCookieName = "test_csrf"

// base64urlAlphabet is the unpadded RFC 4648 URL-safe alphabet that every
// token character must belong to.
const base64urlAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// tokenRequest returns a GET request without any cookie.
func tokenRequest() *http.Request {
	return httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
}

// verifyRequest returns a POST request carrying the given cookie token and
// form field token; an empty token omits that part of the request.
func verifyRequest(cookieToken, fieldToken string) *http.Request {
	form := url.Values{}
	if fieldToken != "" {
		form.Set(FieldName, fieldToken)
	}
	request := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		"/submit",
		strings.NewReader(form.Encode()),
	)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookieToken != "" {
		request.AddCookie(&http.Cookie{Name: testCookieName, Value: cookieToken})
	}
	return request
}

func TestNewGuard(t *testing.T) {
	t.Run("rejects an empty cookie name", func(t *testing.T) {
		guard, err := NewGuard("", false)
		require.Nil(t, guard)
		require.Error(t, err)
	})

	t.Run("accepts a valid cookie name", func(t *testing.T) {
		guard, err := NewGuard(testCookieName, false)
		require.NoError(t, err)
		require.NotNil(t, guard)
	})
}

func TestToken(t *testing.T) {
	t.Run("issues a token and its cookie on the first visit", func(t *testing.T) {
		guard, err := NewGuard(testCookieName, false)
		require.NoError(t, err)
		response := httptest.NewRecorder()

		token, err := guard.Token(response, tokenRequest())

		require.NoError(t, err)
		require.Len(t, token, 43)
		for _, char := range token {
			require.Contains(t, base64urlAlphabet, string(char))
		}

		cookies := response.Result().Cookies()
		require.Len(t, cookies, 1)
		cookie := cookies[0]
		require.Equal(t, testCookieName, cookie.Name)
		require.Equal(t, token, cookie.Value)
		require.Equal(t, "/", cookie.Path)
		require.True(t, cookie.HttpOnly)
		require.False(t, cookie.Secure)
		require.Equal(t, http.SameSiteLaxMode, cookie.SameSite)
		require.Zero(t, cookie.MaxAge)
	})

	t.Run("marks the cookie Secure when configured", func(t *testing.T) {
		guard, err := NewGuard(testCookieName, true)
		require.NoError(t, err)
		response := httptest.NewRecorder()

		_, err = guard.Token(response, tokenRequest())

		require.NoError(t, err)
		require.True(t, response.Result().Cookies()[0].Secure)
	})

	t.Run("returns the existing token for a returning browser", func(t *testing.T) {
		guard, err := NewGuard(testCookieName, false)
		require.NoError(t, err)
		first := httptest.NewRecorder()
		issued, err := guard.Token(first, tokenRequest())
		require.NoError(t, err)

		request := tokenRequest()
		request.AddCookie(first.Result().Cookies()[0])
		second := httptest.NewRecorder()
		returned, err := guard.Token(second, request)

		require.NoError(t, err)
		require.Equal(t, issued, returned)
		require.Empty(t, second.Result().Cookies())
	})

	t.Run("replaces a malformed cookie with a fresh token", func(t *testing.T) {
		guard, err := NewGuard(testCookieName, false)
		require.NoError(t, err)
		request := tokenRequest()
		request.AddCookie(&http.Cookie{Name: testCookieName, Value: "garbage"})
		response := httptest.NewRecorder()

		token, err := guard.Token(response, request)

		require.NoError(t, err)
		require.NotEqual(t, "garbage", token)
		require.Len(t, response.Result().Cookies(), 1)
		require.Equal(t, token, response.Result().Cookies()[0].Value)
	})

	t.Run("issues a distinct token for every new browser", func(t *testing.T) {
		guard, err := NewGuard(testCookieName, false)
		require.NoError(t, err)

		first, err := guard.Token(httptest.NewRecorder(), tokenRequest())
		require.NoError(t, err)
		second, err := guard.Token(httptest.NewRecorder(), tokenRequest())

		require.NoError(t, err)
		require.NotEqual(t, first, second)
	})
}

func TestVerify(t *testing.T) {
	// issuedToken returns a token as it would be issued to a fresh browser.
	issuedToken := func(t *testing.T) string {
		t.Helper()
		guard, err := NewGuard(testCookieName, false)
		require.NoError(t, err)
		token, err := guard.Token(httptest.NewRecorder(), tokenRequest())
		require.NoError(t, err)
		return token
	}

	t.Run("accepts a matching cookie and form field", func(t *testing.T) {
		guard, err := NewGuard(testCookieName, false)
		require.NoError(t, err)
		token := issuedToken(t)

		err = guard.Verify(verifyRequest(token, token))

		require.NoError(t, err)
	})

	t.Run("rejects a missing cookie", func(t *testing.T) {
		guard, err := NewGuard(testCookieName, false)
		require.NoError(t, err)
		token := issuedToken(t)

		err = guard.Verify(verifyRequest("", token))

		require.ErrorIs(t, err, ErrInvalidToken)
	})

	t.Run("rejects a missing form field", func(t *testing.T) {
		guard, err := NewGuard(testCookieName, false)
		require.NoError(t, err)
		token := issuedToken(t)

		err = guard.Verify(verifyRequest(token, ""))

		require.ErrorIs(t, err, ErrInvalidToken)
	})

	t.Run("rejects mismatched values", func(t *testing.T) {
		guard, err := NewGuard(testCookieName, false)
		require.NoError(t, err)
		cookieToken := issuedToken(t)
		fieldToken := issuedToken(t)
		require.NotEqual(t, cookieToken, fieldToken)

		err = guard.Verify(verifyRequest(cookieToken, fieldToken))

		require.ErrorIs(t, err, ErrInvalidToken)
	})

	t.Run("rejects a malformed cookie value", func(t *testing.T) {
		guard, err := NewGuard(testCookieName, false)
		require.NoError(t, err)
		token := issuedToken(t)

		err = guard.Verify(verifyRequest("garbage", token))

		require.ErrorIs(t, err, ErrInvalidToken)
	})

	t.Run("rejects a malformed form field", func(t *testing.T) {
		guard, err := NewGuard(testCookieName, false)
		require.NoError(t, err)
		token := issuedToken(t)

		err = guard.Verify(verifyRequest(token, "garbage"))

		require.ErrorIs(t, err, ErrInvalidToken)
	})

	t.Run("rejects a well-formed token of the wrong length", func(t *testing.T) {
		guard, err := NewGuard(testCookieName, false)
		require.NoError(t, err)
		token := issuedToken(t)
		short := token[:22]

		err = guard.Verify(verifyRequest(short, short))

		require.ErrorIs(t, err, ErrInvalidToken)
	})

	t.Run("ignores tokens in query parameters", func(t *testing.T) {
		guard, err := NewGuard(testCookieName, false)
		require.NoError(t, err)
		token := issuedToken(t)

		request := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodPost,
			"/submit?"+FieldName+"="+token,
			strings.NewReader(""),
		)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.AddCookie(&http.Cookie{Name: testCookieName, Value: token})

		err = guard.Verify(request)

		require.ErrorIs(t, err, ErrInvalidToken)
	})
}
