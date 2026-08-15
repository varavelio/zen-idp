package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// robotsMetaTag is the exact crawler directive every rendered page must
// carry.
const robotsMetaTag = `<meta name="robots" content="noindex, nofollow">`

func TestRobotsTXT(t *testing.T) {
	app := newTestApp(t, testUsers)
	request := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"/robots.txt",
		nil,
	)
	response := httptest.NewRecorder()

	app.server.Handler().ServeHTTP(response, request)

	require.Equal(t, http.StatusOK, response.Code)
	require.Equal(t, "text/plain; charset=utf-8", response.Header().Get("Content-Type"))
	require.Equal(t, "User-agent: *\nDisallow: /\n", response.Body.String())
}

func TestPagesDeclareNoIndex(t *testing.T) {
	app := newTestApp(t, testUsers)
	for _, test := range []struct {
		path   string
		status int
	}{
		{path: "/admin", status: http.StatusOK},         // anonymous: the administrator sign-in form
		{path: "/enroll", status: http.StatusOK},        // anonymous: the enrollment form
		{path: "/login", status: http.StatusBadRequest}, // no pending request: the invalid-request page
		{path: "/logout", status: http.StatusOK},        // no session: the signed-out page
	} {
		t.Run(test.path, func(t *testing.T) {
			request := httptest.NewRequestWithContext(
				context.Background(),
				http.MethodGet,
				test.path,
				nil,
			)
			response := httptest.NewRecorder()

			app.server.Handler().ServeHTTP(response, request)

			require.Equal(t, test.status, response.Code)
			require.Contains(t, response.Body.String(), robotsMetaTag)
		})
	}
}
