//go:build e2e

package harness

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
)

// Browser is an HTTP client with a browser-like cookie jar that never follows
// redirects, so tests can inspect every redirect target and cookie decision.
type Browser struct {
	http   *http.Client
	jar    *cookiejar.Jar
	origin *url.URL
}

// Get issues a GET request against the given path of the harness origin.
func (b *Browser) Get(t *testing.T, path string) *Response {
	t.Helper()
	return b.do(t, http.MethodGet, path, nil, nil)
}

// GetAuth issues a GET request carrying the given Authorization header
// value.
func (b *Browser) GetAuth(t *testing.T, path, authorization string) *Response {
	t.Helper()
	return b.do(t, http.MethodGet, path, nil, map[string]string{
		"Authorization": authorization,
	})
}

// PostForm issues a POST request with the given form values.
func (b *Browser) PostForm(t *testing.T, path string, form url.Values) *Response {
	t.Helper()
	return b.do(t, http.MethodPost, path, strings.NewReader(form.Encode()), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	})
}

// PostFormAuth issues a POST request with the given form values and
// Authorization header value.
func (b *Browser) PostFormAuth(
	t *testing.T,
	path string,
	form url.Values,
	authorization string,
) *Response {
	t.Helper()
	return b.do(t, http.MethodPost, path, strings.NewReader(form.Encode()), map[string]string{
		"Content-Type":  "application/x-www-form-urlencoded",
		"Authorization": authorization,
	})
}

// PostRaw issues a POST request with a raw form-encoded body.
func (b *Browser) PostRaw(t *testing.T, path string, body []byte) *Response {
	t.Helper()
	return b.do(t, http.MethodPost, path, bytes.NewReader(body), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	})
}

// Cookie returns the value of the named cookie held by this browser's jar, or
// an empty string when the jar holds no such cookie for the harness origin.
func (b *Browser) Cookie(name string) string {
	for _, cookie := range b.jar.Cookies(b.origin) {
		if cookie.Name == name {
			return cookie.Value
		}
	}
	return ""
}

// do issues one request and reads its complete response.
func (b *Browser) do(
	t *testing.T,
	method, path string,
	body io.Reader,
	headers map[string]string,
) *Response {
	t.Helper()
	request, err := http.NewRequestWithContext(
		context.Background(),
		method,
		b.origin.String()+path,
		body,
	)
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response, err := b.http.Do(request)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = response.Body.Close() }()
	contents, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read %s %s response: %v", method, path, err)
	}
	return &Response{
		Status: response.StatusCode,
		Header: response.Header,
		Body:   contents,
	}
}

// Response is one complete HTTP response of a harness client.
type Response struct {
	// Status is the HTTP status code.
	Status int
	// Header holds the response headers.
	Header http.Header
	// Body holds the complete response body.
	Body []byte
}

// RequireStatus fails the test unless the response carries the given status
// code.
func (r *Response) RequireStatus(t *testing.T, want int) *Response {
	t.Helper()
	if r.Status != want {
		t.Fatalf("status = %d, want %d (body: %s)", r.Status, want, r.Body)
	}
	return r
}

// Location returns the parsed redirect target of the response, failing the
// test when the response carries no Location header.
func (r *Response) Location(t *testing.T) *url.URL {
	t.Helper()
	target := r.Header.Get("Location")
	if target == "" {
		t.Fatalf("response carries no Location header (status %d)", r.Status)
	}
	parsed, err := url.Parse(target)
	if err != nil {
		t.Fatalf("parse Location %q: %v", target, err)
	}
	return parsed
}

// JSON decodes the response body as JSON into v.
func (r *Response) JSON(t *testing.T, v any) *Response {
	t.Helper()
	if err := json.Unmarshal(r.Body, v); err != nil {
		t.Fatalf("decode JSON response: %v (body: %s)", err, r.Body)
	}
	return r
}

// Contains fails the test unless the response body contains the given
// fragment.
func (r *Response) Contains(t *testing.T, fragment string) *Response {
	t.Helper()
	if !bytes.Contains(r.Body, []byte(fragment)) {
		t.Fatalf("response body does not contain %q (body: %s)", fragment, r.Body)
	}
	return r
}

// NotContains fails the test unless the response body omits the given
// fragment.
func (r *Response) NotContains(t *testing.T, fragment string) *Response {
	t.Helper()
	if bytes.Contains(r.Body, []byte(fragment)) {
		t.Fatalf("response body contains %q (body: %s)", fragment, r.Body)
	}
	return r
}

// SetCookie returns the raw Set-Cookie header of the response, or an empty
// string when the response sets no cookie.
func (r *Response) SetCookie() string {
	return r.Header.Get("Set-Cookie")
}
