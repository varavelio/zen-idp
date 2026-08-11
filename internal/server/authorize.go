package server

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/varavelio/zen-idp/internal/config"
)

// authorizeLoginPath is the login interaction that valid authorization
// requests are forwarded to.
const authorizeLoginPath = "/login"

// authorizeRequest is the parsed wire form of an OIDC authorization request.
type authorizeRequest struct {
	clientID            string
	redirectURI         string
	responseType        string
	scope               string
	state               string
	nonce               string
	codeChallenge       string
	codeChallengeMethod string
}

// authorize handles the OIDC authorization endpoint. It validates every wire
// parameter of the request and, when the request is valid, forwards it to
// the login interaction with its parameters intact. Requests whose client or
// redirect URI is not trusted receive a generic error page instead of a
// redirect, because no safe target exists for them.
func (server *Server) authorize(w http.ResponseWriter, r *http.Request) error {
	request, err := parseAuthorizeRequest(r.URL.Query())
	if err != nil {
		return writeInvalidRequestPage(w)
	}
	client, ok := findClient(server.clients, request.clientID)
	if !ok || !allowsRedirectURI(client, request.redirectURI) {
		return writeInvalidRequestPage(w)
	}
	if err := validateAuthorizeRequest(request, client); err != nil {
		return redirectAuthorizeError(w, r, request, err)
	}
	http.Redirect(w, r, authorizeLoginPath+"?"+r.URL.RawQuery, http.StatusFound)
	return nil
}

// parseAuthorizeRequest extracts the authorization request parameters from
// the query string. Any parameter supplied more than once fails the parse
// because OIDC requires rejecting duplicated parameters.
func parseAuthorizeRequest(values url.Values) (authorizeRequest, error) {
	var request authorizeRequest
	parameters := []struct {
		name   string
		target *string
	}{
		{name: "client_id", target: &request.clientID},
		{name: "redirect_uri", target: &request.redirectURI},
		{name: "response_type", target: &request.responseType},
		{name: "scope", target: &request.scope},
		{name: "state", target: &request.state},
		{name: "nonce", target: &request.nonce},
		{name: "code_challenge", target: &request.codeChallenge},
		{name: "code_challenge_method", target: &request.codeChallengeMethod},
	}
	for _, parameter := range parameters {
		entries := values[parameter.name]
		if len(entries) > 1 {
			return authorizeRequest{}, fmt.Errorf(
				"authorization request parameter %q is supplied more than once",
				parameter.name,
			)
		}
		if len(entries) == 1 {
			*parameter.target = entries[0]
		}
	}
	return request, nil
}

// findClient returns the declared client with the given identifier.
func findClient(clients []config.Client, clientID string) (config.Client, bool) {
	for _, client := range clients {
		if client.ID == clientID {
			return client, true
		}
	}
	return config.Client{}, false
}

// allowsRedirectURI reports whether uri is one of the client's registered
// redirect URIs, matched exactly.
func allowsRedirectURI(client config.Client, uri string) bool {
	return slices.Contains(client.RedirectURIs, uri)
}

// authorizeError is an OIDC authorization error that is reported to the
// client through a redirect to its registered redirect URI.
type authorizeError struct {
	code        string
	description string
}

// Error returns the OIDC error code and description.
func (err *authorizeError) Error() string {
	return err.code + ": " + err.description
}

// validateAuthorizeRequest enforces the OIDC wire contract on a request
// whose client and redirect URI are already trusted: response_type must be
// exactly "code", the scope must contain "openid", and PKCE S256 is
// mandatory for public clients and validated whenever supplied. The optional
// state parameter is echoed back by error responses when present.
func validateAuthorizeRequest(request authorizeRequest, client config.Client) error {
	if request.responseType != "code" {
		return &authorizeError{
			code:        "unsupported_response_type",
			description: "only response_type=code is supported",
		}
	}
	if !scopeContainsOpenID(request.scope) {
		return &authorizeError{
			code:        "invalid_scope",
			description: "the openid scope is required",
		}
	}
	if request.codeChallenge == "" {
		if request.codeChallengeMethod != "" {
			return &authorizeError{
				code:        "invalid_request",
				description: "a code challenge is required when a method is supplied",
			}
		}
		if client.SecretHash == "" {
			return &authorizeError{
				code:        "invalid_request",
				description: "public clients must use the S256 PKCE method",
			}
		}
		return nil
	}
	if request.codeChallengeMethod != "S256" {
		return &authorizeError{
			code:        "invalid_request",
			description: "only the S256 PKCE method is supported",
		}
	}
	if !validCodeChallenge(request.codeChallenge) {
		return &authorizeError{
			code:        "invalid_request",
			description: "the code challenge is malformed",
		}
	}
	return nil
}

// scopeContainsOpenID reports whether scope lists "openid" as one of its
// space-separated tokens.
func scopeContainsOpenID(scope string) bool {
	return slices.Contains(strings.Fields(scope), "openid")
}

// validCodeChallenge reports whether value is a syntactically valid PKCE
// code challenge: 43 to 128 characters from the unreserved URL alphabet.
func validCodeChallenge(value string) bool {
	if len(value) < 43 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if !isUnreserved(character) {
			return false
		}
	}
	return true
}

// isUnreserved reports whether character belongs to the RFC 3986 unreserved
// set used by the PKCE base64url alphabet.
func isUnreserved(character rune) bool {
	switch {
	case character >= 'a' && character <= 'z':
		return true
	case character >= 'A' && character <= 'Z':
		return true
	case character >= '0' && character <= '9':
		return true
	}
	return character == '-' || character == '.' || character == '_' || character == '~'
}

// redirectAuthorizeError sends err to the request's redirect URI as an OIDC
// error response, echoing state when the request carried one.
func redirectAuthorizeError(
	w http.ResponseWriter,
	r *http.Request,
	request authorizeRequest,
	err error,
) error {
	var authorizeErr *authorizeError
	if !errors.As(err, &authorizeErr) {
		return err
	}
	target, err := url.Parse(request.redirectURI)
	if err != nil {
		return err
	}
	query := target.Query()
	query.Set("error", authorizeErr.code)
	query.Set("error_description", authorizeErr.description)
	if request.state != "" {
		query.Set("state", request.state)
	}
	target.RawQuery = query.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
	return nil
}

// writeInvalidRequestPage writes the generic error page shown when an
// authorization request cannot be redirected safely because its client or
// redirect URI is not trusted.
func writeInvalidRequestPage(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusBadRequest)
	_, err := io.WriteString(w, invalidRequestPageHTML)
	return err
}

const invalidRequestPageHTML = `
<!DOCTYPE html>
<html lang="en">
	<head>
		<meta charset="utf-8">
		<title>Zen IdP</title>
	</head>
	<body>
		<h1>Invalid authorization request</h1>
		<p>The authorization request could not be processed.</p>
	</body>
</html>
`
