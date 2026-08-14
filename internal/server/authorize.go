package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/varavelio/zen-idp/internal/config"
	"github.com/varavelio/zen-idp/internal/onetoken"
	"github.com/varavelio/zen-idp/internal/session"
	"github.com/varavelio/zen-idp/internal/ui"
)

// authorizeLoginPath is the login interaction that valid authorization
// requests are forwarded to.
const authorizeLoginPath = "/login"

// authorizationCodeLifetime is the absolute lifetime of an issued
// authorization code.
const authorizationCodeLifetime = 300 * time.Second

// SessionStore validates and revokes SSO session browser tokens, satisfied
// by session.Store. Validation authenticates the cookie presented with an
// authorization request; revocation removes the record of a session that
// can never be usable again.
type SessionStore interface {
	Validate(context.Context, string, time.Time) (session.Session, error)
	Revoke(context.Context, string) error
}

// CodeIssuer creates one-use OIDC authorization codes carrying every binding
// of an accepted authorization request, satisfied by onetoken.Store.
type CodeIssuer interface {
	CreateCode(context.Context, onetoken.CodeParams) (string, error)
}

// LockChecker reports whether a subject is currently gated by a panic or
// administrative lock, satisfied by lock.Locks.
type LockChecker interface {
	IsLocked(context.Context, string) (bool, error)
}

// AuthorizeDependencies carries the injected pieces of the authorization
// endpoint's session continuation.
type AuthorizeDependencies struct {
	// Sessions validates and revokes the SSO session cookie presented
	// with an authorization request.
	Sessions SessionStore
	// Codes creates the one-use authorization code that completes an
	// accepted request.
	Codes CodeIssuer
	// Users lists every configured user, the only subjects whose sessions
	// may continue an authorization request.
	Users []config.User
	// Locks gates session continuation on the subject's current lock
	// state.
	Locks LockChecker
}

// authorizeRequest is the parsed wire form of an OIDC authorization request.
type authorizeRequest struct {
	clientID            string
	redirectURI         string
	responseType        string
	responseMode        string
	scope               string
	state               string
	nonce               string
	prompt              string
	maxAge              string
	codeChallenge       string
	codeChallengeMethod string
	request             string
	requestURI          string
}

// authorize handles the OIDC authorization endpoint. It validates every wire
// parameter of the request and, when the request is valid, continues the
// flow: an active SSO session whose subject is still current in the
// configuration receives a fresh authorization code and a redirect to the
// registered redirect URI, and any other request is forwarded to the login
// interaction with its parameters intact. The prompt parameter shapes the
// flow: prompt=login always forces a fresh authentication, prompt=none never
// shows an interaction and fails with login_required without a usable
// session, and the consent and select_account prompts are skipped by design
// because Zen IdP has no consent or account-selection screens. Requests
// whose client or redirect URI is not trusted receive a generic error page
// instead of a redirect, because no safe target exists for them.
func (server *Server) authorize(w http.ResponseWriter, r *http.Request) error {
	request, err := server.parseAndValidateAuthorizeRequest(r)
	if err != nil {
		var authorizeErr *authorizeError
		if errors.As(err, &authorizeErr) {
			return redirectAuthorizeError(w, r, request, err)
		}
		return writeInvalidRequestPage(w)
	}

	if promptRequestsLogin(request.prompt) {
		http.Redirect(w, r, authorizeLoginPath+"?"+r.URL.RawQuery, http.StatusFound)
		return nil
	}

	current, ok, err := server.currentAuthorizeSession(r, time.Now())
	if err != nil {
		return err
	}
	if ok && server.sessionWithinMaxAge(current, request.maxAge) {
		return server.issueCodeAndRedirect(w, r, request, current)
	}
	if promptIsNone(request.prompt) {
		return redirectAuthorizeError(w, r, request, &authorizeError{
			code:        "login_required",
			description: "authentication is required",
		})
	}
	http.Redirect(w, r, authorizeLoginPath+"?"+r.URL.RawQuery, http.StatusFound)
	return nil
}

// sessionWithinMaxAge reports whether the validated session satisfies the
// request's maximum authentication age: without a max_age parameter every
// session qualifies, and with one the session must have authenticated within
// the allowed number of seconds at the current instant. An older session is
// sent to the login interaction for a fresh authentication.
func (server *Server) sessionWithinMaxAge(current session.Session, maxAge string) bool {
	if maxAge == "" {
		return true
	}
	seconds, err := strconv.ParseInt(maxAge, 10, 64)
	if err != nil {
		return false
	}
	age := int64(time.Since(current.CreatedAt) / time.Second)
	return age <= seconds
}

// promptRequestsLogin reports whether the prompt parameter requests a fresh
// authentication interaction.
func promptRequestsLogin(prompt string) bool {
	return slices.Contains(strings.Fields(prompt), "login")
}

// promptIsNone reports whether the prompt parameter requests no
// authentication or consent user interface at all.
func promptIsNone(prompt string) bool {
	return slices.Contains(strings.Fields(prompt), "none")
}

// currentAuthorizeSession authenticates the SSO session cookie presented
// with an authorization request and reports whether the session may
// continue the flow. The cookie must authenticate an active user-kind
// session whose subject is still declared, unexpired, unlocked, and at the
// subject's current TOTP revision at the given instant; any other state
// reports ok=false, which is not an error and sends the browser to the
// login interaction. A validated session that fails the current-state
// checks is revoked opportunistically, because those checks depend only on
// the current configuration and lock state and can never make the session
// usable again.
func (server *Server) currentAuthorizeSession(
	r *http.Request,
	now time.Time,
) (session.Session, bool, error) {
	cookie, err := r.Cookie(sessionCookieName)
	if err == nil {
		current, err := server.authorization.Sessions.Validate(r.Context(), cookie.Value, now)
		if err == nil {
			usable, err := server.usableSession(r.Context(), current, now)
			if err != nil {
				return session.Session{}, false, err
			}
			if usable {
				return current, true, nil
			}
			// The record can never become usable again; deletion is
			// opportunistic, so a failing delete is not an error.
			_ = server.authorization.Sessions.Revoke(r.Context(), cookie.Value)
			return session.Session{}, false, nil
		}
		switch {
		case errors.Is(err, session.ErrMalformedToken),
			errors.Is(err, session.ErrInvalidSession),
			errors.Is(err, session.ErrExpiredSession):
			// The cookie does not authenticate an active session; the
			// browser continues to the login interaction.
		default:
			return session.Session{}, false, fmt.Errorf("validate session cookie: %w", err)
		}
	}
	return session.Session{}, false, nil
}

// usableSession reports whether the validated session may continue an
// authorization request at the given instant: its subject must still be
// declared in the active configuration, unexpired, unlocked, and
// authenticated at the subject's current TOTP revision.
func (server *Server) usableSession(
	ctx context.Context,
	current session.Session,
	now time.Time,
) (bool, error) {
	user, ok := server.resolveAuthorizeUser(current.Subject)
	if !ok {
		return false, nil
	}
	if !user.ExpiresAt.IsZero() && !now.Before(user.ExpiresAt) {
		return false, nil
	}
	if user.TOTPRevision != current.TOTPRev {
		return false, nil
	}
	locked, err := server.authorization.Locks.IsLocked(ctx, current.Subject)
	if err != nil {
		return false, fmt.Errorf("check session subject locks: %w", err)
	}
	if locked {
		return false, nil
	}
	return true, nil
}

// resolveAuthorizeUser returns the configured user declared with exactly
// the given subject. Configuration validation guarantees that subjects are
// unique, so the first match is the only match.
func (server *Server) resolveAuthorizeUser(subject string) (config.User, bool) {
	for _, user := range server.authorization.Users {
		if user.Subject == subject {
			return user, true
		}
	}
	return config.User{}, false
}

// issueCodeAndRedirect issues a fresh authorization code carrying every
// binding of the accepted request plus the authenticated session's subject
// and TOTP revision, and redirects the browser to the client's registered
// redirect URI with the code and the request state. The response is marked
// no-store because its target URL carries a redeemable one-use credential.
func (server *Server) issueCodeAndRedirect(
	w http.ResponseWriter,
	r *http.Request,
	request authorizeRequest,
	sessions session.Session,
) error {
	now := time.Now()
	code, err := server.authorization.Codes.CreateCode(r.Context(), onetoken.CodeParams{
		Subject:       sessions.Subject,
		TOTPRev:       sessions.TOTPRev,
		ClientID:      request.clientID,
		RedirectURI:   request.redirectURI,
		Scope:         request.scope,
		Nonce:         request.nonce,
		AuthTime:      sessions.CreatedAt,
		PKCEChallenge: request.codeChallenge,
		PKCEMethod:    request.codeChallengeMethod,
		ExpiresAt:     now.Add(authorizationCodeLifetime),
		Now:           now,
	})
	if err != nil {
		return fmt.Errorf("issue authorization code: %w", err)
	}

	target, err := url.Parse(request.redirectURI)
	if err != nil {
		return fmt.Errorf("parse redirect URI: %w", err)
	}
	query := target.Query()
	query.Set("code", code)
	if request.state != "" {
		query.Set("state", request.state)
	}
	target.RawQuery = query.Encode()
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, target.String(), http.StatusFound)
	return nil
}

// errUntrustedRequest marks an authorization request whose client or redirect
// URI is not declared, leaving no safe target for an error redirect.
var errUntrustedRequest = errors.New("untrusted authorization request")

// parseAndValidateAuthorizeRequest parses and fully validates the pending OIDC
// authorization request carried by r against the declared clients. The
// returned request is populated whenever the query itself parsed, so callers
// can still report validation failures to the request's redirect URI.
func (server *Server) parseAndValidateAuthorizeRequest(r *http.Request) (authorizeRequest, error) {
	request, err := parseAuthorizeRequest(r.URL.Query())
	if err != nil {
		return authorizeRequest{}, err
	}
	client, ok := findClient(server.clients, request.clientID)
	if !ok || !allowsRedirectURI(client, request.redirectURI) {
		return request, errUntrustedRequest
	}
	if err := validateAuthorizeRequest(request, client); err != nil {
		return request, err
	}
	return request, nil
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
		{name: "response_mode", target: &request.responseMode},
		{name: "scope", target: &request.scope},
		{name: "state", target: &request.state},
		{name: "nonce", target: &request.nonce},
		{name: "prompt", target: &request.prompt},
		{name: "max_age", target: &request.maxAge},
		{name: "code_challenge", target: &request.codeChallenge},
		{name: "code_challenge_method", target: &request.codeChallengeMethod},
		{name: "request", target: &request.request},
		{name: "request_uri", target: &request.requestURI},
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
// exactly "code", the response mode must be the default query mode, the
// scope must contain "openid", the prompt value none cannot be combined
// with other prompt values, JAR parameters are not supported, and PKCE S256
// is mandatory for public clients and validated whenever supplied. The
// optional state parameter is echoed back by error responses when present.
func validateAuthorizeRequest(request authorizeRequest, client config.Client) error {
	if request.responseType != "code" {
		return &authorizeError{
			code:        "unsupported_response_type",
			description: "only response_type=code is supported",
		}
	}
	if request.responseMode != "" && request.responseMode != "query" {
		return &authorizeError{
			code:        "invalid_request",
			description: "only the query response mode is supported",
		}
	}
	if promptIsNone(request.prompt) {
		for value := range strings.FieldsSeq(request.prompt) {
			if value != "none" {
				return &authorizeError{
					code:        "invalid_request",
					description: "the prompt value none cannot be combined with other values",
				}
			}
		}
	}
	if request.maxAge != "" {
		seconds, err := strconv.ParseInt(request.maxAge, 10, 64)
		if err != nil || seconds < 0 {
			return &authorizeError{
				code:        "invalid_request",
				description: "max_age must be a non-negative integer number of seconds",
			}
		}
	}
	if request.request != "" {
		return &authorizeError{
			code:        "request_not_supported",
			description: "JWT-secured authorization requests are not supported",
		}
	}
	if request.requestURI != "" {
		return &authorizeError{
			code:        "request_uri_not_supported",
			description: "request_uri authorization requests are not supported",
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
	if !validPKCEValue(request.codeChallenge) {
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

// validPKCEValue reports whether value is a syntactically valid PKCE code
// challenge or verifier: 43 to 128 characters from the unreserved URL
// alphabet.
func validPKCEValue(value string) bool {
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

// writeInvalidRequestPage writes the generic error page shown when a request
// cannot be redirected safely because its client or redirect URI is not
// trusted.
func writeInvalidRequestPage(w http.ResponseWriter) error {
	html, err := ui.InvalidRequestPage().RenderString()
	if err != nil {
		return fmt.Errorf("render invalid request page: %w", err)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusBadRequest)
	_, err = io.WriteString(w, html)
	return err
}
