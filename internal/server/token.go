package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/varavelio/zen-idp/internal/config"
	"github.com/varavelio/zen-idp/internal/crypto"
	"github.com/varavelio/zen-idp/internal/onetoken"
	"github.com/varavelio/zen-idp/internal/token"
)

// tokenGrantType is the only grant type the token endpoint accepts.
const tokenGrantType = "authorization_code"

// bearerTokenType is the token type of every successful token response.
const bearerTokenType = "Bearer"

// maxTokenBodyBytes bounds the token request form body; a legitimate token
// request carries only a handful of short parameters.
const maxTokenBodyBytes = 1 << 20

// CodeConsumer redeems the one-use authorization code of a token request,
// satisfied by onetoken.Store.
type CodeConsumer interface {
	ConsumeCode(context.Context, string, time.Time) (onetoken.Code, error)
}

// TokenIssuer mints the ID and access tokens of a token response, satisfied
// by token.Issuer.
type TokenIssuer interface {
	IssueIDToken(context.Context, token.IDTokenParams) (string, error)
	IssueAccessToken(context.Context, token.AccessTokenParams) (string, error)
}

// TokenDependencies carries the injected pieces of the token endpoint.
type TokenDependencies struct {
	// Codes redeems the one-use authorization code of the request.
	Codes CodeConsumer
	// Issuer mints the ID and access tokens of the response.
	Issuer TokenIssuer
	// RequireClientSecretTLS demands HTTPS for client-secret
	// authentication; production deployments must set it.
	RequireClientSecretTLS bool
}

// token handles the OIDC token endpoint. It authenticates the client,
// redeems the one-use authorization code with every binding validated,
// verifies the PKCE verifier when the code is PKCE-bound, and issues the ID
// and access tokens of the token response.
func (server *Server) token(w http.ResponseWriter, r *http.Request) error {
	if r.URL.RawQuery != "" {
		return writeTokenError(
			w,
			http.StatusBadRequest,
			"invalid_request",
			"token parameters must be sent in the request body",
		)
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxTokenBodyBytes)
	if err := r.ParseForm(); err != nil {
		return writeTokenError(
			w,
			http.StatusBadRequest,
			"invalid_request",
			"the request body is not valid form data",
		)
	}

	switch grantType := r.FormValue("grant_type"); grantType {
	case "":
		return writeTokenError(
			w,
			http.StatusBadRequest,
			"invalid_request",
			"the grant_type parameter is required",
		)
	case tokenGrantType:
	default:
		return writeTokenError(
			w,
			http.StatusBadRequest,
			"unsupported_grant_type",
			"only the authorization_code grant is supported",
		)
	}

	client, err := server.authenticateTokenClient(r)
	if err != nil {
		if tokenErr, ok := errors.AsType[*tokenError](err); ok {
			return writeTokenError(w, tokenErr.status, tokenErr.code, tokenErr.description)
		}
		return err
	}

	codeValue := r.FormValue("code")
	if codeValue == "" {
		return writeTokenError(
			w,
			http.StatusBadRequest,
			"invalid_request",
			"the code parameter is required",
		)
	}
	redirectURI := r.FormValue("redirect_uri")
	if redirectURI == "" {
		return writeTokenError(
			w,
			http.StatusBadRequest,
			"invalid_request",
			"the redirect_uri parameter is required",
		)
	}

	code, err := server.tokens.Codes.ConsumeCode(r.Context(), codeValue, time.Now())
	switch {
	case errors.Is(err, onetoken.ErrMalformedToken),
		errors.Is(err, onetoken.ErrInvalidToken),
		errors.Is(err, onetoken.ErrExpiredToken):
		return writeTokenError(
			w,
			http.StatusBadRequest,
			"invalid_grant",
			"the authorization code is invalid or expired",
		)
	case err != nil:
		return fmt.Errorf("consume authorization code: %w", err)
	}
	if code.ClientID != client.ID {
		return writeTokenError(
			w,
			http.StatusBadRequest,
			"invalid_grant",
			"the authorization code was issued to another client",
		)
	}
	if code.RedirectURI != redirectURI {
		return writeTokenError(
			w,
			http.StatusBadRequest,
			"invalid_grant",
			"the redirect URI does not match the authorization request",
		)
	}
	if code.PKCEChallenge != "" &&
		!verifyPKCEVerifier(code.PKCEChallenge, r.FormValue("code_verifier")) {
		return writeTokenError(
			w,
			http.StatusBadRequest,
			"invalid_grant",
			"the PKCE verifier does not match the code challenge",
		)
	}

	now := time.Now()
	idToken, err := server.tokens.Issuer.IssueIDToken(r.Context(), token.IDTokenParams{
		Subject:  code.Subject,
		ClientID: client.ID,
		Nonce:    code.Nonce,
		Now:      now,
	})
	if errors.Is(err, token.ErrDenied) {
		return writeTokenError(
			w,
			http.StatusBadRequest,
			"invalid_grant",
			"the authorization code can no longer be redeemed",
		)
	}
	if err != nil {
		return fmt.Errorf("issue id token: %w", err)
	}
	accessToken, err := server.tokens.Issuer.IssueAccessToken(r.Context(), token.AccessTokenParams{
		Subject: code.Subject,
		Now:     now,
	})
	if errors.Is(err, token.ErrDenied) {
		return writeTokenError(
			w,
			http.StatusBadRequest,
			"invalid_grant",
			"the authorization code can no longer be redeemed",
		)
	}
	if err != nil {
		return fmt.Errorf("issue access token: %w", err)
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if err := json.NewEncoder(w).Encode(tokenResponse{
		AccessToken: accessToken,
		TokenType:   bearerTokenType,
		ExpiresIn:   int64(token.Lifetime.Seconds()),
		IDToken:     idToken,
		Scope:       code.Scope,
	}); err != nil {
		return fmt.Errorf("write token response: %w", err)
	}
	return nil
}

// authenticateTokenClient identifies the client of a token request and
// verifies its credentials. Confidential clients must authenticate with
// client_secret_basic over HTTPS in production; public clients must identify
// themselves with the client_id parameter and must not present a secret.
func (server *Server) authenticateTokenClient(r *http.Request) (config.Client, error) {
	clientID, clientSecret, presented, err := parseClientCredentials(r)
	if err != nil {
		return config.Client{}, err
	}
	client, ok := findClient(server.clients, clientID)
	if !ok {
		return config.Client{}, clientError("the client is not registered")
	}
	if client.SecretHash == "" {
		if presented {
			return config.Client{}, clientError(
				"public clients must not authenticate with a client secret",
			)
		}
		return client, nil
	}
	if !presented {
		return config.Client{}, clientError(
			"confidential clients must authenticate with client_secret_basic",
		)
	}
	if server.tokens.RequireClientSecretTLS && r.TLS == nil {
		return config.Client{}, clientError("client secrets are only accepted over HTTPS")
	}
	match, err := crypto.VerifyCredential(clientSecret, client.SecretHash)
	if err != nil {
		return config.Client{}, fmt.Errorf("verify client secret: %w", err)
	}
	if !match {
		return config.Client{}, clientError("the client credentials are invalid")
	}
	return client, nil
}

// parseClientCredentials extracts the client identifier and optional secret
// from a token request: the client_id form parameter for public clients, or
// the HTTP Basic authorization header carrying the client_id and
// client_secret pair for confidential clients.
func parseClientCredentials(
	r *http.Request,
) (clientID, clientSecret string, presented bool, err error) {
	authorization := r.Header.Get("Authorization")
	if authorization == "" {
		return r.FormValue("client_id"), "", false, nil
	}
	const basicScheme = "Basic "
	if !strings.HasPrefix(authorization, basicScheme) {
		return "", "", false, clientError("unsupported client authentication method")
	}
	decoded, err := base64.StdEncoding.DecodeString(
		strings.TrimSpace(authorization[len(basicScheme):]),
	)
	if err != nil {
		return "", "", false, clientError("malformed client credentials")
	}
	clientID, clientSecret, ok := strings.Cut(string(decoded), ":")
	if !ok || clientID == "" {
		return "", "", false, clientError("malformed client credentials")
	}
	return clientID, clientSecret, true, nil
}

// verifyPKCEVerifier reports whether verifier is a valid PKCE S256 verifier
// whose SHA-256 digest matches the code's challenge in constant time.
func verifyPKCEVerifier(challenge, verifier string) bool {
	if !validPKCEValue(verifier) {
		return false
	}
	digest := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(digest[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}

// tokenResponse is the JSON body of a successful token request.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	IDToken     string `json:"id_token"`
	Scope       string `json:"scope"`
}

// tokenErrorResponse is the JSON error body of a failed token request.
type tokenErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// tokenError is a protocol error reported to the client as a JSON error
// response carrying the given HTTP status.
type tokenError struct {
	status      int
	code        string
	description string
}

// Error returns the OIDC error code and description.
func (err *tokenError) Error() string {
	return err.code + ": " + err.description
}

// clientError builds an invalid_client token error.
func clientError(description string) *tokenError {
	return &tokenError{
		status:      http.StatusUnauthorized,
		code:        "invalid_client",
		description: description,
	}
}

// writeTokenError writes the JSON error response of a failed token request
// with no-store semantics and a Basic authentication challenge on 401
// responses.
func writeTokenError(w http.ResponseWriter, status int, code, description string) error {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Basic realm="zen-idp"`)
	}
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(tokenErrorResponse{
		Error:            code,
		ErrorDescription: description,
	})
}
