package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/varavelio/zen-idp/internal/userinfo"
)

// bearerScheme is the only HTTP authorization scheme the /userinfo endpoint
// accepts.
const bearerScheme = "Bearer "

// UserinfoService resolves a bearer access token into the current claims of
// its subject, satisfied by userinfo.Service.
type UserinfoService interface {
	Resolve(context.Context, string, time.Time) (map[string]any, error)
}

// UserinfoDependencies carries the injected pieces of the /userinfo
// endpoint.
type UserinfoDependencies struct {
	// Service resolves access tokens into subject claims.
	Service UserinfoService
}

// userInfo serves the OIDC UserInfo endpoint: it authenticates the bearer
// access token and returns the current claims of its subject as a JSON
// object with no-store semantics. Every rejected token receives the same
// invalid_token response, so resolution failures cannot be distinguished.
func (server *Server) userInfo(w http.ResponseWriter, r *http.Request) error {
	accessToken, err := bearerToken(r)
	if err != nil {
		return writeUserinfoError(
			w,
			http.StatusBadRequest,
			"invalid_request",
			err.Error(),
		)
	}

	claims, err := server.userinfo.Service.Resolve(r.Context(), accessToken, time.Now())
	if errors.Is(err, userinfo.ErrDenied) {
		return writeUserinfoError(
			w,
			http.StatusUnauthorized,
			"invalid_token",
			"the access token is invalid or expired",
		)
	}
	if err != nil {
		return fmt.Errorf("resolve userinfo: %w", err)
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if err := json.NewEncoder(w).Encode(claims); err != nil {
		return fmt.Errorf("write userinfo response: %w", err)
	}
	return nil
}

// bearerToken extracts the bearer access token of the request, or an error
// describing why the Authorization header cannot be accepted.
func bearerToken(r *http.Request) (string, error) {
	authorization := r.Header.Get("Authorization")
	if authorization == "" {
		return "", errors.New("the Authorization header is required")
	}
	if !hasAuthScheme(authorization, bearerScheme) {
		return "", errors.New("only bearer token authentication is supported")
	}
	token := strings.TrimSpace(authorization[len(bearerScheme):])
	if token == "" {
		return "", errors.New("the bearer token must not be empty")
	}
	return token, nil
}

// writeUserinfoError writes the JSON error response of a failed /userinfo
// request with no-store semantics and a bearer authentication challenge on
// 401 responses.
func writeUserinfoError(w http.ResponseWriter, status int, code, description string) error {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer realm="zen-idp", error="invalid_token"`)
	}
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(userinfoErrorResponse{
		Error:            code,
		ErrorDescription: description,
	})
}

// userinfoErrorResponse is the JSON error body of a failed /userinfo
// request.
type userinfoErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}
