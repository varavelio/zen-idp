package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/varavelio/zen-idp/internal/config"
	"github.com/varavelio/zen-idp/internal/login"
	"github.com/varavelio/zen-idp/internal/ui"
)

// sessionCookieName is the browser cookie that carries the SSO session
// credential token.
const sessionCookieName = "zen_idp_session"

// authorizePath is the authorization endpoint that successful logins
// continue to with their pending request intact.
const authorizePath = "/authorize"

// loginFailureMessage is the single, indistinguishable failure message shown
// for every denied login attempt, matching the denial contract of the login
// service.
const loginFailureMessage = "Sign-in failed. Check your identifier and code."

// LoginService authenticates a user and creates their authoritative SSO
// session, satisfied by login.Service.
type LoginService interface {
	Login(context.Context, login.Params) (string, error)
}

// LoginDependencies carries the injected pieces of the login interaction.
type LoginDependencies struct {
	// Service authenticates users and creates their sessions.
	Service LoginService
	// UI holds the presentation settings shown on the login page.
	UI config.UI
	// SecureCookies marks the session cookie Secure; it must be true in
	// production deployments.
	SecureCookies bool
	// SessionMaxAge is the lifetime of both the session record and its
	// browser cookie.
	SessionMaxAge time.Duration
}

// loginForm renders the login interaction for a valid pending authorization
// request. Requests that do not carry a valid pending request receive the
// generic invalid-request page, because the login interaction is only
// reachable as part of an authorization flow.
func (server *Server) loginForm(w http.ResponseWriter, r *http.Request) error {
	if _, err := server.parseAndValidateAuthorizeRequest(r); err != nil {
		return writeInvalidRequestPage(w)
	}
	return server.renderLoginPage(w, r, "")
}

// processLogin handles the login form submission: it authenticates the
// submitted identifier and one-time code, and on success issues the SSO
// session cookie and continues the pending authorization flow. Every denied
// attempt re-renders the form with the same generic failure message.
func (server *Server) processLogin(w http.ResponseWriter, r *http.Request) error {
	if _, err := server.parseAndValidateAuthorizeRequest(r); err != nil {
		return writeInvalidRequestPage(w)
	}
	if err := r.ParseForm(); err != nil {
		return fmt.Errorf("parse login form: %w", err)
	}

	token, err := server.login.Service.Login(r.Context(), login.Params{
		Identifier: r.FormValue("identifier"),
		Code:       r.FormValue("code"),
		IPAddress:  remoteIP(r.RemoteAddr),
		UserAgent:  r.UserAgent(),
		Now:        time.Now(),
	})
	if errors.Is(err, login.ErrDenied) {
		return server.renderLoginPage(w, r, loginFailureMessage)
	}
	if err != nil {
		return fmt.Errorf("login: %w", err)
	}

	http.SetCookie(
		w,
		browserCookie(
			sessionCookieName,
			token,
			int(server.login.SessionMaxAge.Seconds()),
			server.login.SecureCookies,
		),
	)
	http.Redirect(w, r, authorizePath+"?"+r.URL.RawQuery, http.StatusSeeOther)
	return nil
}

// browserCookie builds the browser cookie that carries a session credential
// token. A negative maxAge clears the cookie instead of setting a token.
func browserCookie(name, value string, maxAge int, secure bool) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	}
}

// renderLoginPage writes the login form for the pending authorization request
// carried by r, with an optional failure message.
func (server *Server) renderLoginPage(
	w http.ResponseWriter,
	r *http.Request,
	failure string,
) error {
	action := authorizeLoginPath
	if r.URL.RawQuery != "" {
		action += "?" + r.URL.RawQuery
	}
	html, err := ui.LoginPage(server.login.UI, action, failure).RenderString()
	if err != nil {
		return fmt.Errorf("render login page: %w", err)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, err = io.WriteString(w, html)
	return err
}

// remoteIP strips the port from a remote address, returning the address
// unchanged when it has no port to strip.
func remoteIP(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return address
	}
	return host
}
