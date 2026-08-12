package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/varavelio/zen-idp/internal/admin"
	"github.com/varavelio/zen-idp/internal/config"
	"github.com/varavelio/zen-idp/internal/csrf"
	"github.com/varavelio/zen-idp/internal/session"
	"github.com/varavelio/zen-idp/internal/ui"
)

// adminSessionCookieName is the browser cookie that carries the
// administrator session credential token, distinct from the user SSO
// session cookie.
const adminSessionCookieName = "zen_idp_admin_session"

// CSRFCookieName is the browser cookie that carries the anti-forgery token
// protecting the state-changing administration forms.
const CSRFCookieName = "zen_idp_csrf"

// adminLoginPath is the administration landing page that carries the
// administrator sign-in form.
const adminLoginPath = "/admin"

// adminLoginAction is the form target of the administrator sign-in form.
const adminLoginAction = "/admin/login"

// adminLogoutPath is the administrator sign-out endpoint.
const adminLogoutPath = "/admin/logout"

// adminFailureMessage is the single, indistinguishable failure message shown
// for every denied administrator sign-in attempt, matching the denial
// contract of the admin service.
const adminFailureMessage = "Administrator sign-in failed."

// AdminService authenticates the administrator and creates their distinct
// administrator session, satisfied by admin.Service.
type AdminService interface {
	Login(context.Context, string, time.Time) (string, error)
}

// AdminSessions owns the administrator session lifecycle the administration
// interaction needs: validation of administrator browser tokens and
// revocation, satisfied by session.Store.
type AdminSessions interface {
	ValidateAdmin(context.Context, string, time.Time) (session.Session, error)
	Revoke(context.Context, string) error
}

// CSRFGuard issues and verifies the anti-forgery tokens that protect the
// state-changing administration forms, satisfied by csrf.Guard.
type CSRFGuard interface {
	Token(http.ResponseWriter, *http.Request) (string, error)
	Verify(*http.Request) error
}

// AdminDependencies carries the injected pieces of the administration
// interaction.
type AdminDependencies struct {
	// Service authenticates the administrator and creates their session.
	Service AdminService
	// Sessions validates and revokes administrator session cookies.
	Sessions AdminSessions
	// CSRF protects the state-changing administration forms from
	// cross-site request forgery.
	CSRF CSRFGuard
	// UI holds the presentation settings shown on administration pages.
	UI config.UI
	// SecureCookies marks the administrator session cookie Secure; it must
	// be true in production deployments.
	SecureCookies bool
	// SessionMaxAge is the lifetime of both the administrator session
	// record and its browser cookie.
	SessionMaxAge time.Duration
}

// adminForm renders the administration landing page: the sign-in form for
// anonymous visitors, or the administration home for a browser carrying a
// valid administrator session cookie. An absent, malformed, invalid, or
// expired cookie is not an error: the sign-in form is shown instead.
func (server *Server) adminForm(w http.ResponseWriter, r *http.Request) error {
	token, err := server.admin.CSRF.Token(w, r)
	if err != nil {
		return fmt.Errorf("get CSRF token: %w", err)
	}
	cookie, err := r.Cookie(adminSessionCookieName)
	if err == nil {
		if _, err := server.admin.Sessions.ValidateAdmin(
			r.Context(),
			cookie.Value,
			time.Now(),
		); err == nil {
			return server.renderAdminHomePage(w, token)
		} else if !errors.Is(
			err,
			session.ErrMalformedToken,
		) &&
			!errors.Is(err, session.ErrInvalidSession) &&
			!errors.Is(err, session.ErrExpiredSession) {
			return fmt.Errorf("validate admin session cookie: %w", err)
		}
	}
	return server.renderAdminLoginPage(w, token, "")
}

// processAdminLogin handles the administrator sign-in form submission: it
// verifies the anti-forgery token, authenticates the submitted password
// and, on success, issues the distinct administrator session cookie and
// returns to the administration landing page. Every denied attempt
// re-renders the form with the same generic failure message.
func (server *Server) processAdminLogin(w http.ResponseWriter, r *http.Request) error {
	if err := server.admin.CSRF.Verify(r); err != nil {
		if errors.Is(err, csrf.ErrInvalidToken) {
			return writeForbiddenPage(w)
		}
		return fmt.Errorf("verify CSRF token: %w", err)
	}
	if err := r.ParseForm(); err != nil {
		return fmt.Errorf("parse admin login form: %w", err)
	}

	token, err := server.admin.Service.Login(r.Context(), r.FormValue("password"), time.Now())
	if errors.Is(err, admin.ErrDenied) {
		return server.renderAdminLoginPage(w, "", adminFailureMessage)
	}
	if err != nil {
		return fmt.Errorf("admin login: %w", err)
	}

	http.SetCookie(
		w,
		browserCookie(
			adminSessionCookieName,
			token,
			int(server.admin.SessionMaxAge.Seconds()),
			server.admin.SecureCookies,
		),
	)
	http.Redirect(w, r, adminLoginPath, http.StatusSeeOther)
	return nil
}

// adminLogOut handles the administrator sign-out interaction: it verifies
// the anti-forgery token, revokes the administrator session carried by the
// admin session cookie, clears the cookie, and returns to the
// administration landing page, which shows the sign-in form. An absent or
// malformed admin session cookie is not an error, so sign-out always
// completes and always leaves the browser signed out as administrator. The
// regular user SSO session cookie is never touched.
func (server *Server) adminLogOut(w http.ResponseWriter, r *http.Request) error {
	if err := server.admin.CSRF.Verify(r); err != nil {
		if errors.Is(err, csrf.ErrInvalidToken) {
			return writeForbiddenPage(w)
		}
		return fmt.Errorf("verify CSRF token: %w", err)
	}

	cookie, err := r.Cookie(adminSessionCookieName)
	if err == nil {
		if err := server.admin.Sessions.Revoke(r.Context(), cookie.Value); err != nil &&
			!errors.Is(err, session.ErrMalformedToken) {
			return fmt.Errorf("revoke admin session: %w", err)
		}
	}

	http.SetCookie(w, browserCookie(adminSessionCookieName, "", -1, server.admin.SecureCookies))
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, adminLoginPath, http.StatusSeeOther)
	return nil
}

// renderAdminLoginPage writes the administrator sign-in form with the given
// anti-forgery token and an optional failure message.
func (server *Server) renderAdminLoginPage(
	w http.ResponseWriter,
	token, failure string,
) error {
	html, err := ui.AdminLoginPage(server.admin.UI, token, failure).RenderString()
	if err != nil {
		return fmt.Errorf("render admin login page: %w", err)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, err = io.WriteString(w, html)
	return err
}

// renderAdminHomePage writes the administration landing page for an
// authenticated administrator, carrying the given anti-forgery token.
func (server *Server) renderAdminHomePage(w http.ResponseWriter, token string) error {
	html, err := ui.AdminHomePage(server.admin.UI, token).RenderString()
	if err != nil {
		return fmt.Errorf("render admin home page: %w", err)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, err = io.WriteString(w, html)
	return err
}

// writeForbiddenPage writes the generic 403 page shown when a
// state-changing request fails its anti-forgery check. The page is
// stateless and must not be cached.
func writeForbiddenPage(w http.ResponseWriter) error {
	html, err := ui.ForbiddenPage().RenderString()
	if err != nil {
		return fmt.Errorf("render forbidden page: %w", err)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusForbidden)
	_, err = io.WriteString(w, html)
	return err
}
