package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/varavelio/zen-idp/internal/audit"
	"github.com/varavelio/zen-idp/internal/config"
	"github.com/varavelio/zen-idp/internal/csrf"
	"github.com/varavelio/zen-idp/internal/session"
	"github.com/varavelio/zen-idp/internal/ui"
)

// SessionRevoker validates and revokes the SSO session identified by a
// browser token, satisfied by session.Store. Validation identifies the
// affected subject so the revocation can be recorded.
type SessionRevoker interface {
	Validate(context.Context, string, time.Time) (session.Session, error)
	Revoke(context.Context, string) error
}

// LogoutDependencies carries the injected pieces of the local logout
// interaction.
type LogoutDependencies struct {
	// Sessions validates and revokes the SSO session presented with the
	// logout request.
	Sessions SessionRevoker
	// Audit appends the session revocation to the audit log.
	Audit AuditRecorder
	// CSRF protects the sign-out confirmation form from cross-site request
	// forgery.
	CSRF CSRFGuard
	// UI holds the presentation settings shown on the logout pages.
	UI config.UI
	// SecureCookies marks the session cookie Secure; it must be true in
	// production deployments.
	SecureCookies bool
}

// logoutForm renders the local logout interaction: the sign-out confirmation
// with its protected form when the browser carries a session cookie, or the
// signed-out page directly when there is nothing to confirm. The GET itself
// never changes state; the actual revocation happens only through the
// protected form submission.
func (server *Server) logoutForm(w http.ResponseWriter, r *http.Request) error {
	token, err := server.logout.CSRF.Token(w, r)
	if err != nil {
		return fmt.Errorf("get CSRF token: %w", err)
	}
	if _, err := r.Cookie(sessionCookieName); err != nil {
		return server.renderSignedOutPage(w)
	}
	return server.renderSignOutConfirmationPage(w, token)
}

// processLogout handles the sign-out confirmation form submission: it
// verifies the anti-forgery token, validates the SSO session carried by the
// session cookie, revokes it, records the revocation, clears the cookie, and
// renders the signed-out page. An absent or malformed cookie is not an
// error, so logout always completes and always leaves the browser signed
// out; only a live session is revoked and recorded.
func (server *Server) processLogout(w http.ResponseWriter, r *http.Request) error {
	if err := server.logout.CSRF.Verify(r); err != nil {
		if errors.Is(err, csrf.ErrInvalidToken) {
			return writeForbiddenPage(w)
		}
		return fmt.Errorf("verify CSRF token: %w", err)
	}

	cookie, err := r.Cookie(sessionCookieName)
	if err == nil {
		current, err := server.logout.Sessions.Validate(r.Context(), cookie.Value, time.Now())
		switch {
		case err == nil:
			if err := server.logout.Sessions.Revoke(r.Context(), cookie.Value); err != nil &&
				!errors.Is(err, session.ErrMalformedToken) {
				return fmt.Errorf("revoke session: %w", err)
			}
			if err := server.logout.Audit.Record(r.Context(), audit.RecordParams{
				Category: audit.CategorySessionRevoked,
				Subject:  current.Subject,
				Now:      time.Now(),
			}); err != nil {
				return fmt.Errorf("record session revocation audit event: %w", err)
			}
		case errors.Is(err, session.ErrMalformedToken),
			errors.Is(err, session.ErrInvalidSession),
			errors.Is(err, session.ErrExpiredSession):
			// The cookie does not authenticate a live session: there is
			// nothing to revoke and no event to record.
		default:
			return fmt.Errorf("validate session cookie: %w", err)
		}
	}

	http.SetCookie(w, browserCookie(sessionCookieName, "", -1, server.logout.SecureCookies))
	w.Header().Set("Cache-Control", "no-store")
	return server.renderSignedOutPage(w)
}

// renderSignOutConfirmationPage writes the sign-out confirmation form with
// the given anti-forgery token.
func (server *Server) renderSignOutConfirmationPage(w http.ResponseWriter, token string) error {
	html, err := ui.LogOutConfirmationPage(server.logout.UI, token).RenderString()
	if err != nil {
		return fmt.Errorf("render sign-out confirmation page: %w", err)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, err = io.WriteString(w, html)
	return err
}

// renderSignedOutPage writes the signed-out completion page.
func (server *Server) renderSignedOutPage(w http.ResponseWriter) error {
	html, err := ui.LoggedOutPage(server.logout.UI).RenderString()
	if err != nil {
		return fmt.Errorf("render signed-out page: %w", err)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, err = io.WriteString(w, html)
	return err
}
