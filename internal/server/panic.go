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

// PanicSessions validates the SSO session presented with the panic request,
// satisfied by session.Store. The session is the proof that the invoking
// browser belongs to the user and the source of the affected subject.
type PanicSessions interface {
	Validate(context.Context, string, time.Time) (session.Session, error)
}

// PanicLocks triggers the atomic panic action for a subject, satisfied by
// lock.Locks. PanicSubject additionally revokes every active session of the
// subject atomically with the lock creation.
type PanicLocks interface {
	PanicSubject(context.Context, string, time.Time) error
}

// PanicDependencies carries the injected pieces of the user panic
// interaction.
type PanicDependencies struct {
	// Sessions validates the SSO session presented with the panic
	// request.
	Sessions PanicSessions
	// Locks triggers the panic action and revokes the subject's sessions.
	Locks PanicLocks
	// Audit appends the panic action to the audit log.
	Audit AuditRecorder
	// CSRF protects the panic confirmation form from cross-site request
	// forgery.
	CSRF CSRFGuard
	// UI holds the presentation settings shown on the panic pages.
	UI config.UI
	// SecureCookies marks the session cookie Secure; it must be true in
	// production deployments.
	SecureCookies bool
}

// panicForm renders the user panic interaction: the confirmation with its
// protected form when the browser carries a valid SSO session, or a neutral
// sign-in-required page otherwise. The GET itself never changes state; the
// panic action happens only through the protected form submission.
func (server *Server) panicForm(w http.ResponseWriter, r *http.Request) error {
	token, err := server.panics.CSRF.Token(w, r)
	if err != nil {
		return fmt.Errorf("get CSRF token: %w", err)
	}
	if _, ok, err := server.currentPanicSession(r); err != nil {
		return err
	} else if !ok {
		return server.renderPanicSessionRequiredPage(w)
	}
	return server.renderPanicConfirmationPage(w, token)
}

// processPanic handles the panic confirmation form submission: it verifies
// the anti-forgery token, requires a valid SSO session, triggers the atomic
// panic action for the session's subject (revoking every active session of
// the user and creating the panic lock in one database transaction), clears
// the session cookie, and renders the panic completion page. The invoking
// browser is always left signed out, and sign-in stays blocked until an
// administrator clears the panic lock.
func (server *Server) processPanic(w http.ResponseWriter, r *http.Request) error {
	if err := server.panics.CSRF.Verify(r); err != nil {
		if errors.Is(err, csrf.ErrInvalidToken) {
			return writeForbiddenPage(w)
		}
		return fmt.Errorf("verify CSRF token: %w", err)
	}

	current, ok, err := server.currentPanicSession(r)
	if err != nil {
		return err
	}
	if !ok {
		return server.renderPanicSessionRequiredPage(w)
	}

	now := time.Now()
	if err := server.panics.Locks.PanicSubject(r.Context(), current.Subject, now); err != nil {
		return fmt.Errorf("invoke panic action: %w", err)
	}

	if err := server.panics.Audit.Record(r.Context(), audit.RecordParams{
		Category: audit.CategoryPanicAction,
		Subject:  current.Subject,
		Now:      now,
	}); err != nil {
		return fmt.Errorf("record panic audit event: %w", err)
	}

	http.SetCookie(w, browserCookie(sessionCookieName, "", -1, server.panics.SecureCookies))
	return server.renderPanicCompletePage(w)
}

// currentPanicSession validates the SSO session presented with a panic
// request. It reports ok=false for an absent, malformed, invalid, or expired
// cookie, which is not an error: the panic interaction simply requires an
// active session, and the page shown in its absence must not reveal why.
func (server *Server) currentPanicSession(r *http.Request) (session.Session, bool, error) {
	cookie, err := r.Cookie(sessionCookieName)
	if err == nil {
		current, err := server.panics.Sessions.Validate(r.Context(), cookie.Value, time.Now())
		if err == nil {
			return current, true, nil
		}
		switch {
		case errors.Is(err, session.ErrMalformedToken),
			errors.Is(err, session.ErrInvalidSession),
			errors.Is(err, session.ErrExpiredSession):
			// The cookie does not authenticate an active session; the
			// panic interaction requires one.
		default:
			return session.Session{}, false, fmt.Errorf("validate panic session cookie: %w", err)
		}
	}
	return session.Session{}, false, nil
}

// renderPanicConfirmationPage writes the panic confirmation form with the
// given anti-forgery token.
func (server *Server) renderPanicConfirmationPage(w http.ResponseWriter, token string) error {
	html, err := ui.PanicConfirmationPage(server.panics.UI, token).RenderString()
	if err != nil {
		return fmt.Errorf("render panic confirmation page: %w", err)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, err = io.WriteString(w, html)
	return err
}

// renderPanicCompletePage writes the panic completion page.
func (server *Server) renderPanicCompletePage(w http.ResponseWriter) error {
	html, err := ui.PanicCompletePage(server.panics.UI).RenderString()
	if err != nil {
		return fmt.Errorf("render panic complete page: %w", err)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, err = io.WriteString(w, html)
	return err
}

// renderPanicSessionRequiredPage writes the neutral page shown when a panic
// request does not carry a valid SSO session.
func (server *Server) renderPanicSessionRequiredPage(w http.ResponseWriter) error {
	html, err := ui.PanicSessionRequiredPage(server.panics.UI).RenderString()
	if err != nil {
		return fmt.Errorf("render panic session-required page: %w", err)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, err = io.WriteString(w, html)
	return err
}
