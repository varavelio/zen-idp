package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/varavelio/zen-idp/internal/admin"
	"github.com/varavelio/zen-idp/internal/audit"
	"github.com/varavelio/zen-idp/internal/clock"
	"github.com/varavelio/zen-idp/internal/config"
	"github.com/varavelio/zen-idp/internal/csrf"
	"github.com/varavelio/zen-idp/internal/onetoken"
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

// adminTokensAction is the form target of the enrollment-token creation
// form.
const adminTokensAction = "/admin/tokens"

// adminFailureMessage is the single, indistinguishable failure message shown
// for every denied administrator sign-in attempt, matching the denial
// contract of the admin service.
const adminFailureMessage = "Administrator sign-in failed."

// Enrollment-token creation failure messages shown on the administration
// home. The messages are specific because the form is only reachable by an
// authenticated administrator.
const (
	enrollmentUnknownSubject    = "The subject does not match a configured user."
	enrollmentMissingExpiration = "Provide a relative duration or an absolute deadline."
	enrollmentBothExpirations   = "Provide either a relative duration or an absolute deadline, not both."
	enrollmentInvalidDuration   = "The duration is not a valid positive duration."
	enrollmentInvalidDeadline   = "The deadline is not a valid date-time."
	enrollmentPastDeadline      = "The deadline must be in the future."
)

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

// EnrollmentCreator records one-use enrollment tokens bound to a configured
// subject and revision, satisfied by onetoken.Store.
type EnrollmentCreator interface {
	CreateEnrollment(context.Context, onetoken.EnrollmentParams) (string, error)
}

// AuditRecorder appends security-relevant administration events, satisfied
// by audit.Recorder.
type AuditRecorder interface {
	Record(context.Context, audit.RecordParams) error
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
	// Enrollments records one-use enrollment tokens.
	Enrollments EnrollmentCreator
	// Audit appends administration events to the audit log.
	Audit AuditRecorder
	// Users lists every configured user, the only subjects enrollment
	// tokens may be created for.
	Users []config.User
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
			return server.renderAdminHomePage(w, token, "")
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
// authenticated administrator, carrying the given anti-forgery token and an
// optional failure message from a rejected enrollment-token creation.
func (server *Server) renderAdminHomePage(w http.ResponseWriter, token, failure string) error {
	html, err := ui.AdminHomePage(server.admin.UI, token, failure).RenderString()
	if err != nil {
		return fmt.Errorf("render admin home page: %w", err)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, err = io.WriteString(w, html)
	return err
}

// processEnrollmentToken handles the enrollment-token creation form
// submission: it verifies the anti-forgery token, requires a valid
// administrator session, resolves the submitted subject against the
// configured users, normalizes the supplied relative duration or absolute
// deadline to a future expiration, records the one-use token and its audit
// event, and shows the token exactly once. Rejected submissions re-render
// the administration home with the specific failure message.
func (server *Server) processEnrollmentToken(w http.ResponseWriter, r *http.Request) error {
	if err := server.admin.CSRF.Verify(r); err != nil {
		if errors.Is(err, csrf.ErrInvalidToken) {
			return writeForbiddenPage(w)
		}
		return fmt.Errorf("verify CSRF token: %w", err)
	}

	cookie, err := r.Cookie(adminSessionCookieName)
	if err == nil {
		_, err = server.admin.Sessions.ValidateAdmin(r.Context(), cookie.Value, time.Now())
	}
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) ||
			errors.Is(err, session.ErrMalformedToken) ||
			errors.Is(err, session.ErrInvalidSession) ||
			errors.Is(err, session.ErrExpiredSession) {
			w.Header().Set("Cache-Control", "no-store")
			http.Redirect(w, r, adminLoginPath, http.StatusSeeOther)
			return nil
		}
		return fmt.Errorf("validate admin session cookie: %w", err)
	}

	if err := r.ParseForm(); err != nil {
		return fmt.Errorf("parse enrollment token form: %w", err)
	}

	now := time.Now()
	user, ok := server.resolveEnrollmentUser(r.FormValue("subject"))
	if !ok {
		return server.renderAdminHomeFailure(w, r, enrollmentUnknownSubject)
	}

	expiresAt, failure := enrollmentExpiration(
		r.FormValue("duration"),
		r.FormValue("deadline"),
		now,
	)
	if failure != "" {
		return server.renderAdminHomeFailure(w, r, failure)
	}

	enrollmentToken, err := server.admin.Enrollments.CreateEnrollment(
		r.Context(),
		onetoken.EnrollmentParams{
			Subject:   user.Subject,
			TOTPRev:   user.TOTPRevision,
			ExpiresAt: expiresAt,
			Now:       now,
		},
	)
	if err != nil {
		return fmt.Errorf("create enrollment token: %w", err)
	}

	if err := server.admin.Audit.Record(r.Context(), audit.RecordParams{
		Category: audit.CategoryEnrollmentTokenCreated,
		Subject:  user.Subject,
		Details:  map[string]any{"expires_at": clock.Format(expiresAt)},
		Now:      now,
	}); err != nil {
		return fmt.Errorf("record enrollment token audit event: %w", err)
	}

	return server.renderEnrollmentTokenPage(
		w,
		user.Subject,
		clock.Format(expiresAt),
		enrollmentToken,
	)
}

// renderAdminHomeFailure re-renders the administration home with the given
// failure message, refreshing the anti-forgery token of the re-rendered
// form from the request's cookie.
func (server *Server) renderAdminHomeFailure(
	w http.ResponseWriter,
	r *http.Request,
	failure string,
) error {
	token, err := server.admin.CSRF.Token(w, r)
	if err != nil {
		return fmt.Errorf("get CSRF token: %w", err)
	}
	return server.renderAdminHomePage(w, token, failure)
}

// renderEnrollmentTokenPage writes the one-time display of a freshly
// created enrollment token. The page must never be cached.
func (server *Server) renderEnrollmentTokenPage(
	w http.ResponseWriter,
	subject, expiresAt, enrollmentToken string,
) error {
	html, err := ui.EnrollmentTokenPage(
		server.admin.UI,
		subject,
		expiresAt,
		enrollmentToken,
	).RenderString()
	if err != nil {
		return fmt.Errorf("render enrollment token page: %w", err)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, err = io.WriteString(w, html)
	return err
}

// resolveEnrollmentUser returns the configured user declared with exactly
// the given subject. Configuration validation guarantees that subjects are
// unique, so the first match is the only match.
func (server *Server) resolveEnrollmentUser(subject string) (config.User, bool) {
	for _, user := range server.admin.Users {
		if user.Subject == subject {
			return user, true
		}
	}
	return config.User{}, false
}

// enrollmentExpiration normalizes the submitted relative duration or
// absolute deadline into the absolute expiration of a new enrollment token.
// Exactly one of the two forms must be supplied, and the resulting
// expiration must be in the future. On invalid input it returns the failure
// message to show on the form.
func enrollmentExpiration(durationText, deadlineText string, now time.Time) (time.Time, string) {
	hasDuration := durationText != ""
	hasDeadline := deadlineText != ""
	switch {
	case !hasDuration && !hasDeadline:
		return time.Time{}, enrollmentMissingExpiration
	case hasDuration && hasDeadline:
		return time.Time{}, enrollmentBothExpirations
	}

	if hasDuration {
		duration, err := time.ParseDuration(durationText)
		if err != nil || duration <= 0 {
			return time.Time{}, enrollmentInvalidDuration
		}
		return now.Add(duration), ""
	}

	deadline, err := time.Parse(time.RFC3339, deadlineText)
	if err != nil {
		return time.Time{}, enrollmentInvalidDeadline
	}
	deadline = deadline.UTC()
	if !deadline.After(now) {
		return time.Time{}, enrollmentPastDeadline
	}
	return deadline, ""
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
