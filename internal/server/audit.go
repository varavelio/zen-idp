package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/varavelio/zen-idp/internal/audit"
	"github.com/varavelio/zen-idp/internal/clock"
	"github.com/varavelio/zen-idp/internal/session"
	"github.com/varavelio/zen-idp/internal/ui"
)

// adminAuditPath is the audit log page of the administration interaction.
const adminAuditPath = "/admin/audit"

// auditListLimit is the number of most recent events the audit log page
// shows.
const auditListLimit = 100

// AuditLister lists the most recent security-relevant events, satisfied by
// audit.Recorder.
type AuditLister interface {
	List(context.Context, int) ([]audit.Event, error)
}

// auditLog renders the audit log page for a browser carrying a valid
// administrator session cookie: the most recent security-relevant events,
// newest first. An absent, malformed, invalid, or expired cookie is not an
// error: the sign-in form is shown instead.
func (server *Server) auditLog(w http.ResponseWriter, r *http.Request) error {
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
			return server.renderAuditLogPage(w, r.Context(), token)
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

// renderAuditLogPage writes the audit log page for an authenticated
// administrator, listing the most recent events newest first. csrfToken
// protects the sign-out form of the shared header. The page must never be
// cached.
func (server *Server) renderAuditLogPage(
	w http.ResponseWriter,
	ctx context.Context,
	csrfToken string,
) error {
	events, err := server.admin.AuditLog.List(ctx, auditListLimit)
	if err != nil {
		return fmt.Errorf("list audit records: %w", err)
	}

	records := make([]ui.AuditRecord, 0, len(events))
	for _, event := range events {
		records = append(records, ui.AuditRecord{
			At:       clock.Format(event.CreatedAt),
			Category: string(event.Category),
			Subject:  event.Subject,
			Details:  event.Details,
		})
	}

	html, err := ui.AuditLogPage(server.admin.UI, records, csrfToken).RenderString()
	if err != nil {
		return fmt.Errorf("render audit log page: %w", err)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, err = io.WriteString(w, html)
	return err
}
