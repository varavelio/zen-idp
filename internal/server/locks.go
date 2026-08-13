package server

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/varavelio/zen-idp/internal/audit"
	"github.com/varavelio/zen-idp/internal/csrf"
	"github.com/varavelio/zen-idp/internal/session"
)

// adminLocksAction is the form target of the lock-management form.
const adminLocksAction = "/admin/locks"

// Lock-change form action values, also recorded verbatim in the audit
// details of the events they produce.
const (
	lockActionLock       = "lock"
	lockActionUnlock     = "unlock"
	lockActionClearPanic = "clear_panic"
)

// Lock-management failure messages shown on the administration home. The
// messages are specific because the form is only reachable by an
// authenticated administrator.
const (
	lockUnknownSubject = "The subject does not match a configured user."
	lockInvalidAction  = "The requested lock action is not supported."
)

// processLockChange handles the lock-management form submission: it verifies
// the anti-forgery token, requires a valid administrator session, resolves
// the submitted subject against the configured users, and applies the
// requested administrative lock change. Locking a subject also revokes every
// active session of that subject in the same database transaction, so the
// lock blocks login and SSO use immediately. Rejected submissions re-render
// the administration home with the specific failure message.
func (server *Server) processLockChange(w http.ResponseWriter, r *http.Request) error {
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
		return fmt.Errorf("parse lock change form: %w", err)
	}

	user, ok := server.resolveUser(r.FormValue("subject"))
	if !ok {
		return server.renderAdminHomeRefresh(w, r, lockUnknownSubject)
	}

	action := r.FormValue("action")
	now := time.Now()
	switch action {
	case lockActionLock:
		err = server.admin.Locks.LockSubject(r.Context(), user.Subject, now)
	case lockActionUnlock:
		err = server.admin.Locks.UnlockSubject(r.Context(), user.Subject)
	case lockActionClearPanic:
		err = server.admin.Locks.ClearPanic(r.Context(), user.Subject)
	default:
		return server.renderAdminHomeRefresh(w, r, lockInvalidAction)
	}
	if err != nil {
		return fmt.Errorf("apply lock change: %w", err)
	}

	if err := server.admin.Audit.Record(r.Context(), audit.RecordParams{
		Category: audit.CategoryLockChanged,
		Subject:  user.Subject,
		Details:  map[string]any{"action": action},
		Now:      now,
	}); err != nil {
		return fmt.Errorf("record lock change audit event: %w", err)
	}

	return server.renderAdminHomeRefresh(w, r, "")
}
