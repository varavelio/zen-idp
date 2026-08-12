package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/varavelio/zen-idp/internal/config"
	"github.com/varavelio/zen-idp/internal/session"
	"github.com/varavelio/zen-idp/internal/ui"
)

// SessionRevoker revokes the SSO session identified by a browser token,
// satisfied by session.Store.
type SessionRevoker interface {
	Revoke(context.Context, string) error
}

// LogoutDependencies carries the injected pieces of the local logout
// interaction.
type LogoutDependencies struct {
	// Sessions revokes the SSO session presented with the logout request.
	Sessions SessionRevoker
	// UI holds the presentation settings shown on the signed-out page.
	UI config.UI
	// SecureCookies marks the session cookie Secure; it must be true in
	// production deployments.
	SecureCookies bool
}

// logOut handles the local logout interaction: it revokes the SSO session
// carried by the session cookie, clears the cookie, and renders the
// signed-out page. An absent or malformed session cookie is not an error, so
// logout always completes and always leaves the browser signed out.
func (server *Server) logOut(w http.ResponseWriter, r *http.Request) error {
	cookie, err := r.Cookie(sessionCookieName)
	if err == nil {
		if err := server.logout.Sessions.Revoke(r.Context(), cookie.Value); err != nil &&
			!errors.Is(err, session.ErrMalformedToken) {
			return fmt.Errorf("revoke session: %w", err)
		}
	}

	http.SetCookie(w, sessionCookie("", -1, server.logout.SecureCookies))

	html, err := ui.SignedOutPage(server.logout.UI).RenderString()
	if err != nil {
		return fmt.Errorf("render signed-out page: %w", err)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, err = io.WriteString(w, html)
	return err
}
