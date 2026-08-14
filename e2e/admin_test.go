//go:build e2e

package e2e

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/varavelio/zen-idp/e2e/harness"
)

// TestAdminLifecycle walks the complete administration interaction: sign-in,
// enrollment-token creation and consumption, administrative locks, the user
// panic action, and the audit log.
func TestAdminLifecycle(t *testing.T) {
	app := testApp(t)
	c := app.Browser()
	query := authorizeQuery("public-app", "http://127.0.0.1:9999/callback")

	// Anonymous visitors receive the sign-in form.
	form := c.Get(t, "/admin")
	form.RequireStatus(t, 200).Contains(t, "Administration")
	csrf := harness.FormValue(form.Body, "csrf_token")
	require.NotEmpty(t, csrf)

	// A submission without an anti-forgery token is forbidden.
	c.PostForm(t, "/admin/login", url.Values{
		"password": {testAdminPassword},
	}).RequireStatus(t, 403)

	// A wrong password is denied with the single generic message.
	c.PostForm(t, "/admin/login", url.Values{
		"password":   {"wrong-password"},
		"csrf_token": {csrf},
	}).RequireStatus(t, 200).Contains(t, "Administrator sign-in failed")

	// The correct password signs the administrator in with a distinct
	// session cookie.
	loginResponse := c.PostForm(t, "/admin/login", url.Values{
		"password":   {testAdminPassword},
		"csrf_token": {csrf},
	})
	loginResponse.RequireStatus(t, 303)
	require.True(t, strings.HasPrefix(c.Cookie("zen_idp_admin_session"), "sess_"))
	require.Empty(t, c.Cookie("zen_idp_session"))

	// The administration home lists every configured user.
	home := c.Get(t, "/admin")
	home.RequireStatus(t, 200).Contains(t, "alice").Contains(t, "bob")
	csrf = harness.FormValue(home.Body, "csrf_token")
	require.NotEmpty(t, csrf)

	// An enrollment token is created for alice and shown exactly once
	// with its shareable link.
	tokenPage := c.PostForm(t, "/admin/tokens", url.Values{
		"subject":    {"alice"},
		"duration":   {"1h"},
		"csrf_token": {csrf},
	})
	tokenPage.RequireStatus(t, 200)
	enrollToken := harness.FindToken(tokenPage.Body)
	require.True(t, strings.HasPrefix(enrollToken, "tok_"))
	tokenPage.Contains(t, app.BaseURL()+"/enroll?token="+enrollToken)

	// The user redeems the token at the enrollment interaction and the
	// revealed secret matches the independent derivation exactly.
	enroll := c.Get(t, "/enroll?token="+enrollToken)
	enroll.RequireStatus(t, 200)
	require.Equal(t, enrollToken, harness.FormValue(enroll.Body, "token"))
	ready := c.PostForm(t, "/enroll", url.Values{
		"token":      {enrollToken},
		"csrf_token": {harness.FormValue(enroll.Body, "csrf_token")},
	})
	ready.RequireStatus(t, 200).Contains(t, "data:image/png;base64,")
	require.Equal(
		t,
		harness.DeriveTOTPSecret(testRootSecret, "alice", 0),
		harness.FindOTPAuthSecret(ready.Body),
	)

	// The one-use token is consumed: a second redemption is denied.
	replayForm := c.Get(t, "/enroll")
	replayForm.RequireStatus(t, 200)
	c.PostForm(t, "/enroll", url.Values{
		"token":      {enrollToken},
		"csrf_token": {harness.FormValue(replayForm.Body, "csrf_token")},
	}).RequireStatus(t, 200).Contains(t, "invalid or has expired")

	// An administrative lock blocks the user's login, and the unlock
	// restores it.
	aliceSecret := harness.DeriveTOTPSecret(testRootSecret, "alice", 0)
	lockCode := harness.TOTPCode(aliceSecret, time.Now())
	c.PostForm(t, "/admin/locks", url.Values{
		"subject":    {"alice"},
		"action":     {"lock"},
		"csrf_token": {csrf},
	}).RequireStatus(t, 200)
	c.PostForm(t, "/login?"+query, url.Values{
		"identifier": {"alice"},
		"code":       {lockCode},
	}).RequireStatus(t, 200).Contains(t, "Sign-in failed")
	c.PostForm(t, "/admin/locks", url.Values{
		"subject":    {"alice"},
		"action":     {"unlock"},
		"csrf_token": {csrf},
	}).RequireStatus(t, 200)

	// The user signs in and triggers the panic action, which revokes
	// every session and leaves the browser signed out.
	require.Equal(t, 303, login(t, c, query, "alice").Status)
	panicForm := c.Get(t, "/panic")
	panicForm.RequireStatus(t, 200)
	c.PostForm(t, "/panic", url.Values{
		"csrf_token": {harness.FormValue(panicForm.Body, "csrf_token")},
	}).RequireStatus(t, 200)
	require.Empty(t, c.Cookie("zen_idp_session"))

	// The panic lock blocks login until the administrator clears it, and
	// an unlock never clears a distinct panic lock: only clear_panic does.
	c.PostForm(t, "/login?"+query, url.Values{
		"identifier": {"alice"},
		"code":       {harness.TOTPCode(aliceSecret, time.Now())},
	}).RequireStatus(t, 200).Contains(t, "Sign-in failed")
	home = c.Get(t, "/admin")
	home.RequireStatus(t, 200)
	c.PostForm(t, "/admin/locks", url.Values{
		"subject":    {"alice"},
		"action":     {"unlock"},
		"csrf_token": {harness.FormValue(home.Body, "csrf_token")},
	}).RequireStatus(t, 200)
	c.PostForm(t, "/login?"+query, url.Values{
		"identifier": {"alice"},
		"code":       {harness.TOTPCode(aliceSecret, time.Now())},
	}).RequireStatus(t, 200).Contains(t, "Sign-in failed")
	home = c.Get(t, "/admin")
	home.RequireStatus(t, 200)
	c.PostForm(t, "/admin/locks", url.Values{
		"subject":    {"alice"},
		"action":     {"clear_panic"},
		"csrf_token": {harness.FormValue(home.Body, "csrf_token")},
	}).RequireStatus(t, 200)
	require.Equal(t, 303, login(t, c, query, "alice").Status)

	// A local logout revokes the user session and records the event.
	confirmation := c.Get(t, "/logout")
	confirmation.RequireStatus(t, 200)
	c.PostForm(t, "/logout", url.Values{
		"csrf_token": {harness.FormValue(confirmation.Body, "csrf_token")},
	}).RequireStatus(t, 200)

	// The audit log shows every security-relevant event of the flow.
	audit := c.Get(t, "/admin/audit")
	audit.RequireStatus(t, 200)
	for _, category := range []string{
		"admin_authentication",
		"enrollment_token_created",
		"enrollment_token_consumed",
		"lock_change",
		"panic_action",
		"session_revoked",
	} {
		audit.Contains(t, category)
	}

	// Five wrong passwords exhaust the administrator budget, and the
	// throttled sixth attempt records a rate-limit event.
	for range 5 {
		c.PostForm(t, "/admin/login", url.Values{
			"password":   {"wrong-password"},
			"csrf_token": {csrf},
		}).RequireStatus(t, 200)
	}
	c.PostForm(t, "/admin/login", url.Values{
		"password":   {testAdminPassword},
		"csrf_token": {csrf},
	}).RequireStatus(t, 200).Contains(t, "Administrator sign-in failed")
	audit = c.Get(t, "/admin/audit")
	audit.RequireStatus(t, 200).Contains(t, "rate_limit")

	// The sign-out clears the administrator session.
	c.PostForm(t, "/admin/logout", url.Values{
		"csrf_token": {csrf},
	}).RequireStatus(t, 303)
	require.Empty(t, c.Cookie("zen_idp_admin_session"))
}
