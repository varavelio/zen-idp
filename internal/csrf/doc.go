// Package csrf protects state-changing browser actions from cross-site
// request forgery with the double-submit cookie pattern.
//
// The server issues a random per-browser token in an HttpOnly cookie and
// every protected form must echo the same token in a hidden field. A
// cross-site attacker cannot read the cookie to forge the field, and the
// cookie is not sent with cross-site requests under SameSite=Lax, so a
// forged submission fails verification. Tokens are compared in constant
// time.
//
// The cookie is a session cookie: it lives as long as the browser session
// and is reissued automatically by any page that renders a protected form,
// so an expired or absent cookie only forces the user to reload the page
// once. Tokens are not bound to a server-side session and do not rotate on
// privilege changes.
package csrf
