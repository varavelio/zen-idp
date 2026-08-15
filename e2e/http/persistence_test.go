//go:build e2e

package e2e

import (
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/varavelio/zen-idp/e2e/http/harness"
)

// TestRestartPersistence verifies that unexpired operational state survives
// an ordinary service restart with the same state database: the SSO
// session, the signing identity, and issued tokens keep working, while a
// revoked session stays revoked.
func TestRestartPersistence(t *testing.T) {
	app := testApp(t)
	c := app.Browser()
	query := authorizeQuery("public-app", "http://127.0.0.1:9999/callback")
	authorizePath := "/authorize?" + query

	// Sign in and obtain an authorization code before the restart.
	require.Equal(t, 303, login(t, c, query, "alice").Status)
	response := c.Get(t, authorizePath)
	response.RequireStatus(t, 302)
	code := response.Location(t).Query().Get("code")
	require.True(t, strings.HasPrefix(code, "tok_"))

	// Restart the service with the same configuration and state file.
	app.Restart(t)

	// The SSO session survives: the same browser continues the flow
	// without a new login.
	response = c.Get(t, authorizePath)
	response.RequireStatus(t, 302)
	require.True(t, strings.HasPrefix(response.Location(t).Query().Get("code"), "tok_"))

	// The authorization code issued before the restart still redeems, and
	// the issued tokens still resolve at /userinfo.
	response = c.PostForm(t, "/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"http://127.0.0.1:9999/callback"},
		"client_id":     {"public-app"},
		"code_verifier": {harness.PKCEVerifier},
	})
	response.RequireStatus(t, 200)
	var tokens struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}
	response.JSON(t, &tokens)

	var userinfo map[string]any
	c.GetAuth(t, "/userinfo", "Bearer "+tokens.AccessToken).
		RequireStatus(t, 200).
		JSON(t, &userinfo)
	require.Equal(t, "alice", userinfo["sub"])

	// Revoking the session persists: after another restart, the revoked
	// session no longer continues the flow.
	confirmation := c.Get(t, "/logout")
	confirmation.RequireStatus(t, 200)
	csrf := harness.FormValue(confirmation.Body, "csrf_token")
	require.NotEmpty(t, csrf)
	c.PostForm(t, "/logout", url.Values{"csrf_token": {csrf}}).RequireStatus(t, 200)

	app.Restart(t)

	response = c.Get(t, authorizePath)
	response.RequireStatus(t, 302)
	require.True(t, strings.HasPrefix(response.Location(t).Path, "/login"))
}

// TestDeterminism verifies that the signing identity and every derived
// credential are reproduced exactly across restarts and independent
// instances, without depending on SQLite.
func TestDeterminism(t *testing.T) {
	app := testApp(t)
	c := app.Browser()

	// The same root secret reproduces the same public identity across
	// independent instances.
	kid := func() (string, string) {
		t.Helper()
		var jwks struct {
			Keys []struct {
				Kid string `json:"kid"`
				N   string `json:"n"`
			} `json:"keys"`
		}
		c.Get(t, "/.well-known/jwks.json").RequireStatus(t, 200).JSON(t, &jwks)
		require.Len(t, jwks.Keys, 1)
		return jwks.Keys[0].Kid, jwks.Keys[0].N
	}
	kidBefore, modulusBefore := kid()

	// An independent instance with the same secret derives the same
	// identity, so SQLite plays no role in the derivation.
	other := testApp(t)
	var otherJWKS struct {
		Keys []struct {
			Kid string `json:"kid"`
			N   string `json:"n"`
		} `json:"keys"`
	}
	other.Browser().Get(t, "/.well-known/jwks.json").RequireStatus(t, 200).JSON(t, &otherJWKS)
	require.Equal(t, kidBefore, otherJWKS.Keys[0].Kid)
	require.Equal(t, modulusBefore, otherJWKS.Keys[0].N)

	// A restart reproduces the same identity.
	app.Restart(t)
	kidAfter, modulusAfter := kid()
	require.Equal(t, kidBefore, kidAfter)
	require.Equal(t, modulusBefore, modulusAfter)

	// The deterministic TOTP credential still signs the user in after the
	// restart; the accepted code was computed from the independent
	// derivation, so the contract is validated as a black box.
	query := authorizeQuery("public-app", "http://127.0.0.1:9999/callback")
	require.Equal(t, 303, login(t, c, query, "alice").Status)
}
