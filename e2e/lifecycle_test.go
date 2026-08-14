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

// rotatedRootSecret is a second root secret used to exercise rotation.
const rotatedRootSecret = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

// TestUserExpiration verifies that an expired user cannot authenticate and
// receives the same generic denial as every other failure.
func TestUserExpiration(t *testing.T) {
	app := harness.New(t, harness.Config{
		RootSecret: testRootSecret,
		AdminHash:  testAdminHash,
		Users: []harness.User{
			{Sub: "alice", ExpiresAt: "2020-01-01T00:00:00Z"},
		},
		Clients: []harness.Client{{
			ID:           "app",
			RedirectURIs: []string{"http://127.0.0.1:9999/callback"},
		}},
	})
	c := app.Browser()
	query := authorizeQuery("app", "http://127.0.0.1:9999/callback")

	// The correct TOTP code is still denied: expiration is
	// indistinguishable from any other failure.
	code := harness.TOTPCode(harness.DeriveTOTPSecret(testRootSecret, "alice", 0), time.Now())
	response := c.PostForm(t, "/login?"+query, url.Values{
		"identifier": {"alice"},
		"code":       {code},
	})
	response.RequireStatus(t, 200).Contains(t, "Sign-in failed")
}

// TestTOTPRevisionRotation verifies that incrementing a user's TOTP
// revision invalidates the old credential and every session authenticated
// under it, while leaving other users untouched.
func TestTOTPRevisionRotation(t *testing.T) {
	app := testApp(t)
	c := app.Browser()
	query := authorizeQuery("public-app", "http://127.0.0.1:9999/callback")

	// alice authenticates at revision 0.
	require.Equal(t, 303, login(t, c, query, "alice").Status)

	// Rotate alice's revision and restart with the new configuration.
	cfg := testConfig()
	cfg.Users[0].TOTPRev = 1
	app.Reconfigure(t, cfg)

	// The session authenticated under the stale revision no longer
	// continues the flow.
	response := c.Get(t, "/authorize?"+query)
	response.RequireStatus(t, 302)
	require.True(t, strings.HasPrefix(response.Location(t).Path, "/login"))

	// The old credential stops working and the new one works.
	oldSecret := harness.DeriveTOTPSecret(testRootSecret, "alice", 0)
	c.PostForm(t, "/login?"+query, url.Values{
		"identifier": {"alice"},
		"code":       {harness.TOTPCode(oldSecret, time.Now())},
	}).RequireStatus(t, 200).Contains(t, "Sign-in failed")
	newSecret := harness.DeriveTOTPSecret(testRootSecret, "alice", 1)
	response = c.PostForm(t, "/login?"+query, url.Values{
		"identifier": {"alice"},
		"code":       {harness.TOTPCode(newSecret, time.Now())},
	})
	response.RequireStatus(t, 303)

	// bob, still at revision 0, is unaffected.
	require.Equal(t, 303, login(t, c, query, "bob").Status)
}

// TestRootSecretRotation verifies that changing the root secret derives a
// different signing identity and different TOTP credentials, invalidates
// every existing session, and requires the rotation behavior to re-enroll.
func TestRootSecretRotation(t *testing.T) {
	app := testApp(t)
	c := app.Browser()
	query := authorizeQuery("public-app", "http://127.0.0.1:9999/callback")

	// Capture the identity and sign in before the rotation.
	var before struct {
		Keys []struct {
			Kid string `json:"kid"`
			N   string `json:"n"`
		} `json:"keys"`
	}
	c.Get(t, "/.well-known/jwks.json").RequireStatus(t, 200).JSON(t, &before)
	require.Equal(t, 303, login(t, c, query, "alice").Status)

	// Rotate the root secret and restart with the same state database.
	cfg := testConfig()
	cfg.RootSecret = rotatedRootSecret
	app.Reconfigure(t, cfg)

	// The signing identity is different.
	var after struct {
		Keys []struct {
			Kid string `json:"kid"`
			N   string `json:"n"`
		} `json:"keys"`
	}
	c.Get(t, "/.well-known/jwks.json").RequireStatus(t, 200).JSON(t, &after)
	require.NotEqual(t, before.Keys[0].Kid, after.Keys[0].Kid)
	require.NotEqual(t, before.Keys[0].N, after.Keys[0].N)

	// The old session no longer continues the flow.
	response := c.Get(t, "/authorize?"+query)
	response.RequireStatus(t, 302)
	require.True(t, strings.HasPrefix(response.Location(t).Path, "/login"))

	// The old TOTP credential stops working and the new one works.
	oldSecret := harness.DeriveTOTPSecret(testRootSecret, "alice", 0)
	c.PostForm(t, "/login?"+query, url.Values{
		"identifier": {"alice"},
		"code":       {harness.TOTPCode(oldSecret, time.Now())},
	}).RequireStatus(t, 200).Contains(t, "Sign-in failed")
	newSecret := harness.DeriveTOTPSecret(rotatedRootSecret, "alice", 0)
	response = c.PostForm(t, "/login?"+query, url.Values{
		"identifier": {"alice"},
		"code":       {harness.TOTPCode(newSecret, time.Now())},
	})
	response.RequireStatus(t, 303)
}

// TestStateLossRecovery verifies that losing the state database invalidates
// every state-dependent artifact while the deterministic identity and
// credentials, derived from YAML plus the root secret, survive unchanged.
func TestStateLossRecovery(t *testing.T) {
	app := testApp(t)
	c := app.Browser()
	query := authorizeQuery("public-app", "http://127.0.0.1:9999/callback")

	// Capture the identity and sign in before the loss.
	var jwks struct {
		Keys []struct {
			Kid string `json:"kid"`
			N   string `json:"n"`
		} `json:"keys"`
	}
	c.Get(t, "/.well-known/jwks.json").RequireStatus(t, 200).JSON(t, &jwks)
	require.Equal(t, 303, login(t, c, query, "alice").Status)

	// Lose the state file and restart with a fresh database.
	app.ResetState(t)

	// The session is gone, but the identity and the TOTP credential are
	// byte-for-byte unchanged because they never depend on SQLite.
	response := c.Get(t, "/authorize?"+query)
	response.RequireStatus(t, 302)
	require.True(t, strings.HasPrefix(response.Location(t).Path, "/login"))
	var fresh struct {
		Keys []struct {
			Kid string `json:"kid"`
			N   string `json:"n"`
		} `json:"keys"`
	}
	c.Get(t, "/.well-known/jwks.json").RequireStatus(t, 200).JSON(t, &fresh)
	require.Equal(t, jwks.Keys[0].Kid, fresh.Keys[0].Kid)
	require.Equal(t, jwks.Keys[0].N, fresh.Keys[0].N)
	require.Equal(t, 303, login(t, c, query, "alice").Status)
}

// TestRateLimitsSurviveRestart verifies that failed-attempt counters are
// SQLite-backed and remain effective across an ordinary restart.
func TestRateLimitsSurviveRestart(t *testing.T) {
	app := testApp(t)
	c := app.Browser()
	query := authorizeQuery("public-app", "http://127.0.0.1:9999/callback")

	// Four failed attempts before the restart.
	for range 4 {
		c.PostForm(t, "/login?"+query, url.Values{
			"identifier": {"bob"},
			"code":       {"000000"},
		}).RequireStatus(t, 200)
	}

	// Restart: the counter survives.
	app.Restart(t)

	// One more failure exhausts the budget.
	c.PostForm(t, "/login?"+query, url.Values{
		"identifier": {"bob"},
		"code":       {"000000"},
	}).RequireStatus(t, 200)

	// The sixth attempt is throttled even with the correct code.
	bobSecret := harness.DeriveTOTPSecret(testRootSecret, "bob", 0)
	response := c.PostForm(t, "/login?"+query, url.Values{
		"identifier": {"bob"},
		"code":       {harness.TOTPCode(bobSecret, time.Now())},
	})
	response.RequireStatus(t, 200).Contains(t, "Sign-in failed")
}

// TestUserRemoval verifies that removing a user from the configuration
// revokes their sessions and invalidates their outstanding tokens, while
// leaving the rest of the system untouched.
func TestUserRemoval(t *testing.T) {
	app := testApp(t)
	c := app.Browser()
	query := authorizeQuery("public-app", "http://127.0.0.1:9999/callback")

	// Sign in and redeem a code into an access token while alice is
	// declared.
	require.Equal(t, 303, login(t, c, query, "alice").Status)
	code := c.Get(t, "/authorize?"+query).
		RequireStatus(t, 302).
		Location(t).Query().Get("code")
	response := c.PostForm(t, "/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"http://127.0.0.1:9999/callback"},
		"client_id":     {"public-app"},
		"code_verifier": {harness.PKCEVerifier},
	})
	response.RequireStatus(t, 200)
	var tokens struct {
		AccessToken string `json:"access_token"`
	}
	response.JSON(t, &tokens)
	require.NotEmpty(t, tokens.AccessToken)

	// Remove alice from the configuration, keeping bob, and restart.
	cfg := testConfig()
	cfg.Users = cfg.Users[1:]
	app.Reconfigure(t, cfg)

	// The session no longer continues the flow.
	response = c.Get(t, "/authorize?"+query)
	response.RequireStatus(t, 302)
	require.True(t, strings.HasPrefix(response.Location(t).Path, "/login"))

	// The outstanding access token can no longer be resolved.
	response = c.GetAuth(t, "/userinfo", "Bearer "+tokens.AccessToken)
	require.Equal(t, 401, response.Status)
	requireErrorCode(t, response, "invalid_token")

	// bob, who remains declared, still signs in normally.
	require.Equal(t, 303, login(t, c, query, "bob").Status)
}
