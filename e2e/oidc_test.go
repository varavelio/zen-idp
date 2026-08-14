//go:build e2e

package e2e

import (
	"maps"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/varavelio/zen-idp/e2e/harness"
)

// Shared fixtures of the suite: the root secret, the administrator
// credential pair, and the confidential client credential pair. The hashes
// are precomputed Argon2id PHC values anchored in the unit test suite.
const (
	testRootSecret    = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	testAdminPassword = "test-admin-password"
	testAdminHash     = "$argon2id$v=19$m=65536,t=2,p=2$INy39hwa9rMN8WhprspfDQ$45uH4EsaLtb2h9bUkVfgAAoLKsgPK1ALYprlwxm16B4"
	testClientSecret  = "test-client-secret"
	testClientHash    = "$argon2id$v=19$m=65536,t=2,p=2$5XEq+R1hozyGGEdvY7KVYA$cEyyXwpgnzm0IMtpsDu3+O6eBxBdO2VaFEpyLHUetIo"
)

// testConfig returns the shared configuration of the suite: two users and
// one public and one confidential client.
func testConfig() harness.Config {
	return harness.Config{
		RootSecret: testRootSecret,
		AdminHash:  testAdminHash,
		UIName:     "E2E Test Auth",
		Users: []harness.User{
			{
				Sub:   "alice",
				Login: "alice@example.com",
				Claims: map[string]any{
					"name":   "Alice Example",
					"groups": []any{"engineering", "operators"},
				},
			},
			{Sub: "bob"},
		},
		Clients: []harness.Client{
			{
				ID:           "public-app",
				Name:         "Public App",
				RedirectURIs: []string{"http://127.0.0.1:9999/callback"},
			},
			{
				ID:           "confidential-app",
				Name:         "Confidential App",
				SecretHash:   testClientHash,
				RedirectURIs: []string{"http://127.0.0.1:9999/confidential-callback"},
			},
		},
	}
}

// testApp returns a harness with the shared test configuration.
func testApp(t *testing.T) *harness.Harness {
	t.Helper()
	return harness.New(t, testConfig())
}

// authorizeQuery builds a valid authorization request for the given client
// with the shared PKCE pair and state.
func authorizeQuery(clientID, redirectURI string) string {
	return url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"response_type":         {"code"},
		"scope":                 {"openid"},
		"state":                 {"state-123"},
		"nonce":                 {"nonce-456"},
		"code_challenge":        {harness.PKCEChallenge()},
		"code_challenge_method": {"S256"},
	}.Encode()
}

// login signs the given identifier in with its correct TOTP code and
// returns the login response.
func login(t *testing.T, c *harness.Browser, query, identifier string) *harness.Response {
	t.Helper()
	secret := harness.DeriveTOTPSecret(testRootSecret, identifier, 0)
	return c.PostForm(t, "/login?"+query, url.Values{
		"identifier": {identifier},
		"code":       {harness.TOTPCode(secret, time.Now())},
	})
}

// TestOIDCGoldenPath walks the complete OpenID Connect flow of a public
// client: discovery, JWKS, authorization, login, code redemption, token
// contents, userinfo resolution, and logout.
func TestOIDCGoldenPath(t *testing.T) {
	app := testApp(t)
	c := app.Browser()
	query := authorizeQuery("public-app", "http://127.0.0.1:9999/callback")
	authorizePath := "/authorize?" + query

	// Discovery advertises exactly the implemented behavior.
	var discovery struct {
		Issuer                string   `json:"issuer"`
		AuthorizationEndpoint string   `json:"authorization_endpoint"`
		TokenEndpoint         string   `json:"token_endpoint"`
		UserinfoEndpoint      string   `json:"userinfo_endpoint"`
		EndSessionEndpoint    string   `json:"end_session_endpoint"`
		JWKSURI               string   `json:"jwks_uri"`
		ResponseTypes         []string `json:"response_types_supported"`
		AuthMethods           []string `json:"token_endpoint_auth_methods_supported"`
		CodeChallengeMethods  []string `json:"code_challenge_methods_supported"`
	}
	c.Get(t, "/.well-known/openid-configuration").
		RequireStatus(t, 200).
		JSON(t, &discovery)
	require.Equal(t, app.BaseURL(), discovery.Issuer)
	require.Equal(t, app.BaseURL()+"/authorize", discovery.AuthorizationEndpoint)
	require.Equal(t, app.BaseURL()+"/token", discovery.TokenEndpoint)
	require.Equal(t, app.BaseURL()+"/userinfo", discovery.UserinfoEndpoint)
	require.Equal(t, app.BaseURL()+"/logout", discovery.EndSessionEndpoint)
	require.Equal(t, app.BaseURL()+"/.well-known/jwks.json", discovery.JWKSURI)
	require.Equal(t, []string{"code"}, discovery.ResponseTypes)
	require.Equal(
		t,
		[]string{"none", "client_secret_basic", "client_secret_post"},
		discovery.AuthMethods,
	)
	require.Equal(t, []string{"S256"}, discovery.CodeChallengeMethods)

	// JWKS publishes the public signing identity.
	var jwks struct {
		Keys []struct {
			Kty string `json:"kty"`
			Alg string `json:"alg"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	c.Get(t, "/.well-known/jwks.json").RequireStatus(t, 200).JSON(t, &jwks)
	require.Len(t, jwks.Keys, 1)
	require.Equal(t, "RSA", jwks.Keys[0].Kty)
	require.Equal(t, "RS256", jwks.Keys[0].Alg)
	require.NotEmpty(t, jwks.Keys[0].N)
	require.NotEmpty(t, jwks.Keys[0].E)
	kid := jwks.Keys[0].Kid

	// An anonymous authorization request redirects to the login
	// interaction with its parameters intact.
	response := c.Get(t, authorizePath)
	response.RequireStatus(t, 302)
	require.Equal(t, "/login?"+query, response.Location(t).RequestURI())

	// The login form renders for a valid pending request and every page
	// carries the browser security headers.
	response = c.Get(t, "/login?"+query)
	response.RequireStatus(t, 200).
		Contains(t, `name="identifier"`).
		Contains(t, `name="code"`)
	require.Contains(t, response.Header.Get("Content-Security-Policy"), "default-src 'self'")
	require.Equal(t, "nosniff", response.Header.Get("X-Content-Type-Options"))
	require.Equal(t, "no-referrer", response.Header.Get("Referrer-Policy"))

	// A wrong code is denied with the single generic message.
	response = c.PostForm(t, "/login?"+query, url.Values{
		"identifier": {"alice"},
		"code":       {"000000"},
	})
	response.RequireStatus(t, 200).Contains(t, "Sign-in failed")

	// The correct TOTP code signs the user in and issues the SSO session
	// cookie with its security attributes.
	response = login(t, c, query, "alice")
	response.RequireStatus(t, 303)
	require.Equal(t, "/authorize?"+query, response.Location(t).RequestURI())
	require.Contains(t, response.SetCookie(), "HttpOnly")
	require.Contains(t, response.SetCookie(), "SameSite=Lax")
	require.True(t, strings.HasPrefix(c.Cookie("zen_idp_session"), "sess_"))

	// The authorized session receives a fresh code and the echoed state.
	response = c.Get(t, authorizePath)
	response.RequireStatus(t, 302)
	target := response.Location(t)
	require.Equal(t, "http", target.Scheme)
	require.Equal(t, "127.0.0.1:9999", target.Host)
	require.Equal(t, "/callback", target.Path)
	code := target.Query().Get("code")
	require.True(t, strings.HasPrefix(code, "tok_"))
	require.Equal(t, "state-123", target.Query().Get("state"))

	// The code redeems into the token response.
	response = c.PostForm(t, "/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"http://127.0.0.1:9999/callback"},
		"client_id":     {"public-app"},
		"code_verifier": {harness.PKCEVerifier},
	})
	response.RequireStatus(t, 200)
	require.Contains(t, response.Header.Get("Cache-Control"), "no-store")
	var tokens struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
		IDToken     string `json:"id_token"`
		Scope       string `json:"scope"`
	}
	response.JSON(t, &tokens)
	require.Equal(t, "Bearer", tokens.TokenType)
	require.Equal(t, int64(900), tokens.ExpiresIn)
	require.Equal(t, "openid", tokens.Scope)
	require.NotEmpty(t, tokens.AccessToken)
	require.NotEmpty(t, tokens.IDToken)

	// The ID token carries the protocol contract and every custom claim.
	header, claims := harness.DecodeJWT(t, tokens.IDToken)
	require.Equal(t, "RS256", header["alg"])
	require.Equal(t, kid, header["kid"])
	require.Equal(t, app.BaseURL(), claims["iss"])
	require.Equal(t, "alice", claims["sub"])
	require.Equal(t, "public-app", claims["aud"])
	require.Equal(t, "nonce-456", claims["nonce"])
	require.InDelta(t, float64(time.Now().Unix()), claims["auth_time"].(float64), 60)
	require.Equal(t, float64(900), claims["exp"].(float64)-claims["iat"].(float64))
	require.Equal(t, "Alice Example", claims["name"])
	require.Equal(t, []any{"engineering", "operators"}, claims["groups"])
	for key := range claims {
		require.False(t, strings.HasPrefix(key, "idp_"))
	}

	// The access token is thin and bound to the /userinfo audience.
	_, claims = harness.DecodeJWT(t, tokens.AccessToken)
	require.Equal(t, app.BaseURL()+"/userinfo", claims["aud"])
	require.Equal(t, "alice", claims["sub"])
	require.NotContains(t, claims, "name")
	require.NotContains(t, claims, "groups")

	// /userinfo resolves the current claims of the bearer token.
	var userinfo map[string]any
	response = c.GetAuth(t, "/userinfo", "Bearer "+tokens.AccessToken)
	response.RequireStatus(t, 200).JSON(t, &userinfo)
	require.Equal(t, "alice", userinfo["sub"])
	require.Equal(t, "Alice Example", userinfo["name"])
	require.Equal(t, []any{"engineering", "operators"}, userinfo["groups"])
	require.Equal(t, "*", response.Header.Get("Access-Control-Allow-Origin"))

	// Logout requires confirmation and a valid anti-forgery token, then
	// revokes the session and clears the cookie.
	confirmation := c.Get(t, "/logout")
	confirmation.RequireStatus(t, 200).Contains(t, "Sign out")
	c.PostForm(t, "/logout", url.Values{}).RequireStatus(t, 403)
	csrf := harness.FormValue(confirmation.Body, "csrf_token")
	require.NotEmpty(t, csrf)
	c.PostForm(t, "/logout", url.Values{"csrf_token": {csrf}}).RequireStatus(t, 200)
	require.Empty(t, c.Cookie("zen_idp_session"))

	// The revoked session no longer continues the flow.
	response = c.Get(t, authorizePath)
	response.RequireStatus(t, 302)
	require.True(t, strings.HasPrefix(response.Location(t).Path, "/login"))
}

// TestOIDCDenials verifies that every rejected authorization and login
// attempt fails indistinguishably and without leaking usable state.
func TestOIDCDenials(t *testing.T) {
	app := testApp(t)
	c := app.Browser()
	query := authorizeQuery("public-app", "http://127.0.0.1:9999/callback")
	authorizePath := "/authorize?" + query

	// An untrusted client receives the generic error page, never a
	// redirect to an attacker-controlled target.
	response := c.Get(t, "/authorize?"+url.Values{
		"client_id":     {"evil"},
		"redirect_uri":  {"https://evil.example/callback"},
		"response_type": {"code"},
		"scope":         {"openid"},
	}.Encode())
	response.RequireStatus(t, 400)

	// A missing openid scope fails with an OIDC error redirect that
	// echoes the state.
	response = c.Get(t, "/authorize?"+url.Values{
		"client_id":             {"public-app"},
		"redirect_uri":          {"http://127.0.0.1:9999/callback"},
		"response_type":         {"code"},
		"scope":                 {"profile"},
		"state":                 {"state-123"},
		"code_challenge":        {harness.PKCEChallenge()},
		"code_challenge_method": {"S256"},
	}.Encode())
	response.RequireStatus(t, 302)
	require.Equal(t, "invalid_scope", response.Location(t).Query().Get("error"))
	require.Equal(t, "state-123", response.Location(t).Query().Get("state"))

	// A public client without PKCE is rejected.
	response = c.Get(t, "/authorize?"+url.Values{
		"client_id":     {"public-app"},
		"redirect_uri":  {"http://127.0.0.1:9999/callback"},
		"response_type": {"code"},
		"scope":         {"openid"},
		"state":         {"state-123"},
	}.Encode())
	response.RequireStatus(t, 302)
	require.Equal(t, "invalid_request", response.Location(t).Query().Get("error"))

	// prompt=none without a session fails with login_required instead of
	// showing the login interaction.
	response = c.Get(t, "/authorize?"+url.Values{
		"client_id":             {"public-app"},
		"redirect_uri":          {"http://127.0.0.1:9999/callback"},
		"response_type":         {"code"},
		"scope":                 {"openid"},
		"state":                 {"state-123"},
		"prompt":                {"none"},
		"code_challenge":        {harness.PKCEChallenge()},
		"code_challenge_method": {"S256"},
	}.Encode())
	response.RequireStatus(t, 302)
	require.Equal(t, "login_required", response.Location(t).Query().Get("error"))
	require.Equal(t, "state-123", response.Location(t).Query().Get("state"))

	// An unknown identifier and a wrong code are denied with exactly the
	// same response, so failure causes cannot be distinguished.
	unknown := c.PostForm(t, "/login?"+query, url.Values{
		"identifier": {"nobody"},
		"code": {
			harness.TOTPCode(harness.DeriveTOTPSecret(testRootSecret, "nobody", 0), time.Now()),
		},
	})
	unknown.RequireStatus(t, 200)
	wrongCode := c.PostForm(t, "/login?"+query, url.Values{
		"identifier": {"alice"},
		"code":       {"000000"},
	})
	wrongCode.RequireStatus(t, 200)
	require.Equal(t, unknown.Body, wrongCode.Body)
	require.Contains(t, string(wrongCode.Body), "Sign-in failed")

	// A malformed code is denied identically.
	malformed := c.PostForm(t, "/login?"+query, url.Values{
		"identifier": {"alice"},
		"code":       {"12ab"},
	})
	malformed.RequireStatus(t, 200)
	require.Equal(t, unknown.Body, malformed.Body)

	// The configured idp_login authenticates the same identity.
	aliceSecret := harness.DeriveTOTPSecret(testRootSecret, "alice", 0)
	response = c.PostForm(t, "/login?"+query, url.Values{
		"identifier": {"alice@example.com"},
		"code":       {harness.TOTPCode(aliceSecret, time.Now())},
	})
	response.RequireStatus(t, 303)

	// Sign in to obtain codes for the redemption denials.
	require.Equal(t, 303, login(t, c, query, "alice").Status)

	redeem := func(code string, form url.Values) *harness.Response {
		t.Helper()
		values := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"redirect_uri":  {"http://127.0.0.1:9999/callback"},
			"client_id":     {"public-app"},
			"code_verifier": {harness.PKCEVerifier},
		}
		maps.Copy(values, form)
		return c.PostForm(t, "/token", values)
	}

	freshCode := func() string {
		t.Helper()
		response := c.Get(t, authorizePath)
		response.RequireStatus(t, 302)
		return response.Location(t).Query().Get("code")
	}

	// A code redeems exactly once; the replay is rejected.
	code := freshCode()
	redeem(code, nil).RequireStatus(t, 200)
	response = redeem(code, nil)
	require.Equal(t, 400, response.Status)
	requireErrorCode(t, response, "invalid_grant")

	// A wrong PKCE verifier is rejected and burns the single-use code.
	response = redeem(freshCode(), url.Values{"code_verifier": {strings.Repeat("x", 43)}})
	require.Equal(t, 400, response.Status)
	requireErrorCode(t, response, "invalid_grant")

	// A missing PKCE verifier is rejected for a PKCE-bound code.
	response = redeem(freshCode(), url.Values{"code_verifier": {""}})
	require.Equal(t, 400, response.Status)
	requireErrorCode(t, response, "invalid_grant")

	// A wrong redirect URI is rejected.
	response = redeem(freshCode(), url.Values{"redirect_uri": {"http://127.0.0.1:9999/other"}})
	require.Equal(t, 400, response.Status)
	requireErrorCode(t, response, "invalid_grant")

	// A code issued to another client is rejected, and token parameters
	// in the query string are refused outright.
	response = c.PostFormAuth(t, "/token", url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {freshCode()},
		"redirect_uri": {"http://127.0.0.1:9999/callback"},
		"client_id":    {"confidential-app"},
	}, harness.BasicAuth("confidential-app", testClientSecret))
	require.Equal(t, 400, response.Status)
	requireErrorCode(t, response, "invalid_grant")

	response = c.PostForm(t, "/token?"+url.Values{
		"grant_type": {"authorization_code"},
		"code":       {freshCode()},
	}.Encode(), url.Values{})
	require.Equal(t, 400, response.Status)
	requireErrorCode(t, response, "invalid_request")

	// The shared login budget throttles the sixth consecutive failure,
	// even when the submitted code is correct.
	throttled := testApp(t).Browser()
	for range 5 {
		throttled.PostForm(t, "/login?"+query, url.Values{
			"identifier": {"bob"},
			"code":       {"000000"},
		}).RequireStatus(t, 200)
	}
	response = throttled.PostForm(t, "/login?"+query, url.Values{
		"identifier": {"bob"},
		"code": {
			harness.TOTPCode(harness.DeriveTOTPSecret(testRootSecret, "bob", 0), time.Now()),
		},
	})
	response.RequireStatus(t, 200).Contains(t, "Sign-in failed")
}

// requireErrorCode asserts the OIDC error code of a token error response.
func requireErrorCode(t *testing.T, response *harness.Response, want string) {
	t.Helper()
	var body struct {
		Error string `json:"error"`
	}
	response.JSON(t, &body)
	require.Equal(t, want, body.Error)
}

// TestConfidentialClient walks the confidential-client flow: secret
// authentication with client_secret_basic, no PKCE requirement, and the
// failed-attempt budget that protects the client secret.
func TestConfidentialClient(t *testing.T) {
	app := testApp(t)
	c := app.Browser()
	redirectURI := "http://127.0.0.1:9999/confidential-callback"

	// Confidential clients may omit PKCE entirely: the authorization
	// request carries no code challenge and the redemption no verifier.
	query := url.Values{
		"client_id":     {"confidential-app"},
		"redirect_uri":  {redirectURI},
		"response_type": {"code"},
		"scope":         {"openid"},
		"state":         {"state-123"},
	}.Encode()
	require.Equal(t, 303, login(t, c, query, "alice").Status)
	response := c.Get(t, "/authorize?"+query)
	response.RequireStatus(t, 302)
	code := response.Location(t).Query().Get("code")
	require.True(t, strings.HasPrefix(code, "tok_"))

	// The code redeems with client_secret_basic authentication and no
	// PKCE verifier.
	response = c.PostFormAuth(t, "/token", url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {redirectURI},
		"client_id":    {"confidential-app"},
	}, harness.BasicAuth("confidential-app", testClientSecret))
	response.RequireStatus(t, 200)
	var tokens struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}
	response.JSON(t, &tokens)
	require.NotEmpty(t, tokens.AccessToken)
	require.NotEmpty(t, tokens.IDToken)

	// The same client also authenticates with client_secret_post, the
	// credentials traveling in the form body.
	code = c.Get(t, "/authorize?"+query).
		RequireStatus(t, 302).
		Location(t).Query().Get("code")
	response = c.PostForm(t, "/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {"confidential-app"},
		"client_secret": {testClientSecret},
	})
	response.RequireStatus(t, 200)
	var postTokens struct {
		AccessToken string `json:"access_token"`
	}
	response.JSON(t, &postTokens)
	require.NotEmpty(t, postTokens.AccessToken)

	// A confidential client without credentials is rejected.
	response = c.PostForm(t, "/token", url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {"tok_x_y"},
		"redirect_uri": {redirectURI},
		"client_id":    {"confidential-app"},
	})
	require.Equal(t, 401, response.Status)
	requireErrorCode(t, response, "invalid_client")

	// A public client presenting a secret is rejected.
	response = c.PostFormAuth(t, "/token", url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {"tok_x_y"},
		"redirect_uri": {"http://127.0.0.1:9999/callback"},
		"client_id":    {"public-app"},
	}, harness.BasicAuth("public-app", testClientSecret))
	require.Equal(t, 401, response.Status)
	requireErrorCode(t, response, "invalid_client")

	// Five wrong secrets exhaust the per-client budget; the sixth attempt
	// is blocked even with the correct secret.
	for range 5 {
		response = c.PostFormAuth(t, "/token", url.Values{
			"grant_type":   {"authorization_code"},
			"code":         {"tok_x_y"},
			"redirect_uri": {redirectURI},
			"client_id":    {"confidential-app"},
		}, harness.BasicAuth("confidential-app", "wrong-secret"))
		require.Equal(t, 401, response.Status)
	}
	response = c.PostFormAuth(t, "/token", url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {"tok_x_y"},
		"redirect_uri": {redirectURI},
		"client_id":    {"confidential-app"},
	}, harness.BasicAuth("confidential-app", testClientSecret))
	require.Equal(t, 401, response.Status)
	requireErrorCode(t, response, "invalid_client")
	require.Contains(t, string(response.Body), "blocked")
}

// TestConfidentialClientPKCE verifies the S256 PKCE path of a confidential
// client: optional but fully enforced when the client supplies a challenge.
func TestConfidentialClientPKCE(t *testing.T) {
	app := testApp(t)
	c := app.Browser()
	query := authorizeQuery("confidential-app", "http://127.0.0.1:9999/confidential-callback")
	redirectURI := "http://127.0.0.1:9999/confidential-callback"

	// Sign in to obtain an authenticated session.
	require.Equal(t, 303, login(t, c, query, "alice").Status)
	code := c.Get(t, "/authorize?"+query).
		RequireStatus(t, 302).
		Location(t).Query().Get("code")
	require.True(t, strings.HasPrefix(code, "tok_"))

	// The correct verifier redeems the PKCE-bound code.
	response := c.PostFormAuth(t, "/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {"confidential-app"},
		"code_verifier": {harness.PKCEVerifier},
	}, harness.BasicAuth("confidential-app", testClientSecret))
	response.RequireStatus(t, 200)

	// A wrong verifier burns the code and is rejected.
	code = c.Get(t, "/authorize?"+query).
		RequireStatus(t, 302).
		Location(t).Query().Get("code")
	response = c.PostFormAuth(t, "/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {"confidential-app"},
		"code_verifier": {strings.Repeat("x", 43)},
	}, harness.BasicAuth("confidential-app", testClientSecret))
	require.Equal(t, 400, response.Status)
	requireErrorCode(t, response, "invalid_grant")
}

// TestSSOAcrossClients verifies that one authoritative session continues
// authorization requests for every registered client without a new login,
// while a redirect URI registered only for another client stays rejected.
func TestSSOAcrossClients(t *testing.T) {
	app := testApp(t)
	c := app.Browser()
	queryA := authorizeQuery("public-app", "http://127.0.0.1:9999/callback")
	queryB := authorizeQuery("confidential-app", "http://127.0.0.1:9999/confidential-callback")

	// One login serves both clients.
	require.Equal(t, 303, login(t, c, queryA, "alice").Status)

	// The session issues a code for the second client without a new
	// login, echoing its own state.
	response := c.Get(t, "/authorize?"+queryB)
	response.RequireStatus(t, 302)
	target := response.Location(t)
	require.True(t, strings.HasPrefix(target.Query().Get("code"), "tok_"))
	require.Equal(t, "state-123", target.Query().Get("state"))

	// A redirect URI registered only for another client is not accepted
	// for this client, even with an authenticated session.
	response = c.Get(t, "/authorize?"+url.Values{
		"client_id":             {"public-app"},
		"redirect_uri":          {"http://127.0.0.1:9999/confidential-callback"},
		"response_type":         {"code"},
		"scope":                 {"openid"},
		"state":                 {"state-123"},
		"code_challenge":        {harness.PKCEChallenge()},
		"code_challenge_method": {"S256"},
	}.Encode())
	response.RequireStatus(t, 400)
}

// TestRPInitiatedLogout verifies the relying-party logout redirect: after
// confirmation, a signed-out user with a valid id_token_hint returns to a
// registered post_logout_redirect_uri with the state echoed, while
// unregistered URIs are never followed.
func TestRPInitiatedLogout(t *testing.T) {
	app := testApp(t)
	c := app.Browser()
	query := authorizeQuery("public-app", "http://127.0.0.1:9999/callback")

	// Sign in and obtain an ID token to use as the hint.
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
		IDToken string `json:"id_token"`
	}
	response.JSON(t, &tokens)
	require.NotEmpty(t, tokens.IDToken)

	// A registered post-logout redirect is confirmed and followed with
	// the state echoed back, and the session ends.
	logoutQuery := url.Values{
		"id_token_hint":            {tokens.IDToken},
		"post_logout_redirect_uri": {"http://127.0.0.1:9999/callback"},
		"state":                    {"rp-state"},
	}.Encode()
	confirmation := c.Get(t, "/logout?"+logoutQuery)
	confirmation.RequireStatus(t, 200).Contains(t, "Sign out")
	csrf := harness.FormValue(confirmation.Body, "csrf_token")
	require.NotEmpty(t, csrf)
	response = c.PostForm(t, "/logout?"+logoutQuery, url.Values{"csrf_token": {csrf}})
	response.RequireStatus(t, 303)
	require.Equal(
		t,
		"http://127.0.0.1:9999/callback?state=rp-state",
		response.Location(t).String(),
	)
	require.Empty(t, c.Cookie("zen_idp_session"))

	// An unregistered redirect URI is never followed: the logout
	// completes on the signed-out page.
	require.Equal(t, 303, login(t, c, query, "alice").Status)
	logoutQuery = url.Values{
		"id_token_hint":            {tokens.IDToken},
		"post_logout_redirect_uri": {"http://127.0.0.1:9999/evil"},
	}.Encode()
	confirmation = c.Get(t, "/logout?"+logoutQuery)
	confirmation.RequireStatus(t, 200)
	csrf = harness.FormValue(confirmation.Body, "csrf_token")
	require.NotEmpty(t, csrf)
	response = c.PostForm(t, "/logout?"+logoutQuery, url.Values{"csrf_token": {csrf}})
	response.RequireStatus(t, 200).Contains(t, "You have been signed out")
}
