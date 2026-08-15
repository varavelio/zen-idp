// One complete product scenario: the OIDC green path of a public client,
// walked in a real browser with a real relying party. The openid-client
// library drives the flow from an in-process Deno.serve server, exactly
// like an external application would: discovery, authorization, login with
// a derived TOTP code, code exchange with PKCE, ID token validation, and
// userinfo resolution.

import { expect, test } from "@playwright/test";
import { testAdminHash, testRootSecret } from "./harness/credentials.ts";
import { deriveTOTPSecret, OIDCScenario, totpCode } from "./harness/index.ts";

test("walks the complete OIDC green path with a real client", async ({ page }) => {
  const testInfo = test.info();
  const scenario = await OIDCScenario.start({
    rootSecret: testRootSecret,
    client: { clientId: "public-app", name: "Public App" },
    config: {
      config: {
        ui: { name: "E2E Browser Test" },
        security: { admin_password_hash: testAdminHash },
      },
      users: [{
        sub: "alice",
        name: "Alice Example",
        groups: ["engineering", "operators"],
      }],
    },
  });

  const { harness, client } = scenario;

  try {
    // Discovery advertises exactly the implemented behavior.
    const discovery = await harness.client.get("/.well-known/openid-configuration");
    discovery.requireStatus(200);
    expect(discovery.json()).toMatchObject({
      issuer: harness.baseURL,
      authorization_endpoint: `${harness.baseURL}/authorize`,
      token_endpoint: `${harness.baseURL}/token`,
    });

    // The browser begins the flow at the client and lands on the login
    // interaction with the pending authorization request.
    await page.goto(`${client.baseURL}/start`);
    const loginURL = new URL(page.url());
    expect(loginURL.origin).toBe(harness.baseURL);
    expect(loginURL.pathname).toBe("/login");
    await expect(page).toHaveTitle(/Sign in/);
    await expect(page.getByText("Sign in with your one-time code")).toBeVisible();

    // Signing in with the derived TOTP code returns the browser to the
    // client, which exchanges the code and renders the outcome.
    const code = totpCode(await deriveTOTPSecret(testRootSecret, "alice", 0), new Date());
    await page.getByLabel("Login identifier").fill("alice");
    await page.getByLabel("One-time code").fill(code);
    await page.getByRole("button", { name: "Sign in" }).click();

    await expect(page.getByRole("heading", { name: "Signed in" })).toBeVisible({
      timeout: 10_000,
    });
    expect(new URL(page.url()).origin).toBe(client.baseURL);

    // The ID token carries the protocol contract.
    const idToken = JSON.parse(
      await page.locator("#idtoken").innerText(),
    ) as Record<string, unknown>;
    expect(idToken).toMatchObject({
      iss: harness.baseURL,
      sub: "alice",
      aud: "public-app",
    });

    // The userinfo endpoint resolves the current claims of the subject.
    const userinfo = JSON.parse(
      await page.locator("#userinfo").innerText(),
    ) as Record<string, unknown>;
    expect(userinfo).toMatchObject({
      sub: "alice",
      name: "Alice Example",
      groups: ["engineering", "operators"],
    });
  } finally {
    await scenario.dispose(testInfo);
  }
});
