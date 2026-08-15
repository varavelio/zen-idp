// One complete product scenario: the OIDC green path of a public client,
// walked in a real browser with a real relying party. The openid-client
// library drives the flow from an in-process Deno.serve server, exactly
// like an external application would: discovery, authorization, login with
// a derived TOTP code, code exchange with PKCE, ID token validation, and
// userinfo resolution.

import { expect } from "@playwright/test";
import { attachDiagnostics, test } from "./harness/fixtures.ts";
import { deriveTOTPSecret, Harness, totpCode } from "./harness/index.ts";
import { OIDCClientServer } from "./harness/oidcclient.ts";

// Shared fixtures of the browser suite. The hash is a precomputed
// Argon2id PHC value anchored in the HTTP suite.
const testRootSecret = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
const testAdminHash =
  "$argon2id$v=19$m=65536,t=2,p=2$INy39hwa9rMN8WhprspfDQ$45uH4EsaLtb2h9bUkVfgAAoLKsgPK1ALYprlwxm16B4";

test("walks the complete OIDC green path with a real client", async ({ page }) => {
  const testInfo = test.info();
  // The client binds its loopback port before the instance starts, so the
  // configuration can register its exact callback URI.
  const client = await OIDCClientServer.start({ clientId: "public-app" });
  const harness = await Harness.start({
    rootSecret: testRootSecret,
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
      clients: [{
        id: "public-app",
        name: "Public App",
        redirect_uris: [client.redirectURI],
      }],
    },
  });
  try {
    await client.connect(harness.baseURL);

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
    const code = totpCode(
      await deriveTOTPSecret(testRootSecret, "alice", 0),
      new Date(),
    );
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
    if (testInfo.status === "failed" || testInfo.status === "timedOut") {
      await attachDiagnostics(testInfo, harness);
    }
    await harness.stop();
    await client.stop();
  }
});
