// One complete product scenario: an RP-Initiated Logout. After signing in
// through the relying party, the client sends the browser to the issuer's
// end-session endpoint with the ID token it holds; the browser confirms
// the sign-out and returns to the client with the echoed state, and the
// revoked session can no longer start a new flow.

import { expect, test } from "@playwright/test";
import { testAdminHash, testRootSecret } from "./harness/credentials.ts";
import { deriveTOTPSecret, OIDCScenario, totpCode } from "./harness/index.ts";

test("an RP-initiated logout ends the session and returns to the client", async ({ page }) => {
  const testInfo = test.info();
  const scenario = await OIDCScenario.start({
    rootSecret: testRootSecret,
    client: { clientId: "public-app", name: "Public App" },
    config: {
      config: {
        ui: { name: "E2E Browser Test" },
        security: { admin_password_hash: testAdminHash },
      },
      users: [{ sub: "alice" }],
    },
  });

  const { harness, client } = scenario;

  try {
    // The user signs in through the client and the client holds the ID
    // token of the completed flow.
    await page.goto(`${client.baseURL}/start`);
    await page.getByLabel("Login identifier").fill("alice");
    await page.getByLabel("One-time code").fill(
      totpCode(await deriveTOTPSecret(testRootSecret, "alice", 0), new Date()),
    );
    await page.getByRole("button", { name: "Sign in" }).click();
    await expect(page.getByRole("heading", { name: "Signed in" })).toBeVisible({
      timeout: 10_000,
    });
    const session = await (await fetch(`${client.baseURL}/session`)).json() as {
      id_token: string;
    };

    // The client initiates the logout with the ID token it holds and a
    // fresh state.
    let logoutRequest: URL | undefined;
    page.on("request", (request) => {
      const url = new URL(request.url());
      if (url.origin === harness.baseURL && url.pathname === "/logout") {
        logoutRequest = url;
      }
    });
    await page.goto(`${client.baseURL}/logout`);
    await expect.poll(() => logoutRequest).toBeDefined();
    expect(logoutRequest!.searchParams.get("id_token_hint")).toBe(session.id_token);
    expect(logoutRequest!.searchParams.get("post_logout_redirect_uri")).toBe(
      client.logoutRedirectURI,
    );
    const state = logoutRequest!.searchParams.get("state");
    expect(state).not.toBeNull();

    // The sign-out confirmation renders and completes the logout.
    await expect(page).toHaveTitle(/Sign out/);
    await expect(page.getByText("End your session on this device?")).toBeVisible();
    await page.getByRole("button", { name: "Sign out" }).click();

    // The browser returns to the client with the echoed state.
    await expect(page.getByRole("heading", { name: "Signed out" })).toBeVisible();
    const returnURL = new URL(page.url());
    expect(returnURL.origin).toBe(client.baseURL);
    expect(returnURL.pathname).toBe("/logout-callback");
    expect(returnURL.searchParams.get("state")).toBe(state);

    // The session is gone: a new flow requires the login interaction.
    await page.goto(`${client.baseURL}/start`);
    expect(new URL(page.url()).pathname).toBe("/login");
  } finally {
    await scenario.dispose(testInfo);
  }
});
