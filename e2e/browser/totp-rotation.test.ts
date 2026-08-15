// One complete product scenario: TOTP revision rotation. After the
// credential revision is incremented, the previous code is rejected with
// the generic failure, the previously authenticated session is revoked so
// SSO requires the login interaction again, and the code of the new
// revision signs the user in.

import { expect, type Page, test } from "@playwright/test";
import { calculatePKCECodeChallenge, randomPKCECodeVerifier } from "openid-client";
import { testAdminHash, testRootSecret } from "./harness/credentials.ts";
import { attachDiagnostics } from "./harness/diagnostics.ts";
import { CallbackCatcher, deriveTOTPSecret, Harness, totpCode } from "./harness/index.ts";

test("a rotated TOTP revision rejects old codes and revokes sessions", async ({ page }) => {
  const testInfo = test.info();
  const catcher = CallbackCatcher.start();
  const harness = await Harness.start({
    rootSecret: testRootSecret,
    config: {
      config: {
        ui: { name: "E2E Browser Test" },
        security: { admin_password_hash: testAdminHash },
      },
      users: [{ sub: "alice", idp_totp_rev: 0 }],
      clients: [{ id: "public-app", redirect_uris: [catcher.redirectURI] }],
    },
  });

  try {
    const verifier = randomPKCECodeVerifier();
    const query = new URLSearchParams({
      client_id: "public-app",
      redirect_uri: catcher.redirectURI,
      response_type: "code",
      scope: "openid",
      state: "state-123",
      nonce: "nonce-456",
      code_challenge: await calculatePKCECodeChallenge(verifier),
      code_challenge_method: "S256",
    });

    // The user signs in at revision 0 and the authorization flow
    // completes at the registered callback.
    await page.goto(`${harness.baseURL}/authorize?${query}`);
    await signIn(page, "alice", 0);
    await expect(page.getByRole("heading", { name: "Callback received" })).toBeVisible();
    expect(catcher.lastURL?.searchParams.get("code")).toMatch(/^tok_/);
    const cookies = await page.context().cookies(harness.baseURL);
    expect(cookies.some((cookie) => cookie.name === "zen_idp_session")).toBe(true);

    // The credential is rotated and the instance restarts with the new
    // configuration, keeping the state database.
    await harness.reconfigure({
      config: {
        ui: { name: "E2E Browser Test" },
        security: { admin_password_hash: testAdminHash },
      },
      users: [{ sub: "alice", idp_totp_rev: 1 }],
      clients: [{ id: "public-app", redirect_uris: [catcher.redirectURI] }],
    });

    // The previously authenticated session is revoked: the SSO request
    // requires the login interaction again.
    await page.goto(`${harness.baseURL}/authorize?${query}`);
    expect(new URL(page.url()).pathname).toBe("/login");

    // The previous code is rejected with the single generic failure.
    await signIn(page, "alice", 0);
    await expect(page.getByText("Sign-in failed")).toBeVisible();

    // The code of the new revision signs the user in.
    const before = catcher.requests.length;
    await signIn(page, "alice", 1);
    await expect.poll(() => catcher.requests.length).toBe(before + 1);
    expect(catcher.lastURL?.searchParams.get("code")).toMatch(/^tok_/);
  } finally {
    if (testInfo.status === "failed" || testInfo.status === "timedOut") {
      await attachDiagnostics(testInfo, harness);
    }
    await harness.stop();
    await catcher.stop();
  }
});

/** Fills the login form with the given identifier and the TOTP code of
 * the given revision, and submits it. */
async function signIn(page: Page, identifier: string, revision: number): Promise<void> {
  await page.getByLabel("Login identifier").fill(identifier);
  await page.getByLabel("One-time code").fill(
    totpCode(await deriveTOTPSecret(testRootSecret, identifier, revision), new Date()),
  );
  await page.getByRole("button", { name: "Sign in" }).click();
}
