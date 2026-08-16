// One complete product scenario: the enrollment journey. An administrator
// signs in and creates a one-use enrollment token for a declared user; the
// user redeems the token in a fresh browser, reveals the deterministic
// TOTP secret with its QR code, and is denied on replay; and the user
// signs in with the revealed secret.

import { expect, test } from "@playwright/test";
import { calculatePKCECodeChallenge, randomPKCECodeVerifier } from "openid-client";
import { testAdminHash, testAdminPassword, testRootSecret } from "./harness/credentials.ts";
import { attachDiagnostics } from "./harness/diagnostics.ts";
import { CallbackCatcher, deriveTOTPSecret, findOTPAuthSecret, findToken, Harness, totpCode } from "./harness/index.ts";

test("a user enrolls through the one-use token journey", async ({ page, browser }) => {
  const testInfo = test.info();
  const catcher = CallbackCatcher.start();
  const harness = await Harness.start({
    rootSecret: testRootSecret,
    config: {
      config: {
        ui: { name: "E2E Browser Test" },
        security: { admin_password_hash: testAdminHash },
      },
      users: [{ sub: "alice", name: "Alice Example" }],
      clients: [{ id: "public-app", redirect_uris: [catcher.redirectURI] }],
    },
  });

  try {
    // An administrator signs in.
    await page.goto(`${harness.baseURL}/admin`);
    await expect(page.getByText("Administrator sign-in")).toBeVisible();
    await page.getByLabel("Administrator password").fill(testAdminPassword);
    await page.getByRole("button", { name: "Sign in" }).click();

    // Creates a one-use enrollment token.
    await expect(page.getByRole("button", { name: "Enrollment link" })).toBeVisible();
    await page.getByRole("button", { name: "Enrollment link" }).click();
    await page.getByRole("button", { name: "Create link" }).click();
    await expect(page.getByText("Enrollment token created.")).toBeVisible();
    const token = findToken(await page.locator("body").innerText());
    expect(token).toMatch(/^tok_/);

    // The user redeems the token in a fresh browser page and reveals the
    // deterministic TOTP secret with its QR code.
    const userPage = await browser.newPage();
    await userPage.goto(`${harness.baseURL}/enroll?token=${token}`);
    await expect(userPage.getByText("Set up your authenticator app")).toBeVisible();
    await userPage.getByRole("button", { name: "Show QR" }).click();
    await expect(userPage.getByText("Scan the code with your authenticator app")).toBeVisible();
    await expect(userPage.locator("img[alt=\"TOTP enrollment QR code\"]")).toBeVisible();
    await expect(userPage.locator("img[src^=\"data:image/png;base64,\"]")).toBeVisible();

    // The manual entry values mirror the QR code exactly: the account
    // name and the RFC 6238 profile, without the raw otpauth URI.
    await expect(userPage.getByText("Or configure manually")).toBeVisible();
    await expect(userPage.getByText("E2E Browser Test: alice")).toBeVisible();
    await expect(userPage.getByText("SHA1")).toBeVisible();
    expect(await userPage.content()).not.toContain("otpauth://");
    expect(findOTPAuthSecret(await userPage.content())).toBe(
      await deriveTOTPSecret(testRootSecret, "alice", 0),
    );

    // The one-use token is consumed: a second redemption is denied.
    await userPage.goto(`${harness.baseURL}/enroll?token=${token}`);
    await userPage.getByRole("button", { name: "Show QR" }).click();
    await expect(
      userPage.getByText("This enrollment link is invalid or has expired."),
    ).toBeVisible();

    // The user signs in with the revealed secret and the authorization
    // flow completes at the registered callback with a fresh code.
    const codeVerifier = randomPKCECodeVerifier();
    const query = new URLSearchParams({
      client_id: "public-app",
      redirect_uri: catcher.redirectURI,
      response_type: "code",
      scope: "openid",
      state: "state-123",
      nonce: "nonce-456",
      code_challenge: await calculatePKCECodeChallenge(codeVerifier),
      code_challenge_method: "S256",
    });
    await userPage.goto(`${harness.baseURL}/authorize?${query}`);
    await userPage.getByLabel("Login identifier").fill("alice");
    await userPage.getByLabel("One-time code").fill(
      totpCode(await deriveTOTPSecret(testRootSecret, "alice", 0), new Date()),
    );
    await userPage.getByRole("button", { name: "Sign in" }).click();
    await expect(userPage.getByRole("heading", { name: "Callback received" })).toBeVisible();
    expect(catcher.lastURL?.searchParams.get("code")).toMatch(/^tok_/);
    const cookies = await userPage.context().cookies(harness.baseURL);
    expect(cookies.some((cookie) => cookie.name === "zen_idp_session")).toBe(true);
  } finally {
    if (testInfo.status === "failed" || testInfo.status === "timedOut") {
      await attachDiagnostics(testInfo, harness);
    }
    await harness.stop();
    await catcher.stop();
  }
});
