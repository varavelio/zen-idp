// One complete product scenario: PKCE S256 enforcement for public
// clients. Authorization requests without a code challenge or with the
// forbidden plain method are rejected with an OIDC error redirect, and a
// code bound to a PKCE challenge never redeems with the wrong verifier.

import { expect, test } from "@playwright/test";
import { calculatePKCECodeChallenge, randomPKCECodeVerifier } from "openid-client";
import { testAdminHash, testRootSecret } from "./harness/credentials.ts";
import { attachDiagnostics } from "./harness/diagnostics.ts";
import { CallbackCatcher, deriveTOTPSecret, formValue, Harness, totpCode } from "./harness/index.ts";

test("PKCE S256 is enforced for public clients", async ({ page }) => {
  const testInfo = test.info();
  const catcher = CallbackCatcher.start();
  const harness = await Harness.start({
    rootSecret: testRootSecret,
    config: {
      config: {
        ui: { name: "E2E Browser Test" },
        security: { admin_password_hash: testAdminHash },
      },
      users: [{ sub: "alice" }],
      clients: [{ id: "public-app", redirect_uris: [catcher.redirectURI] }],
    },
  });
  try {
    const query = new URLSearchParams({
      client_id: "public-app",
      redirect_uri: catcher.redirectURI,
      response_type: "code",
      scope: "openid",
      state: "state-123",
      nonce: "nonce-456",
    });

    // Every rejected authorization redirects to the registered callback
    // with the OIDC error and the echoed state, never to an
    // attacker-controlled target.
    const expectDenial = async (params: URLSearchParams): Promise<void> => {
      const before = catcher.requests.length;
      await page.goto(`${harness.baseURL}/authorize?${params}`);
      await expect.poll(() => catcher.requests.length).toBe(before + 1);
      expect(catcher.lastURL!.origin).toBe(catcher.baseURL);
      expect(catcher.lastURL!.pathname).toBe("/callback");
      expect(catcher.lastURL!.searchParams.get("error")).toBe("invalid_request");
      expect(catcher.lastURL!.searchParams.get("state")).toBe("state-123");
    };

    // A public client without a code challenge is rejected.
    await expectDenial(query);

    // The forbidden plain method is rejected.
    const plain = new URLSearchParams(query);
    plain.set("code_challenge", "plain-challenge-value");
    plain.set("code_challenge_method", "plain");
    await expectDenial(plain);

    // A valid S256 flow signs in and issues a code bound to the
    // challenge.
    const verifier = randomPKCECodeVerifier();
    query.set("code_challenge", await calculatePKCECodeChallenge(verifier));
    query.set("code_challenge_method", "S256");
    const code = await loginAndGetCode(harness, query, "alice");

    // The code never redeems with the wrong verifier.
    const wrong = await harness.client.postForm("/token", {
      grant_type: "authorization_code",
      code,
      redirect_uri: catcher.redirectURI,
      client_id: "public-app",
      code_verifier: "x".repeat(43),
    });
    wrong.requireStatus(400);
    expect(wrong.json()).toMatchObject({ error: "invalid_grant" });

    // The correct verifier redeems the fresh code.
    const freshCode = await loginAndGetCode(harness, query, "alice");
    const ok = await harness.client.postForm("/token", {
      grant_type: "authorization_code",
      code: freshCode,
      redirect_uri: catcher.redirectURI,
      client_id: "public-app",
      code_verifier: verifier,
    });
    ok.requireStatus(200);
    const tokens = ok.json() as { id_token: string; access_token: string };
    expect(tokens.id_token).not.toBe("");
    expect(tokens.access_token).not.toBe("");
  } finally {
    if (testInfo.status === "failed" || testInfo.status === "timedOut") {
      await attachDiagnostics(testInfo, harness);
    }
    await harness.stop();
    await catcher.stop();
  }
});

/** Signs the given identifier in and returns the fresh authorization
 * code of the pending request. */
async function loginAndGetCode(
  harness: Harness,
  query: URLSearchParams,
  identifier: string,
): Promise<string> {
  // The login form echoes the anti-forgery token of the browser jar;
  // fetching it first stores the matching cookie.
  const form = await harness.client.get(`/login?${query}`);
  form.requireStatus(200);
  const csrfToken = formValue(form.text(), "csrf_token");
  expect(csrfToken).toBeDefined();
  const code = totpCode(await deriveTOTPSecret(testRootSecret, identifier, 0), new Date());
  (await harness.client.postForm(`/login?${query}`, {
    identifier,
    code,
    csrf_token: csrfToken!,
  })).requireStatus(303);
  const callback = await harness.client.get(`/authorize?${query}`);
  callback.requireStatus(302);
  const authCode = callback.location().searchParams.get("code");
  expect(authCode).toMatch(/^tok_/);
  return authCode!;
}
