// One complete product scenario: the confidential client. The relying
// party authenticates at the token endpoint with client_secret_basic, may
// omit PKCE entirely, and is rejected when it presents the wrong secret;
// the ID token is issued to the confidential client and userinfo resolves.

import { expect, test } from "@playwright/test";
import { testAdminHash, testClientHash, testClientSecret, testRootSecret } from "./harness/credentials.ts";
import { basicAuth, deriveTOTPSecret, OIDCScenario, totpCode } from "./harness/index.ts";

test("a confidential client authenticates with its secret", async ({ page }) => {
  const testInfo = test.info();
  const scenario = await OIDCScenario.start({
    rootSecret: testRootSecret,
    client: {
      clientId: "confidential-app",
      name: "Confidential App",
      secretHash: testClientHash,
      clientSecret: testClientSecret,
    },
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
    // The user signs in through the client, which authenticates the code
    // redemption with client_secret_basic and PKCE.
    await page.goto(`${client.baseURL}/start`);
    await page.getByLabel("Login identifier").fill("alice");
    await page.getByLabel("One-time code").fill(
      totpCode(await deriveTOTPSecret(testRootSecret, "alice", 0), new Date()),
    );
    await page.getByRole("button", { name: "Sign in" }).click();
    await expect(page.getByRole("heading", { name: "Signed in" })).toBeVisible({
      timeout: 10_000,
    });
    const idToken = JSON.parse(
      await page.locator("#idtoken").innerText(),
    ) as Record<string, unknown>;
    expect(idToken).toMatchObject({ iss: harness.baseURL, sub: "alice", aud: "confidential-app" });
    const userinfo = JSON.parse(
      await page.locator("#userinfo").innerText(),
    ) as Record<string, unknown>;
    expect(userinfo).toMatchObject({ sub: "alice" });

    // A confidential client may omit PKCE: the session authorizes a
    // second request without a code challenge, and the code redeems with
    // the secret alone.
    const query = new URLSearchParams({
      client_id: "confidential-app",
      redirect_uri: client.redirectURI,
      response_type: "code",
      scope: "openid",
      state: "state-123",
    });
    const captureCode = async (): Promise<string> => {
      const callback = page.waitForRequest(
        (request) => new URL(request.url()).pathname === "/callback",
      );
      await page.goto(`${harness.baseURL}/authorize?${query}`);
      const code = new URL((await callback).url()).searchParams.get("code");
      expect(code).toMatch(/^tok_/);
      return code!;
    };
    const code = await captureCode();

    // The wrong secret is rejected before any code is redeemed.
    const wrong = await harness.client.postFormAuth("/token", {
      grant_type: "authorization_code",
      code,
      redirect_uri: client.redirectURI,
      client_id: "confidential-app",
    }, basicAuth("confidential-app", "wrong-secret"));
    wrong.requireStatus(401);
    expect(wrong.json()).toMatchObject({ error: "invalid_client" });

    // The correct secret redeems a fresh code.
    const freshCode = await captureCode();
    const ok = await harness.client.postFormAuth("/token", {
      grant_type: "authorization_code",
      code: freshCode,
      redirect_uri: client.redirectURI,
      client_id: "confidential-app",
    }, basicAuth("confidential-app", testClientSecret));
    ok.requireStatus(200);
    const tokens = ok.json() as { id_token: string; access_token: string };
    expect(tokens.id_token).not.toBe("");
    expect(tokens.access_token).not.toBe("");
  } finally {
    await scenario.dispose(testInfo);
  }
});
