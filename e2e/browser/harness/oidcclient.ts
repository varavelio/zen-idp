// A small OIDC relying party built on the openid-client library. It binds
// a loopback port and serves the authorization-flow endpoints of an
// external application, so tests can drive complete flows in a real
// browser exactly like a third-party client would: login, RP-Initiated
// Logout, and the session the client holds in between.

import {
  allowInsecureRequests,
  authorizationCodeGrant,
  buildAuthorizationUrl,
  calculatePKCECodeChallenge,
  ClientSecretBasic,
  type Configuration,
  discovery,
  fetchUserInfo,
  None,
  randomNonce,
  randomPKCECodeVerifier,
  randomState,
} from "openid-client";

/** Options of one OIDC client server. */
export interface OIDCClientServerOptions {
  /** OIDC client identifier registered in the issuer configuration. */
  clientId: string;
  /** Optional client secret that turns the client confidential. */
  clientSecret?: string;
}

/** The outcome of one completed authorization flow. */
export interface OIDCSession {
  /** Claims resolved from the userinfo endpoint. */
  userinfo: Record<string, unknown>;
  /** Claims of the validated ID token. */
  idTokenClaims: Record<string, unknown>;
}

/**
 * Drives the flows of one OIDC client as an external application would:
 * /start begins an authorization flow with fresh PKCE, state, and nonce
 * and redirects the browser to the issuer; /callback exchanges the
 * returned code, validates the tokens, resolves userinfo, and renders the
 * outcome; /logout begins an RP-Initiated Logout with the ID token the
 * client holds; /logout-callback renders the return of that logout; and
 * /session exposes the raw ID token of the last completed flow.
 */
export class OIDCClientServer {
  /** Starts the client on a free loopback port. */
  static start(options: OIDCClientServerOptions): OIDCClientServer {
    let instance: OIDCClientServer | null = null;
    const server = Deno.serve({ hostname: "127.0.0.1", port: 0 }, (request) => {
      if (instance === null) {
        throw new Error("OIDC client server not initialized");
      }
      return instance.#handle(request);
    });
    const baseURL = `http://127.0.0.1:${server.addr.port}`;
    instance = new OIDCClientServer(baseURL, options.clientId, options.clientSecret, server);
    return instance;
  }

  private constructor(
    readonly baseURL: string,
    clientId: string,
    clientSecret: string | undefined,
    server: Deno.HttpServer,
  ) {
    this.#clientId = clientId;
    this.#clientSecret = clientSecret;
    this.#server = server;
  }

  /** The registered callback URI where authorization flows return. */
  get redirectURI(): string {
    return `${this.baseURL}/callback`;
  }

  /** The registered callback URI where RP-Initiated Logout returns. */
  get logoutRedirectURI(): string {
    return `${this.baseURL}/logout-callback`;
  }

  /** Every registered redirect URI of this client. */
  get redirectURIs(): string[] {
    return [this.redirectURI, this.logoutRedirectURI];
  }

  readonly #clientId: string;
  readonly #clientSecret: string | undefined;
  readonly #server: Deno.HttpServer;
  #config: Configuration | null = null;
  readonly #pending = new Map<string, { codeVerifier: string; nonce: string }>();
  #session: { idToken: string } | null = null;
  #stopped = false;

  /**
   * Discovers the issuer and builds the client configuration from its
   * metadata. The loopback issuer is plain HTTP, which the library only
   * accepts when explicitly allowed.
   */
  async connect(issuerURL: string): Promise<void> {
    const clientAuthentication = this.#clientSecret === undefined
      ? None()
      : ClientSecretBasic(this.#clientSecret);
    this.#config = await discovery(
      new URL(issuerURL),
      this.#clientId,
      { redirect_uris: this.redirectURIs },
      clientAuthentication,
      { execute: [allowInsecureRequests] },
    );
  }

  /** Stops the client server. Safe to call more than once. */
  async stop(): Promise<void> {
    if (!this.#stopped) {
      this.#stopped = true;
      await this.#server.shutdown();
    }
  }

  #handle(request: Request): Response | Promise<Response> {
    const url = new URL(request.url);
    switch (url.pathname) {
      case "/start":
        return this.#handleStart();
      case "/callback":
        return this.#handleCallback(url);
      case "/logout":
        return this.#handleLogout();
      case "/logout-callback":
        return this.#handleLogoutCallback(url);
      case "/session":
        return this.#handleSession();
      default:
        return new Response("not found", { status: 404 });
    }
  }

  /** Begins an authorization flow with fresh PKCE, state, and nonce. */
  async #handleStart(): Promise<Response> {
    const config = this.#requireConfig();
    const codeVerifier = randomPKCECodeVerifier();
    const state = randomState();
    const nonce = randomNonce();
    this.#pending.set(state, { codeVerifier, nonce });
    const authorizationURL = buildAuthorizationUrl(config, {
      redirect_uri: this.redirectURI,
      scope: "openid",
      state,
      nonce,
      code_challenge: await calculatePKCECodeChallenge(codeVerifier),
      code_challenge_method: "S256",
    });
    return Response.redirect(authorizationURL, 302);
  }

  /**
   * Exchanges the returned code, validates the tokens, resolves userinfo,
   * stores the client session, and renders the outcome.
   */
  async #handleCallback(url: URL): Promise<Response> {
    const config = this.#requireConfig();
    const state = url.searchParams.get("state");
    if (state === null) {
      return new Response("missing authorization state", { status: 400 });
    }
    const pending = this.#pending.get(state);
    if (pending === undefined) {
      return new Response("unknown authorization state", { status: 400 });
    }
    this.#pending.delete(state);
    const tokens = await authorizationCodeGrant(config, url, {
      pkceCodeVerifier: pending.codeVerifier,
      expectedState: state,
      expectedNonce: pending.nonce,
    });
    const idToken = tokens.id_token;
    const idTokenClaims = tokens.claims();
    if (idToken === undefined || idTokenClaims === undefined) {
      throw new Error("authorization response carried no ID token");
    }
    this.#session = { idToken };
    const userinfo = await fetchUserInfo(config, tokens.access_token, idTokenClaims.sub);
    return new Response(renderSession(idTokenClaims, userinfo), {
      headers: { "content-type": "text/html; charset=utf-8" },
    });
  }

  /**
   * Begins an RP-Initiated Logout with the ID token the client holds,
   * redirecting the browser to the issuer's end-session endpoint.
   */
  #handleLogout(): Response {
    const config = this.#requireConfig();
    if (this.#session === null) {
      return new Response("no active client session", { status: 400 });
    }
    const endSession = config.serverMetadata().end_session_endpoint;
    if (endSession === undefined) {
      throw new Error("issuer does not advertise an end-session endpoint");
    }
    const logoutURL = new URL(endSession);
    logoutURL.searchParams.set("id_token_hint", this.#session.idToken);
    logoutURL.searchParams.set("post_logout_redirect_uri", this.logoutRedirectURI);
    logoutURL.searchParams.set("state", randomState());
    return Response.redirect(logoutURL, 302);
  }

  /** Renders the return of an RP-Initiated Logout with the echoed state. */
  #handleLogoutCallback(url: URL): Response {
    return new Response(renderLogoutReturn(url.searchParams.get("state") ?? ""), {
      headers: { "content-type": "text/html; charset=utf-8" },
    });
  }

  /** Returns the raw ID token of the last completed flow. */
  #handleSession(): Response {
    if (this.#session === null) {
      return new Response("no active client session", { status: 404 });
    }
    return new Response(JSON.stringify({ id_token: this.#session.idToken }), {
      headers: { "content-type": "application/json" },
    });
  }

  #requireConfig(): Configuration {
    if (this.#config === null) {
      throw new Error("OIDC client server is not connected to an issuer");
    }
    return this.#config;
  }
}

/** Renders the outcome of one authorization flow as a result page. */
function renderSession(
  idTokenClaims: Record<string, unknown>,
  userinfo: Record<string, unknown>,
): string {
  const idTokenJSON = escapeHTML(JSON.stringify(idTokenClaims, null, 2));
  const userinfoJSON = escapeHTML(JSON.stringify(userinfo, null, 2));
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>OIDC client</title>
</head>
<body>
  <h1>Signed in</h1>
  <pre id="idtoken">${idTokenJSON}</pre>
  <pre id="userinfo">${userinfoJSON}</pre>
</body>
</html>`;
}

/** Renders the return of an RP-Initiated Logout. */
function renderLogoutReturn(state: string): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>OIDC client</title>
</head>
<body>
  <h1>Signed out</h1>
  <pre id="state">${escapeHTML(state)}</pre>
</body>
</html>`;
}

/** Escapes the HTML-significant characters of a text fragment. */
function escapeHTML(value: string): string {
  return value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
