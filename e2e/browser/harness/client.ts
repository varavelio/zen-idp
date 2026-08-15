// A browser-like HTTP client with a cookie jar that never follows
// redirects, so tests can inspect every redirect target and cookie
// decision, mirroring the e2e/http/harness Go package.

/** One complete HTTP response of a harness client. */
export class Response {
  /**
   * Creates the response wrapper of one exchange. The base URL resolves
   * relative Location headers against the instance origin.
   */
  constructor(
    readonly status: number,
    readonly headers: Headers,
    readonly body: Uint8Array,
    baseURL: string,
  ) {
    this.#baseURL = baseURL;
  }

  readonly #baseURL: string;

  /** Decodes the response body as text. */
  text(): string {
    return new TextDecoder().decode(this.body);
  }

  /** Decodes the response body as JSON. */
  json(): unknown {
    return JSON.parse(this.text());
  }

  /** Fails the test unless the response carries the given status code. */
  requireStatus(want: number): this {
    if (this.status !== want) {
      throw new Error(`status = ${this.status}, want ${want} (body: ${this.text()})`);
    }
    return this;
  }

  /** Returns the parsed redirect target of the response. */
  location(): URL {
    const target = this.headers.get("location");
    if (target === null) {
      throw new Error(`response carries no Location header (status ${this.status})`);
    }
    return new URL(target, this.#baseURL);
  }

  /** Fails the test unless the response body contains the given fragment. */
  contains(fragment: string): this {
    if (!this.text().includes(fragment)) {
      throw new Error(
        `response body does not contain ${JSON.stringify(fragment)} (body: ${this.text()})`,
      );
    }
    return this;
  }

  /** Fails the test unless the response body omits the given fragment. */
  notContains(fragment: string): this {
    if (this.text().includes(fragment)) {
      throw new Error(
        `response body contains ${JSON.stringify(fragment)} (body: ${this.text()})`,
      );
    }
    return this;
  }

  /** Returns the raw Set-Cookie header of the response, if any. */
  setCookie(): string | undefined {
    return this.headers.getSetCookie()[0];
  }
}

/** Options of one client request. */
interface RequestOptions {
  headers?: Record<string, string>;
  body?: string;
}

/**
 * HTTP client with a browser-like cookie jar that never follows redirects.
 * The jar is created once and shared across instance restarts, so browser
 * state observed before a restart survives it.
 */
export class Client {
  /** Creates a client for the given instance origin. */
  constructor(baseURL: string) {
    this.#origin = baseURL;
  }

  readonly #origin: string;
  readonly #cookies = new Map<string, string>();

  /** Returns the value of the named cookie held by this client, if any. */
  cookie(name: string): string | undefined {
    return this.#cookies.get(name);
  }

  /** Issues a GET request against the given path of the instance origin. */
  get(path: string, headers: Record<string, string> = {}): Promise<Response> {
    return this.request("GET", path, { headers });
  }

  /** Issues a GET request carrying the given Authorization header value. */
  getAuth(
    path: string,
    authorization: string,
    headers: Record<string, string> = {},
  ): Promise<Response> {
    return this.request("GET", path, { headers: { Authorization: authorization, ...headers } });
  }

  /** Issues a POST request with the given form values. */
  postForm(
    path: string,
    form: Record<string, string>,
    headers: Record<string, string> = {},
  ): Promise<Response> {
    return this.request("POST", path, {
      headers: { "Content-Type": "application/x-www-form-urlencoded", ...headers },
      body: new URLSearchParams(form).toString(),
    });
  }

  /**
   * Issues a POST request with the given form values and Authorization
   * header value.
   */
  postFormAuth(
    path: string,
    form: Record<string, string>,
    authorization: string,
  ): Promise<Response> {
    return this.postForm(path, form, { Authorization: authorization });
  }

  /** Issues a POST request with a raw form-encoded body. */
  postRaw(path: string, body: string): Promise<Response> {
    return this.request("POST", path, {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
    });
  }

  /** Issues one request and reads its complete response. */
  async request(method: string, path: string, options: RequestOptions = {}): Promise<Response> {
    const headers = new Headers(options.headers);
    const cookieHeader = [...this.#cookies].map(([name, value]) => `${name}=${value}`).join("; ");
    if (cookieHeader !== "") {
      headers.set("cookie", cookieHeader);
    }
    const raw = await fetch(this.#origin + path, {
      method,
      headers,
      body: options.body,
      redirect: "manual",
    });
    for (const setCookie of raw.headers.getSetCookie()) {
      const [name, ...rest] = setCookie.split("=");
      if (name === undefined) {
        continue;
      }
      const value = rest.join("=").split(";")[0] ?? "";
      this.#cookies.set(name.trim(), value.trim());
    }
    const body = new Uint8Array(await raw.arrayBuffer());
    return new Response(raw.status, raw.headers, body, this.#origin);
  }
}
