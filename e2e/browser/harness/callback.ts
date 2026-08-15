// A tiny loopback server that records the exact URL of every request it
// receives, so tests can capture authorization responses without a real
// relying party while the browser completes the flow naturally.

export class CallbackCatcher {
  /** Starts the catcher on a free loopback port. */
  static start(): CallbackCatcher {
    let instance: CallbackCatcher | null = null;
    const server = Deno.serve({ hostname: "127.0.0.1", port: 0 }, (request) => {
      if (instance === null) {
        throw new Error("CallbackCatcher not initialized");
      }
      return instance.#handle(request);
    });
    const baseURL = `http://127.0.0.1:${server.addr.port}`;
    instance = new CallbackCatcher(baseURL, server);
    return instance;
  }

  private constructor(
    readonly baseURL: string,
    private readonly server: Deno.HttpServer,
  ) {}

  /** The registered callback URI of this catcher. */
  get redirectURI(): string {
    return `${this.baseURL}/callback`;
  }

  /** Every request URL received so far, in arrival order. */
  readonly requests: URL[] = [];

  /** The complete URL of the most recent request received, if any. */
  get lastURL(): URL | null {
    return this.requests.at(-1) ?? null;
  }

  #stopped = false;

  /** Stops the catcher. Safe to call more than once. */
  async stop(): Promise<void> {
    if (!this.#stopped) {
      this.#stopped = true;
      await this.server.shutdown();
    }
  }

  #handle(request: Request): Response {
    this.requests.push(new URL(request.url));
    return new Response(
      `
        <!doctype html>
        <html lang="en">
          <head>
            <meta charset="utf-8">
            <title>Callback received</title>
          </head>
          <body>
            <h1>Callback received</h1>
          </body>
        </html>
      `,
      {
        headers: {
          "content-type": "text/html; charset=utf-8",
        },
      },
    );
  }
}
