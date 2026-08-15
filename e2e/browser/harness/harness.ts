// Drives one isolated black-box Zen IdP instance for a single test: a
// dedicated configuration and state database in a per-test directory, one
// loopback port, and one spawned server process. Every instance is fully
// independent, so any number of tests can run in parallel without
// colliding, mirroring the e2e/http/harness Go package.

import { assertBinary, binaryPath } from "./binary.ts";
import { Client } from "./client.ts";
import { buildConfigDocument, type ConfigDocument, dumpYaml, validateConfig } from "./config.ts";

/** How long a spawned server may take to answer its first discovery
 * request before the test fails. */
const readinessTimeoutMs = 15_000;

/** How long a stopped server may take to exit after its termination
 * signal before it is killed. */
const shutdownTimeoutMs = 10_000;

/** How long to wait between readiness probes. */
const probeIntervalMs = 100;

/**
 * Root secret of instances that do not declare one. It satisfies the
 * service minimum length and stays stable, so tests can derive TOTP
 * secrets from it.
 */
export const defaultRootSecret = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

/** Options that describe one black-box instance. */
export interface HarnessOptions {
  /**
   * The YAML configuration document of the instance. The harness fills
   * the issuer and listener settings itself.
   */
  config: ConfigDocument;
  /** Root secret used as ZEN_IDP_SECRET; defaults to defaultRootSecret. */
  rootSecret?: string;
  /** Extra environment variables for the server process. */
  env?: Record<string, string>;
}

/**
 * Drives one isolated black-box Zen IdP instance for a single test: a
 * dedicated configuration and state database in a per-test directory, one
 * loopback port, and one spawned server process.
 */
export class Harness {
  /**
   * Starts a fresh instance for one test: allocates a per-test directory
   * and loopback port, writes the configuration, spawns the compiled
   * executable, and waits until the discovery endpoint answers. It stops
   * the instance and removes its directory when the process fails to
   * start, and the caller must eventually call stop.
   */
  static async start(options: HarnessOptions): Promise<Harness> {
    assertBinary();
    validateConfig(options.config);
    const dir = await Deno.makeTempDir({ prefix: "zen-idp-e2e-" });
    const port = freePort();
    const baseURL = `http://127.0.0.1:${port}`;
    const harness = new Harness(
      dir,
      baseURL,
      port,
      options.rootSecret ?? defaultRootSecret,
      options.env,
    );
    try {
      await harness.writeConfig(options.config);
      harness.startProcess();
      await harness.waitReady();
    } catch (error) {
      await harness.stop();
      throw error;
    }
    return harness;
  }

  private constructor(
    readonly dir: string,
    readonly baseURL: string,
    readonly port: number,
    readonly rootSecret: string,
    env: Record<string, string> | undefined,
  ) {
    this.#env = env;
    this.client = new Client(baseURL);
  }

  /**
   * HTTP client of this instance. Its cookie jar is created once and
   * shared across restarts, so browser state observed before a restart
   * survives it.
   */
  readonly client: Client;

  readonly #env: Record<string, string> | undefined;
  #process: Deno.ChildProcess | null = null;
  #logChunks: Uint8Array[] = [];

  /**
   * Stops the server and removes the instance directory. Safe to call
   * more than once.
   */
  async stop(): Promise<void> {
    await this.stopProcess();
    await Deno.remove(this.dir, { recursive: true }).catch(() => {});
  }

  /**
   * Stops the server and starts it again with the same configuration and
   * state database, simulating an ordinary service restart.
   */
  async restart(): Promise<void> {
    await this.stopProcess();
    this.startProcess();
    await this.waitReady();
  }

  /**
   * Stops the server, replaces the instance configuration, and starts
   * again with the same state database and listener port, simulating a
   * configuration change followed by a restart.
   */
  async reconfigure(config: ConfigDocument): Promise<void> {
    validateConfig(config);
    await this.stopProcess();
    await this.writeConfig(config);
    this.startProcess();
    await this.waitReady();
  }

  /**
   * Stops the server, removes the state database, and starts again with a
   * fresh one, simulating state-file loss followed by a restart.
   */
  async resetState(): Promise<void> {
    await this.stopProcess();
    for (const name of ["state.db", "state.db-wal", "state.db-shm"]) {
      await Deno.remove(`${this.dir}/${name}`).catch(() => {});
    }
    this.startProcess();
    await this.waitReady();
  }

  /** Returns the captured output of the server process. */
  serverLog(): string {
    return new TextDecoder().decode(concatChunks(this.#logChunks));
  }

  /** Returns the YAML configuration of the instance. */
  async configYaml(): Promise<string> {
    try {
      return await Deno.readTextFile(`${this.dir}/config.yaml`);
    } catch {
      return "(configuration unavailable)";
    }
  }

  /** Writes the instance configuration with the harness-owned settings. */
  private async writeConfig(config: ConfigDocument): Promise<void> {
    const document = buildConfigDocument(config, this.baseURL, this.port);
    await Deno.writeTextFile(`${this.dir}/config.yaml`, dumpYaml(document));
  }

  /** Spawns the server process with this instance's configuration. */
  private startProcess(): void {
    this.#logChunks = [];
    const command = new Deno.Command(binaryPath, {
      args: ["serve"],
      cwd: this.dir,
      env: {
        ZEN_IDP_CONFIG_PATH: `${this.dir}/config.yaml`,
        ZEN_IDP_SECRET: this.rootSecret,
        ZEN_IDP_DB_PATH: `${this.dir}/state.db`,
        ...this.#env,
      },
      stdout: "piped",
      stderr: "piped",
    });
    const process = command.spawn();
    this.#process = process;
    // Both streams share one log: each chunk is appended as it arrives,
    // and failures after the process exits are ignored.
    for (const stream of [process.stdout, process.stderr]) {
      stream.pipeTo(
        new WritableStream<Uint8Array>({
          write: (chunk) => {
            this.#logChunks.push(chunk);
          },
        }),
      ).catch(() => {});
    }
  }

  /**
   * Terminates the server gracefully and waits for it to exit, killing it
   * when it does not stop in time.
   */
  private async stopProcess(): Promise<void> {
    if (this.#process !== null) {
      const process = this.#process;
      this.#process = null;
      try {
        process.kill("SIGTERM");
      } catch {
        // The process already exited.
      }
      const exited = await Promise.race([
        process.status.then(() => true),
        delay(shutdownTimeoutMs).then(() => false),
      ]);
      if (!exited) {
        try {
          process.kill("SIGKILL");
        } catch {
          // The process already exited.
        }
        await process.status;
      }
    }
  }

  /**
   * Polls the discovery endpoint until it answers with 200, failing fast
   * with the server output when the process dies before becoming ready.
   */
  private async waitReady(): Promise<void> {
    const deadline = Date.now() + readinessTimeoutMs;
    while (Date.now() < deadline) {
      try {
        const response = await fetch(
          `${this.baseURL}/.well-known/openid-configuration`,
          { signal: AbortSignal.timeout(1_000) },
        );
        if (response.status === 200) {
          await response.arrayBuffer();
          return;
        }
      } catch {
        // Not ready yet.
      }
      if (await this.processExited()) {
        throw new Error(`server exited before becoming ready:\n${this.serverLog()}`);
      }
    }
    throw new Error(`server did not become ready:\n${this.serverLog()}`);
  }

  /** Reports whether the server process has already exited. */
  private async processExited(): Promise<boolean> {
    const process = this.#process;
    if (process === null) {
      return false;
    }
    return await Promise.race([
      process.status.then(() => true),
      delay(probeIntervalMs).then(() => false),
    ]);
  }
}

/** Returns a free loopback TCP port for the server to bind. */
function freePort(): number {
  const listener = Deno.listen({ hostname: "127.0.0.1", port: 0 });
  const port = (listener.addr as Deno.NetAddr).port;
  listener.close();
  return port;
}

/** Concatenates byte chunks into one byte array. */
function concatChunks(chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }
  return result;
}

/** Resolves after the given number of milliseconds. */
function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}
