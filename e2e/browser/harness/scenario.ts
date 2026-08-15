// Orchestrates one OIDC scenario: a Zen IdP instance and the relying-party
// client server registered with it, so tests can drive complete flows in a
// real browser exactly like an external application would.

import type { TestInfo } from "@playwright/test";
import { type ClientConfig, type ConfigDocument } from "./config.ts";
import { attachDiagnostics } from "./diagnostics.ts";
import { Harness } from "./harness.ts";
import { OIDCClientServer } from "./oidcclient.ts";

/** The relying-party client of one scenario. */
export interface OIDCScenarioClient {
  /** OIDC client identifier registered in the instance configuration. */
  clientId: string;
  /** Optional human-readable display name. */
  name?: string;
  /** Optional Argon2id PHC hash that declares a confidential client. */
  secretHash?: string;
  /** Optional client secret used by openid-client to authenticate. */
  clientSecret?: string;
}

/** Options of one OIDC scenario. */
export interface OIDCScenarioOptions {
  /** Root secret of the instance; defaults to the harness default. */
  rootSecret?: string;
  /** The relying-party client served by openid-client. */
  client: OIDCScenarioClient;
  /**
   * The rest of the instance configuration. The client registration is
   * completed automatically with the client server's redirect URIs, so
   * the scenario client must not be declared in `clients`.
   */
  config: ConfigDocument;
}

/**
 * One running OIDC scenario: a Zen IdP instance and the relying-party
 * client server registered with it, already connected through discovery.
 */
export class OIDCScenario {
  private constructor(
    readonly harness: Harness,
    readonly client: OIDCClientServer,
  ) {}

  /** Starts the scenario: the client binds its loopback port first, the
   * instance registers its exact redirect URIs, and the client discovers
   * the instance. */
  static async start(options: OIDCScenarioOptions): Promise<OIDCScenario> {
    const client = OIDCClientServer.start({
      clientId: options.client.clientId,
      clientSecret: options.client.clientSecret,
    });
    try {
      const config = registerClient(options.config, options.client, client.redirectURIs);
      const harness = await Harness.start({ rootSecret: options.rootSecret, config });
      await client.connect(harness.baseURL);
      return new OIDCScenario(harness, client);
    } catch (error) {
      await client.stop();
      throw error;
    }
  }

  /**
   * Attaches the instance diagnostics to a failed test report and stops
   * both servers. Safe to call once at the end of every scenario test.
   */
  async dispose(testInfo: TestInfo): Promise<void> {
    if (testInfo.status === "failed" || testInfo.status === "timedOut") {
      await attachDiagnostics(testInfo, this.harness);
    }
    await this.harness.stop();
    await this.client.stop();
  }
}

/** Completes the configuration with the scenario client registered
 * against the client server's redirect URIs. */
function registerClient(
  config: ConfigDocument,
  client: OIDCScenarioClient,
  redirectURIs: string[],
): ConfigDocument {
  const declaration: ClientConfig = {
    id: client.clientId,
    ...(client.name === undefined ? {} : { name: client.name }),
    ...(client.secretHash === undefined ? {} : { secret_hash: client.secretHash }),
    redirect_uris: redirectURIs,
  };
  return {
    ...config,
    clients: [
      ...(config.clients ?? []).filter((entry) => entry.id !== client.clientId),
      declaration,
    ],
  };
}
