// The YAML configuration document of one black-box instance.

import { stringify } from "@std/yaml";

/** One declared OIDC client of an instance. An omitted secret_hash
 * declares a public client. */
export interface ClientConfig {
  /** Unique OIDC client identifier. */
  id: string;
  /** Optional human-readable display name; defaults to id. */
  name?: string;
  /** Optional Argon2id PHC hash that declares a confidential client. */
  secret_hash?: string;
  /** Registered exact callback URIs. */
  redirect_uris: string[];
}

/** One declared identity with optional custom OIDC claims. */
export interface UserConfig {
  /** Stable OIDC subject. */
  sub: string;
  /** Optional additional login identifier. */
  idp_login?: string;
  /** Optional TOTP credential revision; defaults to 0. */
  idp_totp_rev?: number;
  /** Optional absolute expiration as a quoted RFC3339 timestamp. */
  idp_expires_at?: string;
  /** Any additional fields are custom OIDC claims. */
  [claim: string]: unknown;
}

/**
 * The YAML configuration document of one instance. The harness owns the
 * `issuer` and `server` fields, which it fills automatically; every other
 * field maps to the service configuration, and unknown keys pass through
 * untouched, so any configuration option can be exercised.
 */
export interface ConfigDocument {
  config: {
    /** Required Argon2id PHC hash of the administrator password. */
    security: {
      admin_password_hash: string;
      [key: string]: unknown;
    };
    /** Optional presentation settings. */
    ui?: Record<string, unknown>;
    [key: string]: unknown;
  };
  /** Optional declared OIDC clients. */
  clients?: ClientConfig[];
  /** Optional declared identities. */
  users?: UserConfig[];
  [key: string]: unknown;
}

/**
 * Fails fast when the configuration cannot produce a usable instance, so
 * failures point at the test data instead of the server.
 */
export function validateConfig(config: ConfigDocument): void {
  const adminHash = config.config?.security?.admin_password_hash;
  if (typeof adminHash !== "string" || adminHash === "") {
    throw new Error("harness: configuration needs config.security.admin_password_hash");
  }
  for (const client of config.clients ?? []) {
    if (client.id === "" || client.redirect_uris.length === 0) {
      throw new Error(`harness: client ${JSON.stringify(client.id)} needs an id and at least one redirect URI`);
    }
  }
  for (const user of config.users ?? []) {
    if (user.sub === "") {
      throw new Error("harness: every user needs a sub");
    }
  }
}

/**
 * Completes the given configuration with the harness-owned listener and
 * issuer settings and returns the final document of one instance. The
 * listener settings always win so every instance stays isolated on its own
 * loopback port.
 */
export function buildConfigDocument(
  config: ConfigDocument,
  baseURL: string,
  port: number,
): ConfigDocument {
  return {
    ...config,
    config: {
      ...config.config,
      issuer: baseURL,
      server: { host: "127.0.0.1", port },
    },
  };
}

/** Serializes one value as a YAML document. */
export function dumpYaml(value: unknown): string {
  return stringify(value);
}
