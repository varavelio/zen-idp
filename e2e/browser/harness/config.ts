// The YAML configuration document of one black-box instance, written with
// a small dependency-free emitter so tests can exercise any configuration
// option without extra tooling.

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
  return `${dumpNode(value, 0)}\n`;
}

/** Returns whether the value is serialized as a nested block. */
function isBlock(value: unknown): boolean {
  return value !== null && typeof value === "object";
}

/** Serializes one node, with every line already indented to its level. */
function dumpNode(value: unknown, indent: number): string {
  const pad = "  ".repeat(indent);
  if (value === null || value === undefined) {
    return "null";
  }
  if (Array.isArray(value)) {
    if (value.length === 0) {
      return "[]";
    }
    return value.map((item) => dumpListItem(item, indent)).join("\n");
  }
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>);
    if (entries.length === 0) {
      return "{}";
    }
    return entries.map(([key, item]) => {
      if (isBlock(item)) {
        return `${pad}${yamlKey(key)}:\n${dumpNode(item, indent + 1)}`;
      }
      return `${pad}${yamlKey(key)}: ${dumpNode(item, indent + 1)}`;
    }).join("\n");
  }
  return yamlScalar(value);
}

/** Serializes one array item, keeping the first key of objects inline. */
function dumpListItem(item: unknown, indent: number): string {
  const pad = "  ".repeat(indent);
  if (isBlock(item)) {
    if (Array.isArray(item)) {
      return `${pad}-\n${dumpNode(item, indent + 1)}`;
    }
    const entries = Object.entries(item as Record<string, unknown>);
    if (entries.length === 0) {
      return `${pad}- {}`;
    }
    const [firstKey, firstValue] = entries[0];
    const first = isBlock(firstValue)
      ? `${pad}- ${firstKey}:\n${dumpNode(firstValue, indent + 1)}`
      : `${pad}- ${firstKey}: ${dumpNode(firstValue, indent + 1)}`;
    const rest = entries.slice(1).map(([key, value]) => {
      if (isBlock(value)) {
        return `${pad}  ${key}:\n${dumpNode(value, indent + 1)}`;
      }
      return `${pad}  ${key}: ${dumpNode(value, indent + 1)}`;
    });
    return [first, ...rest].join("\n");
  }
  return `${pad}- ${dumpNode(item, indent + 1)}`;
}

/** Serializes one scalar string, quoting whenever plain style is unsafe. */
function yamlScalar(value: unknown): string {
  if (typeof value === "string") {
    if (isPlainScalar(value)) {
      return value;
    }
    // Double-quoted YAML scalars accept every JSON escape, so a JSON
    // string is always a valid quoted scalar.
    return JSON.stringify(value);
  }
  return String(value);
}

/** Serializes one mapping key. */
function yamlKey(key: string): string {
  return isPlainScalar(key) ? key : JSON.stringify(key);
}

// plainScalarPattern matches strings that can be written as plain YAML
// scalars: they start with an ordinary character and contain no whitespace
// or punctuation that could change their meaning.
const plainScalarPattern = /^[A-Za-z0-9_][A-Za-z0-9_./:@+-]*$/;

// yamlKeywordPattern matches strings that YAML would interpret as a
// non-string scalar.
const yamlKeywordPattern = /^(?:true|false|null|yes|no|on|off|y|n|~)$/i;

// yamlNumberPattern matches strings that YAML would interpret as a number.
const yamlNumberPattern = /^[-+]?(?:\d+\.?\d*|\.\d+)(?:[eE][-+]?\d+)?$|^0x[0-9a-fA-F]+$/;

/** Returns whether the string can be written as a plain YAML scalar. */
function isPlainScalar(value: string): boolean {
  return value !== ""
    && plainScalarPattern.test(value)
    && !yamlKeywordPattern.test(value)
    && !yamlNumberPattern.test(value);
}
