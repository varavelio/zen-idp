---
title: "Configuration"
description: "The complete YAML model: every field of config, clients, and users, plus file discovery, merging, and validation."
icon: "settings"
weight: 3
---

# Configuration

Zen IdP is configured entirely through YAML. One document, or a set of documents you can split as you like, describes every user, every application, and every policy decision. This page documents the complete model and how files are discovered and merged.

If you want the fastest possible introduction instead, [Get Started](/docs/get-started/) shows a minimal working file.

## The three blocks

Every configuration document has exactly three top-level blocks:

```yaml
config:
# Instance settings: issuer, listener, UI, security, maintenance.

clients:
# The applications that trust this identity provider.

users:
# The human identities.
```

Nothing else is allowed at the top level, and runtime inputs such as the root secret and the database path never belong in these files. They live in the environment, see [Operations](/docs/operations/).

The reference file [`config.example.yaml`](https://github.com/varavelio/zen-idp/blob/main/config.example.yaml) in the repository documents every field with comments and is a good starting template.

## `config`: the instance

### `config.issuer`

The public URL of this Zen IdP, for example `https://auth.example.com`. It is the OIDC issuer value, the base for every endpoint URL, and the `iss` claim in tokens. It must be an absolute URL with no userinfo, query, or fragment.

In production it must use HTTPS. Plain HTTP is accepted only for local development, when the host is `localhost` or a loopback IP address. Everything derives from this value, so changing it later is the same as moving your identity provider to a new address: every application must be updated to point at the new issuer.

### `config.server`

Optional listener settings:

| Field  | Default     | Meaning                                                                     |
| ------ | ----------- | --------------------------------------------------------------------------- |
| `host` | `"0.0.0.0"` | Address to bind. Use `127.0.0.1` to keep the listener local to the machine. |
| `port` | `8080`      | TCP port, from 1 to 65535.                                                  |

Zen IdP serves plain HTTP on this listener and never terminates TLS itself. Production deployments put a reverse proxy or CDN in front and forward traffic to this listener. The proxy must send the original scheme in `X-Forwarded-Proto` so cookies and redirects match the public HTTPS issuer.

### `config.ui`

Optional presentation settings for the pages your users see:

| Field            | Meaning                                                             |
| ---------------- | ------------------------------------------------------------------- |
| `name`           | Product or organization name shown on sign-in and enrollment pages. |
| `logo_light_url` | Logo for light mode, an absolute HTTPS URL.                         |
| `logo_dark_url`  | Logo for dark mode, an absolute HTTPS URL.                          |
| `favicon_url`    | Favicon, an absolute HTTPS URL.                                     |

Setting the same URL for both logos shows one logo in both modes. When only one is set it is used everywhere. These settings change what users see, never how authentication works.

### `config.security.admin_password_hash`

Required. The Argon2id hash of the administrator password. It gates the admin interface, which can create enrollment tokens, so treat it as a powerful credential: generate it with `zen-idp generate-secrets`, keep the plain value in your password manager, and put only the hash in YAML.

The administrator password is independent from the root secret. Rotating it means updating this hash.

### `config.security.rate_limits`

Optional failed-attempt limits. All of them are keyed by identifier, never by source IP, and unknown identifiers are bounded exactly like known ones so nobody can tell them apart from the outside.

| Field                                 | Default | Meaning                                              |
| ------------------------------------- | ------- | ---------------------------------------------------- |
| `max_user_login_attempts`             | `5`     | Failed sign-in attempts allowed per identifier.      |
| `user_login_attempts_window_seconds`  | `300`   | Window for those attempts.                           |
| `max_client_auth_attempts`            | `5`     | Failed client authentications allowed per client ID. |
| `client_auth_attempts_window_seconds` | `300`   | Window for those attempts.                           |

A user's two identifiers, `sub` and `idp_login`, share one counter, so an attacker cannot get extra attempts by alternating between them. Administrator sign-in is rate limited with the same model. See [Security](/docs/security/) for the reasoning behind identifier-based limits.

### `config.security.session.max_age_hours`

Optional absolute lifetime of the browser session, in hours, from 1 to 8760. The default is 72. This is the Zen IdP single sign-on session, the thing that keeps users signed in across your applications. It is independent from the tokens your applications issue themselves: when the Zen IdP session expires, the next sign-in needs a fresh TOTP code, but applications keep their own local sessions alive on their own terms.

### `config.maintenance`

Optional background cleanup settings:

| Field                      | Default | Meaning                                                                        |
| -------------------------- | ------- | ------------------------------------------------------------------------------ |
| `cleanup_interval_seconds` | `3600`  | Seconds between cleanup passes, from 60 to 86400. A pass also runs at startup. |
| `audit_retention_hours`    | `720`   | Hours audit records are kept before removal. Zero keeps them indefinitely.     |

Cleanup removes state that can never become usable again: expired rate-limit counters, expired one-use tokens, expired sessions, and audit records older than the retention window.

## `clients`: your applications

Each list item registers one application. The complete field set:

| Field           | Required | Meaning                                                                              |
| --------------- | -------- | ------------------------------------------------------------------------------------ |
| `id`            | Yes      | The OIDC `client_id`. Nonblank, unique.                                              |
| `name`          | No       | Display name, defaults to `id` when omitted.                                         |
| `secret_hash`   | No       | Argon2id hash of the client secret. Present means confidential, absent means public. |
| `redirect_uris` | Yes      | One or more exact callback URIs.                                                     |

Applications that can keep a secret, such as a server side app, use `secret_hash` and authenticate with it. Applications that cannot, such as a mobile app or a SPA, omit it and use PKCE instead. The rules for redirect URIs, and guidance on which kind to choose, are on the [Clients](/docs/clients/) page.

## `users`: your identities

Each list item is one user mapping. The required minimum is a `sub`:

```yaml
users:
  - sub: "alice"
```

Every other field is optional. Recognized internal fields are `idp_login`, `idp_totp_rev`, and `idp_expires_at`, and anything else becomes a custom OIDC claim released to all your applications. The complete model, including claims and the reserved names, is documented on the [Users](/docs/users/) page.

## Splitting configuration across files

The environment variable `ZEN_IDP_CONFIG_PATH` selects your configuration with exactly one selector, which can be:

- **one file**, for example `config/zen-idp.yaml`;
- **one directory**, in which case every immediate `.yaml` and `.yml` child is selected, without recursion;
- **one glob**, for example `config/**/*.yaml`, when you want depth.

Relative selectors resolve from the working directory of the process, so the same relative selector behaves the same in Docker, systemd, or a shell. Selected files are sorted and deduplicated deterministically, then composed into one configuration:

- Mappings merge recursively, so `config/zen-idp.yaml` and `config/security.yaml` can each define parts of `config`.
- Lists are appended in file order, so `users` can live in several files.
- Two definitions of the same thing, such as two different values for `issuer`, or the same `sub` in two files, fail validation instead of silently winning.

Splitting is free, so let your structure follow your organization: a file per team, a generated file for onboarding batches, or a single file for a small deployment. There is no performance difference.

## Validation

Configuration is fully parsed and validated before the service accepts traffic, and invalid configuration fails startup with the file and the reason. The same path runs on demand:

```console
zen-idp validate-config
```

It needs only `ZEN_IDP_CONFIG_PATH`, so it fits naturally in CI: run it on every commit that touches configuration and mistakes never reach a deployment. Validation is strict about unknown fields and wrong types on purpose: a typo that silently does nothing is worse than an error.

## Runtime inputs are not configuration

Three values come from the environment and are rejected if they appear in YAML: `ZEN_IDP_CONFIG_PATH`, `ZEN_IDP_SECRET`, and `ZEN_IDP_DB_PATH`. Keeping infrastructure inputs and identity data apart is what lets you commit your YAML to version control while the secrets stay in a secret manager. The complete runtime reference, including explicit env files and precedence rules, is on the [Operations](/docs/operations/) page.
