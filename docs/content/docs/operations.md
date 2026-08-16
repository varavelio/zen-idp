---
title: "Operations"
description: "Running Zen IdP day to day: runtime inputs, commands, endpoints, reverse proxying, state handling, rotation, and recovery."
icon: "server"
weight: 9
---

# Operations

This page is the runtime reference: what the process needs, what it exposes, how to run it behind a proxy, what the state database means for operations, and every rotation and recovery procedure in one place.

## Runtime inputs

Three environment variables configure the runtime. They never belong in YAML:

| Variable              | Used by                              | Meaning                                                                                  |
| --------------------- | ------------------------------------ | ---------------------------------------------------------------------------------------- |
| `ZEN_IDP_CONFIG_PATH` | `serve`, `validate-config`, `health` | One selector: a file, a directory, or a glob. See [Configuration](/docs/configuration/). |
| `ZEN_IDP_SECRET`      | `serve`                              | The root secret, at least 32 characters, high entropy.                                   |
| `ZEN_IDP_DB_PATH`     | `serve`                              | Path of the SQLite state file, created and migrated on start.                            |

A relative config selector resolves from the working directory of the process. In the published docker image the defaults are already set to the conventional locations: configuration at `/data/config` and the database at `/data/db/zen-idp.sqlite3`.

To load values from a file, pass it explicitly:

```console
zen-idp serve --env-file ./production.env
```

The file is a simple `KEY=value` list. Two rules keep behavior predictable:

- Zen IdP never loads `.env` or any other file implicitly. No file is read unless you name it.
- Values already present in the process environment win, even when they are empty. An empty override fails validation loudly instead of silently falling back to the file.

## Commands

```text
zen-idp serve [--env-file PATH]
zen-idp validate-config [--env-file PATH]
zen-idp generate-secrets
zen-idp health [--env-file PATH]
```

| Command            | What it does                                                                                                      |
| ------------------ | ----------------------------------------------------------------------------------------------------------------- |
| `serve`            | Starts the service. Requires all three variables and completes configuration validation before accepting traffic. |
| `validate-config`  | Runs the exact startup validation and exits. Needs only the configuration. Run it in CI and before every deploy.  |
| `generate-secrets` | Prints an independent bootstrap bundle: root secret, administrator pair, OIDC client pair. Needs nothing.         |
| `health`           | Checks the configured listener and prints `ok`. This is what the container health check runs.                     |

`generate-secrets` writes everything to standard output, including its own warnings. Every run is an independent bundle: when you add a second client, use only the new OIDC client section of the new output and leave the root and administrator values alone unless rotating them.

## HTTP endpoints

Under your issuer, the public surface is:

| Endpoint                            | Purpose                                                   |
| ----------------------------------- | --------------------------------------------------------- |
| `/.well-known/openid-configuration` | OIDC discovery document.                                  |
| `/.well-known/jwks.json`            | Public signing keys.                                      |
| `/authorize`                        | OIDC authorization endpoint.                              |
| `/token`                            | OIDC token endpoint.                                      |
| `/userinfo`                         | OIDC UserInfo endpoint.                                   |
| `/login`, `/logout`                 | Sign-in and sign-out interactions, always part of a flow. |
| `/enroll`                           | One-time authenticator enrollment.                        |
| `/panic`                            | The user emergency action.                                |
| `/admin`, `/admin/audit`            | The admin interface and audit log.                        |
| `/health`                           | Liveness and readiness, returns `ok`.                     |

Most of these you never call by hand. Applications discover what they need from the discovery document, and the browser interactions take care of the rest. `health` is the one worth monitoring, and it is what the image's built-in health check polls.

## Behind a reverse proxy

Production terminates TLS in front and forwards to the plain HTTP listener. The proxy must forward the original scheme in `X-Forwarded-Proto`, everything else is ordinary proxying. With Caddy:

```text
auth.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

Caddy sends the header by default and manages certificates for you. With nginx:

```nginx
server {
    listen 443 ssl;
    server_name auth.example.com;

    ssl_certificate     /etc/letsencrypt/live/auth.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/auth.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

Keep the listener bound to loopback, or unpublished inside a shared Docker network, so the plain HTTP surface is not reachable from outside. If you add edge protections such as IP rate limits or a WAF, that is the right layer for them, see [Security](/docs/security/).

## The state database

One SQLite file holds every session, outstanding enrollment token, rate-limit counter, lock, and audit record. Operationally it behaves like this:

- **Restarts and upgrades preserve it.** Sessions stay alive, unredeemed enrollment links stay valid, locks and counters stay enforced. Nothing to do, nothing to drain.
- **It is never the source of truth.** Users, clients, claims, and policy come from YAML, credentials come from the root secret. The file can be replaced without changing a single identity.
- **Deleting it is an operational reset.** Every session ends, outstanding enrollment links die, locks and counters clear, the audit log is gone. Everyone signs in again with codes that still work, because credentials are derived, not stored.
- **It contains live security state.** Restrict its permissions to the service user. It holds no secrets, but sessions and outstanding tokens are in it.

There is no maintenance job for the database itself. Background cleanup expires dead rows, rate-limit counters, spent tokens, ended sessions, and aged audit records, on a schedule you can tune through `config.maintenance`.

## Rotation procedures

Each rotatable value has a procedure sized to its blast radius:

**Rotate one user's TOTP credential.** Increment their `idp_totp_rev` in YAML, deploy, create a new enrollment token. Sessions authenticated at the old revision are revoked. Nothing and nobody else changes. This is the routine procedure for lost devices.

**Rotate the administrator password.** Run `generate-secrets`, replace `admin_password_hash` in YAML with the new hash, deploy. Current admin sessions end on their own terms. User authentication is untouched.

**Rotate a client secret.** Run `generate-secrets`, replace that client's `secret_hash`, deploy, then update the secret in the application. Doing the YAML side first means the application briefly fails auth until you paste the new value, so pick a quiet moment.

**Rotate the root secret.** Set the new `ZEN_IDP_SECRET`, restart, and treat it as a full credential event: the signing key changes, all users must re-enroll their authenticators, all sessions and outstanding enrollment links die with the change, and relying applications refresh their cached keys from JWKS on their own schedule. Announce it, schedule it, then run the enrollment campaign. See [Security](/docs/security/) for why it is shaped this way.

## Recovery scenarios

Three losses cover almost every bad day:

**Lost the state database.** The cheapest disaster. Start with the same configuration and root secret: identities, credentials, and the signing key are identical, because none of them came from the file. Users sign in again, you reissue enrollment links that were still outstanding, and locks plus the audit log start over clean.

**Lost the YAML configuration.** The service fails closed, as it must: without valid configuration there is nothing to authenticate. Restore from version control, which is the reason identity lives in files under review. Session rows in SQLite can never substitute for the configuration.

**Lost the root secret.** Not recoverable, by design. The signing identity and every TOTP credential are gone with it. The path forward is a new root secret and a full re-enrollment of every user, after which everything works again. This is why the secret lives in a secret manager, not in a notebook.

## Topology

Run **one active instance per issuer**. The state file is embedded SQLite on a local filesystem, and the guarantees around sessions, locks, one-use tokens, and rate limits are the guarantees of one process and one file.

Running two replicas against separate state files does not produce a redundant deployment, it produces two identity providers that disagree about who is signed in and who is locked. If you need more availability than one instance, the supported shapes are a fast restarting single container, or a cold standby with the state directory preserved, restarting onto the same data.

Do not place the state file on network shared storage. SQLite over NFS and friends trades correctness for the illusion of sharing, and the failure modes are the ugly kind of silent.

## Deployment checklist

For a production deployment, the short version of everything above:

1. Pin an exact image version and run `validate-config` against your configuration.
2. Put TLS in front, forward `X-Forwarded-Proto`, keep the listener private to the proxy.
3. Set an HTTPS issuer that matches the public URL users actually visit.
4. Keep the root secret in a secret manager, never in YAML or images.
5. Give the state directory to the service user and include it, or at least its host path, in your backup policy.
6. Monitor `/health` and alert on anything other than `ok`.
7. Test your recovery story once: replace the state file in a staging deployment and watch everyone sign in again with working codes.
