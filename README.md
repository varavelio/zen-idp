<h1 align="center">Zen IdP</h1>

<p align="center">
  <a href="https://github.com/varavelio/zen-idp/actions">
    <img src="https://github.com/varavelio/zen-idp/actions/workflows/ci.yaml/badge.svg" alt="CI status"/>
  </a>
  <a href="https://github.com/varavelio/zen-idp/releases/latest">
    <img src="https://img.shields.io/github/release/varavelio/zen-idp.svg" alt="Release Version"/>
  </a>
  <a href="LICENSE">
    <img src="https://img.shields.io/github/license/varavelio/zen-idp.svg" alt="License"/>
  </a>
  <a href="https://github.com/varavelio/zen-idp">
    <img src="https://img.shields.io/github/stars/varavelio/zen-idp?style=flat&label=github+stars"/>
  </a>
</p>

<p align="center">
  <a href="https://varavel.com">
    <img src="https://cdn.jsdelivr.net/gh/varavelio/brand@1.0.0/dist/badges/project.svg" alt="A Varavel project"/>
  </a>
</p>

Zen IdP is a declarative, zero-maintenance OIDC Identity Provider. It is a single Go binary that turns a reviewable YAML file into a complete authentication service: sign-in with TOTP codes, OIDC Authorization Code Flow for your applications, and a small administration interface - no database server, no external services, nothing to babysit.

## The idea

Most identity providers ask you to run several services, manage a database, and click through an admin panel to keep identity data in sync. Zen IdP takes the opposite road:

- **Your YAML is the source of truth.** Users, OIDC clients, claims, and policy all live in plain, reviewable files. Changes go through your normal code review flow - not through a hidden database.
- **One root secret does the heavy lifting.** From a single `ZEN_IDP_SECRET`, Zen IdP deterministically derives its RSA signing identity and every user's TOTP credential. Nothing sensitive is ever stored, it is _recomputed_.
- **SQLite holds only disposable state.** Sessions, one-use tokens, rate-limit counters, locks, and audit records live in an embedded SQLite file. Lose the file and you lose nothing permanent: identity and credentials are fully recovered from YAML plus the root secret.

## Features

- Full **OIDC Authorization Code Flow** with PKCE (`S256`) for public clients, RS256-signed ID and access tokens, discovery, and JWKS
- Deterministic **TOTP authentication** (RFC 6238) - no user database, no shared-secret storage
- **Declarative YAML configuration** with deterministic deep composition across files, directories, or globs
- **Administration UI** for enrollment tokens, user locks, panic recovery, and the audit log
- **Panic action and administrative locks** that instantly gate sign-in and SSO
- **Rate limiting** for user logins, administrator logins, and client authentication - keyed by identifier, never by IP
- Strict validation, secure defaults, CSRF protection, and browser security headers
- **Zero external state**: one binary, one SQLite file, done

## Quick start

You need to grab a release binary (other install methods coming soon).

Generate your bootstrap credentials:

```console
./dist/zen-idp generate-secrets
```

> [!WARNING]
> `generate-secrets` prints **everything** to standard output: the root secret, administrator plaintext and hash, client plaintext and hash, and operational notes. Treat the output as sensitive. Store the plaintext securely, put only the hashes in YAML, and never reuse a secret or hash across clients.

Point Zen IdP at your configuration with environment variables:

```dotenv
ZEN_IDP_CONFIG_PATH=./config/zen-idp.yaml
ZEN_IDP_SECRET=PASTE_THE_GENERATED_ROOT_SECRET_HERE
ZEN_IDP_DB_PATH=./var/zen-idp.db
```

Zen IdP never loads `.env` implicitly. Pass it explicitly when you want it:

```console
./dist/zen-idp validate-config --env-file ./local.env
./dist/zen-idp serve --env-file ./local.env
```

`validate-config` runs the exact startup discovery, merge, parse, and validation path - a great habit before every deploy. `serve` then starts the HTTP listener on `127.0.0.1:8080` by default.

The fastest way to see it all work: open `http://127.0.0.1:8080/admin`, sign in with the administrator password, create an enrollment token, and share the enrollment link with your first user. That link walks them through setting up their authenticator app.

## Configuration

Start from [`config.example.yaml`](config.example.yaml) - it documents every supported field. The essentials:

- **`config.issuer`** - your public HTTPS URL. This is the OIDC issuer and the base for every endpoint, so it must be the URL your users and applications actually reach.
- **`config.security.admin_password_hash`** - the Argon2id hash of the administrator password (never the plaintext).
- **`clients`** - one entry per application. Include a `secret_hash` for a confidential client, or omit it for a public client (SPA, mobile app).
- **`users`** - one mapping per identity: a stable `sub`, optionally a login identifier, a TOTP revision, an expiration, and any custom claims your applications need.

`ZEN_IDP_CONFIG_PATH` accepts exactly one selector: a single file, a directory (immediate `.yaml`/`.yml` children), or a doublestar glob. Files are sorted and deduplicated deterministically, maps merge recursively, and conflicts fail validation - so you can split configuration across files and compose them freely.

## Commands

| Command            | Environment required                                       | What it does                                                                                         |
| ------------------ | ---------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `serve`            | `ZEN_IDP_CONFIG_PATH`, `ZEN_IDP_SECRET`, `ZEN_IDP_DB_PATH` | Bootstraps everything and starts the server: OIDC endpoints, login and admin UI.                     |
| `validate-config`  | `ZEN_IDP_CONFIG_PATH`                                      | Runs the exact startup configuration path without needing the root secret or the database.           |
| `generate-secrets` | None                                                       | Prints an independent root secret, administrator and client credential pairs, and operational notes. |

Each `generate-secrets` run is independent. When adding a client later, use only the new client section of the output - do not replace the root or administrator values unless you intend to rotate them.

## What you get out of the box

- **For your applications** - the standard OIDC endpoints: discovery, JWKS, authorization, token, and UserInfo. Public clients must use PKCE; confidential clients authenticate with their secret over TLS. No consent screens, no refresh tokens, no surprises.
- **For your users** - a clean sign-in page (sub or configured login identifier plus a TOTP code), SSO across all your applications, a panic action that locks their account and signs out every session, and an enrollment flow that sets up their authenticator with a QR code.
- **For you** - an admin area to create enrollment tokens, lock or unlock users, clear panic locks, and browse the audit log. Every security-relevant action is recorded.

## Security notes

- Terminate TLS at your reverse proxy, CDN, or load balancer. Zen IdP serves plain HTTP by default and derives `Secure` cookies and TLS requirements from the issuer scheme, so the public issuer URL must be HTTPS in production.
- The root secret is the crown jewel: it derives the signing key and every TOTP credential. Rotating it rotates _everything_ - plan accordingly.
- Rate limits are keyed by identifier, never by source IP. Put IP-level limits at your edge.
- The SQLite file is disposable operational state. Deleting it revokes every session and token and wipes the audit log, but the signing identity and all credentials remain intact.

## License

Zen IdP is open-source and available under the [MIT License](LICENSE). Feel free to
use it in your personal or commercial projects.
