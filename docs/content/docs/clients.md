---
title: "Clients"
description: "Register applications as OIDC clients: confidential or public, redirect URI rules, scopes, and connecting real apps."
icon: "blocks"
weight: 5
---

# Clients

Every application that signs people in through Zen IdP is a client, and registering one is a few lines of YAML. This page explains the client model, how to choose between a confidential and a public client, and how to point real applications at your identity provider.

## Confidential or public

The first decision for each client is whether the application can keep a secret:

- A **confidential client** runs somewhere the secret is safe, typically a server side application. It gets a client secret from you and proves its identity with it on every token exchange.
- A **public client** runs somewhere hostile, typically a mobile app, a desktop app, or a SPA. It has no secret. Instead it proves the continuity of its own login flow with PKCE, which is mandatory for public clients.

Both kinds receive the same tokens and the same claims. The choice is about the application's environment, not its importance.

## Registering a client

```yaml
clients:
  - id: "grafana-prod"
    name: "Grafana"
    secret_hash: "$argon2id$..."
    redirect_uris:
      - "https://grafana.example.com/login/generic_oauth"
```

The complete field set:

| Field           | Required | Meaning                                                                        |
| --------------- | -------- | ------------------------------------------------------------------------------ |
| `id`            | Yes      | The `client_id` the application sends. Nonblank and unique.                    |
| `name`          | No       | Display name shown in the interface. Defaults to `id`.                         |
| `secret_hash`   | No       | Argon2id hash of the client secret. Present is confidential, absent is public. |
| `redirect_uris` | Yes      | One or more exact callback URIs.                                               |

Generate client secrets with `zen-idp generate-secrets`, which prints a plain value for the application and a hash for your YAML. Like every credential in Zen IdP, only the hash is ever stored.

<vara-alert
title="One secret per client"
description="Each generated bundle is independent. When you add another client later, run generate-secrets again and use only the new OIDC client section of the output. Never reuse a secret or a hash across clients, and do not regenerate the root or administrator values along the way unless you mean to rotate them."
color="warning"
/>

A public client is simply one without `secret_hash`:

```yaml
clients:
  - id: "mobile-app"
    redirect_uris:
      - "com.example.app:/oauth/callback"
```

## Redirect URI rules

The redirect URI is where Zen IdP sends the browser after login, and it is treated as a security boundary:

- Matching is **exact**, character by character. No wildcards, no partial matches, no normalization. `https://app.example.com/callback` and `https://app.example.com/callback/` are different URIs.
- URIs must be **absolute**, and must not contain a fragment.
- Production URIs use **HTTPS**. Plain HTTP is accepted only for development on `localhost` or a loopback IP.
- Public clients may also register a **custom scheme** in reverse-domain notation with at least one dot, the convention for native app callbacks such as `com.example.app:/oauth/callback`. Confidential clients stick to HTTPS URIs.

Copy redirect URIs from the application's own configuration rather than typing them from memory. A trailing slash or a different case is the single most common reason an app refuses to start its login flow.

## Connecting an application

Any OIDC-capable application connects the same way. Somewhere in its settings it will ask for:

| The application asks for            | You give it                                                  |
| ----------------------------------- | ------------------------------------------------------------ |
| Issuer, authority, or discovery URL | Your `config.issuer`, for example `https://auth.example.com` |
| Client ID                           | The `id` you registered                                      |
| Client secret                       | The generated plain value, confidential clients only         |
| Redirect / callback URI             | One of the exact URIs you registered                         |
| Scopes                              | `openid`                                                     |

Applications that discover their configuration from `/.well-known/openid-configuration` need only the issuer and their credentials, since endpoint URLs, signing algorithms, and capabilities are advertised automatically.

Some applications ask whether to use PKCE. The answer is yes whenever it is offered, for both public and confidential clients. PKCE costs nothing and closes a class of interception attacks. If the application cannot keep a secret at all, register it as a public client and make sure it sends a PKCE challenge, because Zen IdP requires `S256` for public clients.

## What applications experience

The flow is the standard OIDC Authorization Code Flow:

1. The application sends the browser to `/authorize` with its client ID, redirect URI, and state.
2. The user signs in with their identifier and TOTP code, reusing an existing session when one is alive.
3. The browser returns to the application with a one-time authorization code.
4. The application exchanges the code at `/token`, authenticating with its secret if it is confidential and with its PKCE verifier if it used PKCE.
5. It receives an ID token with the user's `sub` and all their custom claims, plus a short lived access token valid for Zen IdP's `/userinfo` endpoint.

A few behaviors are worth knowing in advance:

- **There is no consent screen.** Registering a client is your decision, as the operator, that this application may receive claims. Users go straight through.
- **Scopes are simple.** `openid` is required, other scope names are accepted and echoed back for compatibility, but they never change which claims are released. `offline_access` will not produce a refresh token, because Zen IdP does not issue refresh tokens at all.
- **The access token is for userinfo only.** It is a thin, signed token whose only audience is `/userinfo`. Applications that try to use it as a general API token against other services will not get far; it is not that kind of token.

See [Authentication](/docs/authentication/) for what the user experiences inside step 2, and [Security](/docs/security/) for the reasoning behind the token design.

## Managing clients over time

| Operation               | What you do                                                                          |
| ----------------------- | ------------------------------------------------------------------------------------ |
| Add an application      | Run `generate-secrets`, register the client, deploy, paste credentials into the app. |
| Rotate a client secret  | Generate a new bundle, replace the hash in YAML, deploy, update the app.             |
| Remove an application   | Delete the mapping and deploy. New logins for it stop immediately.                   |
| Fix a redirect mismatch | Add the exact URI the application sends, deploy.                                     |
| Rename the display name | Edit `name`. Protocol identity is the `id`, which stays the same.                    |

Removing a client does not end sessions users already have in that application. The application decides its own session lifetime, and its local sign-out is the reliable way to end access there. What removal does guarantee is that the application can never complete a new login or exchange a new code.
