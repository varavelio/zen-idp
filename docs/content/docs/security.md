---
title: "Security"
description: "The trust model explained: where every secret lives, how tokens are designed, rate limiting, transport, and the honest boundaries."
icon: "lock-keyhole"
weight: 8
---

# Security

This page explains how Zen IdP thinks about security, so your deployment decisions can follow the same logic. It is organized around a simple question: where does each kind of value live, and what happens if it leaks?

## The trust model

Zen IdP answers one question: **who is signing in**. It authenticates humans and asserts verified claims to your applications. What those people may do is answered by each application, using the claims it receives. Groups, roles and other custom claims travel in tokens, permissions stay where they belong, in the applications (clients).

Keeping that boundary is a design decision with consequences you can feel: no permission screens, no policy engine, no per-application claim filtering. Every client receives every custom claim of the signing-in user, which is why claims are perfect for `groups: [engineering]` and wrong for anything you would not hand to every app at once.

## Three places, three kinds of value

Everything in the system lives in exactly one of three places, and knowing which is which is most of the security model:

| Where                             | What lives there                                                      | If it leaks                                                                                                                                                                                                                                                                                   |
| --------------------------------- | --------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| YAML configuration                | Users, clients, claims, policy, and Argon2id hashes                   | Offline guessing of your administrator and client passwords becomes theoretically possible but [absurdly unfeasible](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id). Strong generated values and limited access to the repository are the answer. |
| The root secret, `ZEN_IDP_SECRET` | The input from which the signing key and every TOTP credential derive | Every identity can be impersonated. It never belongs in YAML, logs, or the database, and rotation is a major event, see below.                                                                                                                                                                |
| The SQLite state file             | Sessions, one-use tokens, rate-limit counters, locks, audit records   | Sessions and outstanding enrollment links can be analyzed and, with the right tools, possibly abused. No credentials or private keys are inside, and a fresh state file ends the exposure.                                                                                                    |

The design goal of that split is that the most valuable thing, the root secret, exists in exactly one place you control, and everything else is either public by nature (the public signing key) or disposable (the state).

## The root secret

One value, supplied through the environment, from which two families of secrets derive deterministically:

- the **OIDC signing identity**, an RSA key pair that signs every token, always the same pair for the same secret;
- every **user's TOTP credential**, derived from the root secret, the user's `sub`, and their revision.

Derivation is domain separated and deterministic, which yields the two properties that define Zen IdP operationally: restarts reproduce everything identically without stored key material, and rotating a single user's credential is a one field YAML change.

With that power comes exactly one obligation: the secret must be **high entropy**. It must be at least 32 characters, and it must come from a generator, `generate-secrets` produces 256 bits of entropy. A human sentence as a root secret is a master key with a bad passphrase.

Rotation of the root secret is a globally disruptive event by construction: the signing identity changes, every user's TOTP credential changes, all authenticators must re-enroll, and previously issued tokens stop validating against the new public key. That is not a flaw, it is what "one secret protects everything" means. Plan it, schedule it, and communicate it.

<vara-alert
title="Protect the root token"
description="It is important that you never store the ZEN_IDP_SECRET in any insecure location. Use the primitives of your deployment platform (environment variables, secret managers, etc.), but it is vitally important that this key is not leaked; otherwise, you could consider the system compromised and have to start a new one from scratch with a different secret."
color="warning"
/>

## Token design

Tokens issued to applications are deliberately short lived:

| Token              | Lifetime   | Contents                                                                            |
| ------------------ | ---------- | ----------------------------------------------------------------------------------- |
| ID token           | 15 minutes | Signed identity assertion with `sub`, audience, and every custom claim of the user. |
| Access token       | 15 minutes | Thin, signed, audience restricted to `/userinfo`. Contains no profile claims.       |
| Authorization code | 5 minutes  | One-time code bound to client, redirect URI, subject, and PKCE challenge when used. |

Two design choices deserve the reasoning behind them:

- **There are no refresh tokens.** Short sessions and a fresh sign-in when they expire keep the attack surface small and the mental model simple. Applications that want persistent access keep their own local session and walk the user through a silent re-login when needed.
- **The access token is thin on purpose.** It answers exactly one question at one endpoint: who does this bearer belong to, right now. Applications that need authoritative, current claims call `/userinfo`, which validates the token and then resolves the user against the live configuration, enforcing sessions, locks, expiration, and the current claims in YAML. Treating the access token as a general API key against other services will not work, it was not built for that.

PKCE with the `S256` method is mandatory for public clients and recommended for confidential ones, closing code interception attacks in both cases. Client authentication supports `client_secret_basic` and `client_secret_post` for confidential clients, and `none` for public clients.

## Rate limiting and abuse resistance

Failed attempts are limited per identifier, not per IP:

- A known user's `sub` and `idp_login` share a single counter, so alternating identifiers grants no extra attempts.
- Unknown identifiers are limited too, with responses indistinguishable from other failures, so enumeration through error differences is impractical.
- Administrator sign-in and client authentication have equivalent limits.

IP based limits are deliberately absent from the service: behind proxies and NAT they punish shared users and barely slow distributed attackers. That control belongs at your edge, where the real client addresses are known. A CDN or reverse proxy with IP (and maybe geographical restrictions) limits in front, plus Zen IdP's identifier limits behind it, is the intended combination.

<vara-alert
title="Tip: Increase the security of /admin"
description="To improve Zen IdP security, in addition to configuring your edge to have rate limits, you can perform stricter checks on all paths starting with /admin, such as geo-blocking, more aggressive rate limits, VPN access, etc. Only you know what level of security your project require."
color="info"
/>

## Transport and browser security

Zen IdP serves plain HTTP and expects TLS to terminate in front of it, which is the standard pattern and the one that keeps certificate management out of the service. The obligations are small and specific:

- The issuer URL must be HTTPS in production, and everything, discovery, redirects, cookies, token claims, derives from that value rather than from request headers that could be forged.
- Your proxy must forward the original scheme in `X-Forwarded-Proto`. Zen IdP trusts exactly that header to recognize the public scheme.
- Cookies are `HttpOnly` and, in production, `Secure`, with a strict same-site policy. Session cookies hold opaque high entropy credentials, never self-contained identity, and a database row without its cookie is useless.
- State changing browser actions are CSRF protected, pages handling authorization and enrollment set `no-store` and `no-referrer`, and request sizes are bounded.

## What is deliberately not there

An honest boundary list is part of trusting a security tool, so here is what Zen IdP does not attempt:

- **TOTP is not phishing resistant.** A convincing fake login page can relay a live code. TLS everywhere and user habit are the mitigations available today.
- **A code is accepted for one step of skew in each direction**, and a captured code can be replayed inside that window. Rate limiting and short windows bound the practical risk.
- **Issued ID tokens are not revocable.** They are valid for up to 15 minutes, and `/userinfo` or the session check is the revocation-aware path.
- **The audit log is operational history, not compliance storage.** Retention is finite and tied to the state file. Export events you must keep.
- **One active instance per issuer.** The state file is local SQLite, and multiple instances would not share sessions, locks, or counters coherently.
- **Administrator authority includes enrollment**, which means it includes impersonation. Protect the admin password accordingly and watch the audit log.

None of these are accidents. Each one trades a capability most small deployments do not need for a system that is smaller, easier to reason about, and safer to operate.
