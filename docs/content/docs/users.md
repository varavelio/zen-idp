---
title: "Users"
description: "How identities are declared: subjects, login identifiers, custom claims, expiration, and TOTP credential revisions."
icon: "users"
weight: 4
---

# Users

Every identity in Zen IdP is one YAML mapping. There is no user database behind it, no profile editor, and no sync job: a person exists exactly when their mapping exists, with exactly the fields you gave them. This page documents every field and the lifecycle operations you perform day to day.

## The subject: `sub`

Required, and the most important value you will choose for each person:

```yaml
users:
  - sub: "alice"
```

`sub` is the stable OIDC subject, the identifier every application receives as the `sub` claim. It becomes the user's primary login identifier and the input from which their TOTP credential is derived, which gives it two properties worth internalizing:

- **It is permanent in practice.** Changing a `sub` creates a new identity: a new login, a new TOTP secret, and a new `sub` claim in your applications. Never reuse a subject for a different person, and pick values that survive role changes. `alice-{random}` ages better than `alice-marketing`.
- **It follows rules.** One to 255 US-ASCII characters, case-sensitive, unique. It does not need to be an email address. Quoted YAML strings are required, since numbers and booleans are rejected rather than converted.

## The second identifier: `idp_login`

Optional. When present, the user can sign in with either identifier:

```yaml
users:
  - sub: "user-001"
    idp_login: "alice@example.com"
```

Both values authenticate the same identity, and both can always sign in: adding `idp_login` never disables `sub`. It is a single string, not a list, and it is never released as a claim. It exists for the common case where people remember their email but not their username.

All identifiers share one namespace across all users. Two users cannot have the same `sub`, cannot have the same `idp_login`, and one user's `idp_login` cannot collide with another user's `sub`. Validation fails on any collision, so what you write is exactly what can sign in.

## Custom claims

Any field that is not `sub` or one of the internal `idp_` fields becomes a custom claim:

```yaml
users:
  - sub: "user-001"
    name: "Alice Example"
    email: "alice@example.com"
    groups:
      - "engineering"
      - "operators"
    profile:
      department: "Platform"
      active: true
```

Claims can be strings, numbers, booleans, arrays, and nested objects, and they are emitted exactly as written in every ID token and every UserInfo response. Zen IdP never invents values, never fills in `name` or `email` on its own, and missing data stays missing.

Your applications read these claims and decide what the user may do. Zen IdP is deliberately not an authorization engine: it answers who is signing in, your applications answer what that person can touch. A typical setup declares `groups` or `roles` here and lets each application map them to its own permissions.

Two kinds of names are reserved and rejected with a validation error:

- every key starting with `idp_`, that namespace is internal and never returned as claims in the id token;
- protocol claims such as `iss`, `aud`, `exp`, `iat`, `nonce`, and `auth_time`, which Zen IdP produces itself.

<vara-alert
title="Claims are broadcast"
description="Every registered client receives every custom claim of the signing-in user. Claims are a good place for groups and roles, and a terrible place for secrets or sensitive personal data you would not hand to every application."
color="warning"
/>

## Expiration: `idp_expires_at`

Optional. An absolute instant after which the user can no longer authenticate:

```yaml
users:
  - sub: "contractor-23"
    idp_expires_at: "2026-12-31T23:59:59Z"
```

Write it as a quoted RFC 3339 timestamp. At and after that instant, the user cannot start or complete a sign-in, existing sessions stop working, and UserInfo stops answering for them. Enforcement is immediate and continuous, not tied to a cleanup job.

This is the right tool for contractors, auditors, and temporary staff: the account simply stops existing as an authentication option when the engagement ends. ID tokens already issued remain valid until their own short expiry, which applications handle through their normal token lifetimes.

## TOTP revision: `idp_totp_rev`

Optional, defaults to 0. Incrementing it gives that one user a brand new TOTP credential:

```yaml
users:
  - sub: "user-001"
    idp_totp_rev: 2
```

Each user's authenticator secret is derived deterministically from the root secret, their `sub`, and this revision. When you increment the revision, the old secret stops working, every session authenticated with it is invalidated, and the user needs a new enrollment link. Nobody else is affected, and the signing key does not change.

This is the standard response to a lost device or a suspected leak, and the full recovery walkthrough is on the [Authentication](/docs/authentication/) page. The field is never released as a claim.

## Lifecycle operations

Because identities are files, every lifecycle operation is an edit followed by a deploy. Configuration activates when the service restarts or starts with the new files.

| Operation            | What you do                                                                                  |
| -------------------- | -------------------------------------------------------------------------------------------- |
| Add a user           | Add the mapping, deploy, then create an enrollment token in the admin interface.             |
| Remove a user        | Delete the mapping and deploy. Their sessions stop working immediately.                      |
| Disable temporarily  | Lock the user from the admin interface instead, see [Administration](/docs/administration/). |
| Disable permanently  | Remove the user, or set `idp_expires_at` to a past instant, and deploy.                      |
| Change claims        | Edit the mapping and deploy. New tokens carry the new claims right away.                     |
| Rotate credentials   | Increment `idp_totp_rev`, deploy, create a new enrollment token.                             |
| Rename an identifier | Change `idp_login` freely. Changing `sub` is creating a new identity, prefer not to.         |

Removing a user or letting them expire does not recall ID tokens your applications already accepted. Those tokens are short lived by design, and each application's own session decides how quickly access actually disappears. High-security removals combine the YAML change with an administrative lock, which also revokes every session at once.

## Sizing expectations

Hand-maintained YAML is comfortable from a handful of users into the hundreds. Beyond that, let tooling write the files: because configuration composes deterministically, a script or template that generates a batch of users into a separate file works as well as typing them by hand, and `validate-config` in CI catches generation mistakes before they deploy. Zen IdP is intentionally not a directory service with connectors and sync jobs, see [Security](/docs/security/) for where its boundaries are.
