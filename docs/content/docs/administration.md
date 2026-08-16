---
title: "Administration"
description: "The admin interface: enrollment tokens, user locks, panic recovery, and the audit log."
icon: "shield"
weight: 7
---

# Administration

Zen IdP has a deliberately small admin interface. Identity data never changes through it, that is what YAML is for, so what remains are the four operational actions that genuinely belong behind a strong password: issuing enrollment tokens, locking and unlocking users, clearing panic locks, and reading the audit log.

## Signing in

The admin interface lives at `/admin` under your issuer, for example `https://auth.example.com/admin`. Sign in with the administrator password whose Argon2id hash is configured as `config.security.admin_password_hash`.

Two things make this credential worth protecting:

- It is independent from the root secret. Compromising one does not compromise the other, and rotating it is a YAML edit.
- An administrator can create enrollment tokens, and an enrollment token reveals a user's TOTP secret to whoever redeems it. Treat the admin password as an identity impersonation capability and store it accordingly.

Administrator sessions are separate from user single sign-on sessions, so signing into the admin interface never creates a user session and vice versa. Failed administrator sign-ins are rate limited with the same model as user sign-ins, keyed by identifier rather than IP.

## Enrollment tokens

The primary admin action. Select a user, choose an expiration, and the interface produces a one-time enrollment link:

- The expiration can be given as a **duration from now**, such as one hour.
- The token is **bound to the user and their current TOTP revision**. If you increment the revision after creating it, the link is dead, create a new one.
- The link is **consumed exactly once**, at the moment the credential is revealed. Sending it again does nothing.

Delivery is your choice, and the only rule is trust: deliver the link over a channel you trust for that specific person, because whoever opens it first gets the secret. For most teams that is a direct message to a known account, never a shared channel.

If a link leaks and might have been redeemed by the wrong person, do not hunt for proof: increment that user's `idp_totp_rev`, deploy, and enroll them again. The old secret becomes wrong immediately, which is strictly safer than trying to figure out who saw it.

## Locks

Locks are the temporary gate between "we are looking into something" and the permanent decisions that live in YAML. The admin interface offers lock actions per user:

**Administrative lock.** Immediately revokes every session of that user and blocks new sign-ins. Use it when you need access to stop now but removal to be a separate, considered decision. Unlocking is one click and restores sign-in, provided the user is still declared and unexpired.

**Panic lock.** Created by the user themselves through the panic action, described in [Authentication](/docs/authentication/). Clearing it is an explicit admin decision after your checks, and it is never cleared implicitly by unlocking an administrative lock or editing YAML.

Two properties matter operationally:

- Locks are **operational state, not identity data**. They live in the SQLite state file and do not survive losing it. Durable disablement always goes through YAML: remove the user or set an expiration.
- Locking and revoking happen **atomically**. There is no window where a lock exists but old sessions still work.

When you want someone gone for good, the reliable sequence is: lock first if you want instant effect, then remove them from YAML and deploy. After the deploy, the user no longer exists regardless of any state file anywhere.

## The audit log

Find it at `/admin/audit`. Every security relevant action is recorded: administrator sign-ins, enrollment token creation and consumption, lock changes, panic actions, session revocations, and rate limit events. Records show what happened, when, and to whom.

What the log deliberately does not contain is secrets. No passwords, no TOTP secrets or codes, no tokens, no complete cookies. A leaked audit page is embarrassing, not fatal.

The log is operational, not archival:

- Records live in the SQLite state file and are purged on a retention schedule, 30 days by default, configurable through `config.maintenance.audit_retention_hours`.
- Losing or resetting the state file loses the log with everything else in it.

If your organization needs audit history that survives, export the events you care about to your logging platform as they happen, rather than treating this view as long term storage.

## What the admin interface cannot do

The list of things it cannot do is as intentional as the list of things it can:

- It cannot create, edit, or delete users. Identity lives in YAML and changes through review.
- It cannot change client registrations or any other configuration.
- It cannot reveal root derived keys, signing keys, or stored hashes.
- It cannot increment a user's TOTP revision, that is a YAML change by design, so credential rotation always leaves an audit trail in your repository.

The result is an interface where the worst case for a compromised administrator password is bounded and visible: enrollment links, temporary locks, and readable history, all of it recorded.
