---
title: "Documentation"
description: "Everything you need to run Zen IdP: install it, declare users and clients, and operate it day to day."
icon: "book-open"
weight: 0
---

# Documentation

Zen IdP is a declarative OpenID Connect identity provider. You describe your users, your applications, and your security policy in YAML, you protect one root secret, and a single binary does the rest: TOTP sign-in, OIDC for your applications, and a small administration interface.

These pages are written for the person who runs Zen IdP, not the person who develops it. Every page explains what something does, why it works the way it does, and what you need to type.

## How to read this documentation

The pages follow the natural order of a deployment. If you are new, read them top to bottom:

1. [Get Started](/docs/get-started/) takes you from nothing to your first working login.
2. [Installation](/docs/installation/) covers Docker images and building from source.
3. [Configuration](/docs/configuration/) documents the complete YAML model, field by field.
4. [Users](/docs/users/) explains how identities are declared and managed.
5. [Clients](/docs/clients/) explains how applications are registered and connected.
6. [Authentication](/docs/authentication/) explains sign-in, enrollment, and recovery.
7. [Administration](/docs/administration/) covers the admin interface and the audit log.
8. [Security](/docs/security/) explains the trust model and where every secret lives.
9. [Operations](/docs/operations/) covers running, upgrading, rotating, and recovering.
10. [Examples](/docs/examples/) are practical examples, such as protecting any web application with OAuth2 Proxy, in addition to other guides and examples.

If you just want to see it work, start with [Get Started](/docs/get-started/) and come back to the rest when you need it.

## The three moving parts

Everything in Zen IdP reduces to three inputs, and it helps to keep them separate in your head from the beginning:

- **YAML configuration** holds every identity, client, and policy decision. It is the source of truth. If a user is in the YAML, the user exists. You change identity data the same way you change any other code: edit, review, deploy.
- **The root secret** (`ZEN_IDP_SECRET`) is one high-entropy value you keep in your secret manager. Zen IdP derives its signing key and every user's TOTP credential from it, deterministically, on every start. Nothing sensitive is stored to be stolen.
- **The state database** is a single SQLite file that holds sessions, one-use tokens, rate-limit counters, locks, and audit records. It is disposable operational state, not identity data. Lose it and nobody's identity changes, everyone just signs in again.

The rest of this documentation is what those three statements mean in practice.

## Where to go next

- New here? Go through [Get Started](/docs/get-started/).
- Evaluating for production? Read [Security](/docs/security/) and [Operations](/docs/operations/) before you deploy.
- Looking for a specific field? [Configuration](/docs/configuration/) has the complete reference.
