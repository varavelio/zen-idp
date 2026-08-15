---
title: "Get Started"
description: "From zero to your first working login: generate secrets, write configuration, enroll a user, and connect an application."
icon: "rocket"
weight: 1
---

# Get Started

This walkthrough takes you from an empty machine to a working Zen IdP with one user who can sign in and one application that accepts that sign-in. It uses Docker, which is the quickest way to run a reliable deployment, and a local issuer URL so you can test without a domain or TLS.

Every step below produces something you can see, so you always know where you are. Expect the whole thing to take about fifteen minutes.

## 1. Pull the image

Zen IdP publishes images for amd64 and arm64 on Docker Hub and GitHub Container Registry:

```console
docker pull varavel/zen-idp:0.1.0-alpha.6
```

Pin the exact version you deploy. The `latest` tag only follows stable releases, so pinning keeps upgrades deliberate. See [Installation](/docs/installation/) for the full details, including the GHCR mirror.

## 2. Generate your bootstrap credentials

One command produces everything a fresh deployment needs:

```console
docker run --rm varavel/zen-idp:0.1.0-alpha.6 generate-secrets
```

The output looks like this, with real values instead of the placeholders:

```text
WARNING: This output contains plaintext credentials. Store it securely.

Root secret
ZEN_IDP_SECRET=...

Administrator
plain: ...
hash: "..."

OIDC client
plain: ...
hash: "..."

Important:
- Store plaintext values securely.
- Put only hashes in YAML.
- Never reuse one OIDC client secret or its hash across different clients.
- Each execution creates a completely independent credential bundle.
- When adding another client, use only the new OIDC client section.
- Do not replace the root secret or administrator credentials unless intentionally rotating them.
```

Three values matter right now:

- **Root secret** goes into the environment of the service, never into YAML.
- **Administrator plain and hash** give you access to the admin interface. You sign in with the plain value and put the hash in YAML.
- **OIDC client plain and hash** are the credentials of your first application. The application gets the plain value, the YAML gets the hash.

<vara-alert
title="Treat the output as sensitive"
description="It contains every plaintext credential of your new deployment. Copy it somewhere safe first, then clear it from your terminal history. Only the Argon2id hashes ever belong in YAML."
color="warning"
/>

Save the output now. You will paste parts of it into the configuration and the environment in the next steps.

## 3. Write your configuration

Create a directory for your deployment and a configuration file inside it:

```text
zen-idp/
  config/
    zen-idp.yaml
```

Open `config/zen-idp.yaml` and start with this:

```yaml
config:
  # The public URL of your Zen IdP. HTTP is accepted here because this guide
  # runs locally; production issuers must be HTTPS.
  issuer: "http://localhost:8080"

  # The administrator signs in with the generated plain password.
  # Paste the generated administrator hash here, never the plain value.
  security:
    admin_password_hash: "$argon2id$..."

clients:
  # Your first application. It authenticates with the generated client
  # plain secret, so it is a confidential client.
  - id: "my-app"
    name: "My App"
    secret_hash: "$argon2id$..."
    redirect_uris:
      - "http://localhost:3000/callback"

users:
  # The smallest valid user. This person signs in with "alice" and a TOTP
  # code from their authenticator app.
  - sub: "alice"
    name: "Alice"
    email: "alice@example.com"
```

This is a complete, working configuration. A few things worth noticing:

- `issuer` is the base URL for every endpoint. Localhost with HTTP is fine for this walkthrough. Real deployments use an HTTPS URL behind a reverse proxy.
- The two hashes are the ones `generate-secrets` printed. The application's redirect URI must match exactly what the application will send later, character by character.
- Every field beyond `sub` on a user is optional, including `name` and `email`. See [Users](/docs/users/) for the full model, including custom claims.

## 4. Validate before you run

Make a habit of validating configuration before every deploy. It runs the exact same discovery and validation as startup, so if it passes, `serve` will start:

```console
docker run --rm \
  -v ./config:/data/config \
  varavel/zen-idp:0.1.0-alpha.6 \
  validate-config
```

The image expects configuration in `/data/config` by default, which is why mounting your `config` directory is enough. Validation deliberately does not need the root secret or the database, so you can also run it in CI on every commit.

If validation fails, the error tells you the exact file and the exact problem. Fix it and repeat until you get a clean pass.

## 5. Run the service

Run it with your configuration mounted, the state directory writable, and the root secret in the environment:

```console
docker run -d \
  --name zen-idp \
  -p 8080:8080 \
  -v ./config:/data/config \
  -v ./state:/data/db \
  -e ZEN_IDP_SECRET="paste the generated root secret here" \
  varavel/zen-idp:0.1.0-alpha.6
```

Then check that it is healthy:

```console
curl http://localhost:8080/health
```

The image also ships a built-in health check that runs the same probe every 30 seconds, so your container engine reports the real state of the service. The first start takes a moment because the signing identity is derived from the root secret, but you should see `ok` within seconds.

<vara-alert
title="About the state directory"
description="The container runs as an unprivileged user with UID 65532. Make sure the directory you mount at /data/db is writable by that user, for example with chown 65532:65532 ./state on Linux."
color="info"
/>

## 6. Enroll your first user

Users cannot sign in until they have enrolled an authenticator app, and enrollment happens through a one-time link.

1. Open `http://localhost:8080/admin` and sign in with the administrator plain password from step 2.
2. Find your user `alice`, create an enrollment token, and give it a lifetime, for example one hour.
3. The admin interface gives you a one-time enrollment link. Open it in the browser where you will set up the authenticator, or send it to Alice over a channel you trust.
4. The enrollment page shows a QR code. Scan it with any authenticator app, such as Aegis, 1Password, Google Authenticator, or Bitwarden.
5. The link works exactly once. When the QR has been shown, the token is consumed.

The credentials never left your machine: the TOTP secret is derived from your root secret and Alice's subject, encoded into a standard enrollment QR, and shown once to exactly the right person. See [Authentication](/docs/authentication/) for the complete flow, including what to do when someone loses their device.

## 7. Sign in through your application

There is no standalone login page to visit by design. Signing in always happens as part of an application's OIDC flow, which is what makes it single sign-on.

Point your application at Zen IdP with the values it asks for:

| The application asks for            | You give it                      |
| ----------------------------------- | -------------------------------- |
| Issuer, discovery URL, or authority | `http://localhost:8080`          |
| Client ID                           | `my-app`                         |
| Client secret                       | the generated client plain value |
| Redirect / callback URL             | `http://localhost:3000/callback` |
| Scopes                              | `openid` is enough               |

Open your application, ask it to sign you in, and it will redirect to Zen IdP. Enter `alice` and the six digit code from the authenticator. You come back signed in, and the application has received an ID token with Alice's claims.

The next application you register gets the same treatment, and Alice signs in once for all of them until her session expires.

## 8. What just happened

You now have a complete identity provider:

- Configuration lives in a file you can review and version.
- The root secret derives the signing key and Alice's TOTP credential from thin air, nothing sensitive is stored.
- The state directory holds a SQLite file with Alice's session and nothing else of value.
- The admin interface can issue enrollment tokens for new users, and the audit log records what you did in it.

When you are ready for the real thing, with a domain and TLS, continue with [Installation](/docs/installation/) for deployment details and [Operations](/docs/operations/) for running behind a reverse proxy, upgrades, and backups.
