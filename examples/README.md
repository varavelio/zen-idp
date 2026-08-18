# Zen IdP examples

Runnable, self-contained examples that show Zen IdP working with real
software. Each folder is a complete stack you can start with Docker Compose
and explore.

> [!WARNING]
> Examples hardcode public credentials so they run without setup. They are
> for learning only: before any real deployment, generate every credential
> with `zen-idp generate-secrets` and follow the security guidance in the
> [documentation](https://zen-idp.varavel.com/docs/security/).

## Available examples

- [Protect any web app with Zen IdP + OAuth2 Proxy](./oauth2-proxy/) -
  put single sign-on in front of an existing web application, no code
  changes required.
