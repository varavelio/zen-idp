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

- [Sign in to Grafana with Zen IdP](./grafana/) -
  OIDC single sign-on for Grafana through its generic OAuth provider.

- [Monitor services with Gatus](./gatus/) -
  Gatus is a lightweight health dashboard that checks services on an interval and shows their status at a glance. In this example it watches three public websites (GitHub, Google and Wikipedia) enough to see the checks going green. The dashboard itself is locked behind a Zen IdP sign-in.

- [One-click actions with OliveTin](./olivetin/) -
  OliveTin is a web dashboard of one-click actions that run shell commands. In this example it shows three ping buttons (against GitHub, Google and Wikipedia) and the whole dashboard is locked behind a Zen IdP sign-in, so guests are bounced to the login before they see anything.
