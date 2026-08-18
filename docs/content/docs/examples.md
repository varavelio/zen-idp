---
title: "Examples"
description: "Complete, ready-to-run stacks using Zen IdP. One command and they are up."
icon: "folder-code"
weight: 10
---

# Examples

The examples in this repository are complete stacks that run Zen IdP side by side with real software, end to end, with a single command. Each folder carries its own `compose.yaml` and `config.yaml`, so there is nothing to configure and nothing to generate:

```console
git clone https://github.com/varavelio/zen-idp.git
cd zen-idp/examples/<example>/
docker compose up
```

You only need Docker and an authenticator app for the TOTP codes. If you do not have one at hand, the [TOTP generator](https://soar.github.io/totp-generator) produces the same codes in your browser from the secret pasted into it.

## One demo user for every example

All the examples share the same hardcoded credentials, so you register alice's TOTP secret in your authenticator once and every stack accepts her. Each `config.yaml` spells out the demo values in comments right next to where they are used, including alice's TOTP secret. The stacks also share the same demo ports, so run one example at a time on the same machine.

<vara-alert
title="Hardcoded demo credentials"
description="Every secret in these examples is hardcoded and public so they run untouched: the root secret, the administrator password, the client secrets, and the demo user's TOTP secret are all written out in the files. That is deliberate, and it is the only reason nothing needs to be configured. For a real deployment always generate your own distinct and well-protected secrets with zen-idp generate-secrets; the examples are for learning, not for reuse."
color="warning"
/>

## OAuth2 Proxy: Protect any web app

<https://github.com/varavelio/zen-idp/tree/main/examples/oauth2-proxy>

[OAuth2 Proxy](https://oauth2-proxy.github.io/oauth2-proxy) sits in front of a web application and signs everyone in through Zen IdP before requests reach it. The application itself does not change, which is what makes this the right pattern for internal dashboards, home lab services, or any older tool that was never built with OIDC in mind. The example protects a small nginx demo page and prints the identity headers that OAuth2 Proxy forwards to it.

## Grafana: Sign in with Zen IdP

<https://github.com/varavelio/zen-idp/tree/main/examples/grafana>

[Grafana](https://github.com/grafana/grafana) is a dashboarding and metrics visualization tool that speaks OIDC natively. This example points its login at Zen IdP through Grafana's generic OAuth provider, so the Grafana sign-in page becomes the Zen IdP sign-in page, with the same identifier and TOTP flow as everywhere else.
