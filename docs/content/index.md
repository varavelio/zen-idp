---
title: "Zen IdP"
description: "A declarative, zero-maintenance OIDC Identity Provider."
---

<vara-header
container="lg"
links="Documentation|/docs/get-started/,Installation|/docs/installation/,GitHub|https://github.com/varavelio/zen-idp"
cta_label="Get Started"
cta_href="/docs/get-started/"
/>

<vara-hero
container="lg"
eyebrow="Zen IdP"
title="Single sign-on for your internal tools, declared as code"
description="Zen IdP is a declarative OpenID Connect provider for small and medium teams. Your users, clients, and claims live in YAML, one root secret drives everything cryptographic, and a single binary handles the rest. No database to back up, no directory to sync, no passwords to reset."
primary_label="Get Started"
primary_href="/docs/get-started/"
secondary_label="Installation"
secondary_href="/docs/installation/"
panel_icon="shield-check"
panel_title="What you get"
panel_description="A standard OIDC provider your applications already know how to talk to."
item_1="Grafana, Argo CD, Portainer, Vault, and custom apps sign in through OIDC"
item_2="Users authenticate with TOTP, no passwords or email involved"
item_3="Configuration changes flow through pull requests"
caption="Written in Go, distributed as a single executable."
/>

<vara-features
container="lg"
title="Why Zen IdP"
description="A focused identity provider built for teams that prefer code over admin panels."
columns="3"
item_1_icon="file-code"
item_1_title="Identity as code"
item_1_description="Users, clients, and custom claims are YAML files you can review, version, and audit like any other code. Changes ship through pull requests, not through an admin panel."
item_1_badge="YAML"
item_2_icon="key-round"
item_2_title="One root secret"
item_2_description="A single ZEN_IDP_SECRET derives the OIDC signing key and every user's TOTP credential. Nothing cryptographic is stored in the database, so recovery is deterministic."
item_2_badge="Root secret"
item_3_icon="scan-line"
item_3_title="TOTP authentication"
item_3_description="Users sign in with their identifier and a code from their authenticator app. No passwords to store, no email to deliver, no SMTP to operate."
item_3_badge="TOTP"
item_4_icon="blocks"
item_4_title="Standard OIDC"
item_4_description="Authorization code flow with PKCE, RS256 signing, discovery, JWKS, and /userinfo. Every OIDC-capable application works out of the box."
item_4_badge="OpenID Connect"
item_5_icon="database"
item_5_title="Disposable state"
item_5_description="Sessions, one-use tokens, rate limits, locks, and audit records live in an embedded SQLite file. It is operational state, not a source of truth, so it needs no backups."
item_5_badge="SQLite"
item_6_icon="terminal"
item_6_title="One small binary"
item_6_description="Everything ships as a single Go executable with no runtime dependencies. Point it at your YAML and secret, terminate TLS at your reverse proxy, and you are done."
item_6_badge="Go"
/>

<vara-content-split
container="lg"
eyebrow="How it works"
title="From YAML to single sign-on"
description="The whole journey is visible. You declare the identity layer, and the service handles the rest."
item_1="Declare users, clients, and redirect URIs in YAML, split across as many files as you like"
item_2="Generate a root secret plus the administrator and client hashes with one command"
item_3="Run the binary behind your reverse proxy and hand out one-time enrollment links"
item_4="Applications redirect to Zen IdP, users authenticate with TOTP, and everyone gets back to work"
panel_icon="workflow"
panel_title="Nothing to babysit"
panel_description="Sessions, tokens, rate limits, and cleanup are handled internally. Restarts preserve state, and the database never holds anything you cannot recreate from YAML and the root secret."
heading_level="3"
/>

<vara-stats
container="lg"
title="Small by design"
description="Zen IdP stays focused so you can understand every part of it."
columns="4"
stat_1_value="1"
stat_1_label="Binary to run"
stat_1_description="A single Go executable, nothing else to install."
stat_2_value="0"
stat_2_label="External services"
stat_2_description="No database, directory, SMTP, or third-party identity provider."
stat_3_value="3"
stat_3_label="CLI commands"
stat_3_description="serve, validate-config, and generate-secrets."
stat_4_value="10-500"
stat_4_label="Users per config"
stat_4_description="Comfortable with hand-maintained YAML, more with split or generated files."
heading_level="3"
/>

<vara-faq container="lg" title="Common questions" description="The things people usually ask before adopting Zen IdP." open_first="true" heading_level="3">
<vara-faq-item id="what-is-zen-idp" question="What exactly is Zen IdP?">
Zen IdP is a declarative OpenID Connect identity provider for small and medium teams. It authenticates your people with TOTP and lets every OIDC-capable application accept those identities through single sign-on. Users, clients, and claims are managed as YAML in your repository, not through an admin panel.
</vara-faq-item>
<vara-faq-item id="external-services" question="Do I need a database or a directory service?">
No. Zen IdP is a single Go binary with an embedded SQLite file that holds disposable operational state: sessions, one-use tokens, rate limits, temporary locks, and short-lived audit records. Identities come from YAML and the root secret, so there is no external database, no LDAP, and no Active Directory to keep in sync.
</vara-faq-item>
<vara-faq-item id="how-users-sign-in" question="How do my users sign in?">
With an authenticator app. Each user's TOTP secret is derived deterministically from the root secret, so there are no passwords to store and no email to deliver. An administrator creates a one-time enrollment link for each user, and the user scans it into their authenticator once.
</vara-faq-item>
<vara-faq-item id="which-apps" question="Which applications can I connect?">
Any application that speaks OIDC. Zen IdP implements the authorization code flow with PKCE, RS256 signing, discovery metadata, JWKS, and /userinfo. Grafana, Argo CD, Prometheus, Portainer, Vault, and internal dashboards are typical fits.
</vara-faq-item>
<vara-faq-item id="revoke-access" question="How do I revoke access for someone?">
The way you would expect from a code-first provider: remove or expire the user in YAML and the change applies immediately. For temporary situations, the admin interface can lock a user and revoke all of their sessions at once. Rotating one user's credential is a one-line revision bump in YAML.
</vara-faq-item>
<vara-faq-item id="authorization" question="Does Zen IdP decide what users can do?">
No. Zen IdP answers who is signing in. Every declared custom claim, such as groups or roles, is released in the ID token and /userinfo response, and your applications decide what the user may do. Zen IdP never interprets those claims itself.
</vara-faq-item>
</vara-faq>

<vara-cta
container="lg"
title="Put your identity layer in the repository"
description="Declare your users, choose a root secret, and give your internal tools one shared sign-in."
primary_label="Get Started"
primary_href="/docs/get-started/"
secondary_label="Installation"
secondary_href="/docs/installation/"
/>

<vara-footer
container="lg"
copyright="A Varavel project &copy; %year%"
links="Documentation|/docs,GitHub|https://github.com/varavelio/zen-idp"
github_href="https://github.com/varavelio/zen-idp"
github_label="Zen IdP on GitHub"
/>
