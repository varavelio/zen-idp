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

<landing-hero />

<vara-features
container="lg"
title="Why Zen IdP"
description="Built on a few deliberate decisions that keep the whole system small and understandable."
columns="3"
item_1_icon="file-code"
item_1_title="Identity as code"
item_1_description="Every user, client, and custom claim is a YAML file you can review, version, and audit like any other code. Changes ship through pull requests, not through an admin panel."
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
item_4_description="Authorization code flow with PKCE, RS256 signing, discovery, JWKS, and /userinfo. Every OIDC-capable application can connect directly."
item_4_badge="PKCE S256"
item_5_icon="database"
item_5_title="Disposable state"
item_5_description="Sessions, one-use tokens, rate limits, locks, and audit records live in an embedded SQLite file. It holds operational state only: identities and credentials always come from YAML and the root secret."
item_5_badge="SQLite"
item_6_icon="lock-keyhole"
item_6_title="Free and open source"
item_6_description="MIT-licensed and fully self-hosted. Zen IdP runs entirely on your own infrastructure, so your identities never depend on a vendor's availability or pricing."
item_6_badge="MIT"
/>

<vara-content-split
container="lg"
eyebrow="How it works"
title="From YAML to single sign-on"
description="The whole journey is visible. You declare the identity layer, and the service handles the rest."
item_1="Declare identities, clients, and redirect URIs in YAML, split across as many files as you like"
item_2="Generate a root secret plus the administrator and client hashes with one command"
item_3="Run the binary behind your reverse proxy and hand out one-time enrollment links"
item_4="Applications redirect to Zen IdP, users authenticate with TOTP, and everyone gets back to work"
panel_icon="workflow"
panel_title="Nothing to babysit"
panel_description="Sessions, tokens, rate limits, and cleanup are handled internally, and restarts preserve state. The database is purely operational and never the source of truth."
heading_level="2"
/>

<vara-features
container="lg"
eyebrow="Use cases"
title="Where Zen IdP fits"
description="A focused identity layer for people who want to own their sign-in."
columns="3"
item_1_icon="server"
item_1_title="Internal team SSO"
item_1_description="One shared sign-in for all the internal tools your team runs itself, with no third-party identity provider in the middle."
item_1_badge="Teams"
item_2_icon="house"
item_2_title="Home labs"
item_2_description="A single binary with no external services fits on any small server. Declare your users in YAML, run it behind your reverse proxy, and move on."
item_2_badge="Home labs"
item_3_icon="wifi-off"
item_3_title="Offline environments"
item_3_description="Everything runs locally with no external calls, so Zen IdP works in air-gapped networks where cloud identity providers are not an option."
item_3_badge="Air-gapped"
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
stat_2_description="Nothing to install or connect beyond the binary itself."
stat_3_value="3"
stat_3_label="CLI commands"
stat_3_description="serve, validate-config, and generate-secrets."
stat_4_value="MIT"
stat_4_label="License"
stat_4_description="Free, open source, and fully self-hosted."
/>

<vara-faq container="lg" title="Common questions" description="The things people usually ask before adopting Zen IdP." open_first="true" heading_level="2">
<vara-faq-item id="what-is-zen-idp" question="What exactly is Zen IdP?">
Zen IdP is a declarative OpenID Connect identity provider. It authenticates your people with TOTP and lets every OIDC-capable application accept those identities through single sign-on. Everything is managed as YAML in your repository, not through an admin panel.
</vara-faq-item>
<vara-faq-item id="who-is-it-for" question="Who is Zen IdP for?">
Anyone who wants to own their identity layer. It suits teams that self-host their internal tools and prefer not to depend on a third-party identity provider, home lab owners who want single sign-on across their services, and networks that need an identity provider that works offline. If you manage a handful of tools and want one clean sign-in, Zen IdP is for you.
</vara-faq-item>
<vara-faq-item id="external-services" question="Do I need a database or a directory service?">
No. Zen IdP is a single Go binary with an embedded SQLite file that holds disposable operational state: sessions, one-use tokens, rate limits, temporary locks, and short-lived audit records. Identities come from YAML and the root secret, so there is no external database, no LDAP, and no Active Directory to keep in sync.
</vara-faq-item>
<vara-faq-item id="how-users-sign-in" question="How do my users sign in?">
With an authenticator app. Each user's TOTP secret is derived deterministically from the root secret, so there are no passwords to store and no email to deliver. An administrator creates a one-time enrollment link for each user, and the user scans it into their authenticator once.
</vara-faq-item>
<vara-faq-item id="which-apps" question="Which applications can I connect?">
Any application that speaks OIDC. Zen IdP implements the authorization code flow with PKCE, RS256 signing, discovery metadata, JWKS, and /userinfo, so the self-hosted tools you already run can connect without custom work.
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
description="Declare your users, choose a root secret, and give your internal tools one shared sign-in. Free, open source, and self-hosted."
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
