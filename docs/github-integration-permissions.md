# GitHub integration permission evidence

Open Trestle validates GitHub App permission posture through user visibility and a native broker-issued installation grant. This explicitly approved check can create an installation token. It remains separate from webhook signature validation, source acquisition, review execution, and publication.

## Token and endpoint roles

A short-lived GitHub App user access token calls `GET /user/installations`. GitHub documents this endpoint for user access tokens and includes each accessible installation's permission map, subscribed events, repository-selection mode, account, installation identifier, and suspension state.

After that user visibility check, the native setup-purpose broker may load the pinned App key, sign an App JWT, authenticate `GET /app/installations/{installation_id}`, and send `POST /app/installations/{installation_id}/access_tokens` for the exact numeric repository and read-only permission map. The accepted native grant binds the installation, repository, expiry, issuance attempt, and common and setup-purpose authorities. A caller-supplied opaque token or signed metadata object cannot substitute for this grant.

The inspector never revokes a token, changes installation repository selection, or changes App permissions. Token creation is a write effect with independent host common-authority approval, request consent, permission-authority approval, actor, scope, and current-plan fences. Configuration-only identities and the setup-service bearer token do not grant that effect.

## Admitted posture

The installation must be unsuspended, owned by the configured repository owner, and use selected-repository access. Its permission map must contain exactly:

- `metadata: read`
- `contents: read`
- `pull_requests: read`

Its event list must contain exactly `pull_request`. The native issued grant must cover exactly the configured repository. Extra permissions, write access, extra events, all-repository selection, extra repositories, inconsistent pagination, and crossed account or repository identity fail closed.

GitHub installation tokens are opaque. `GET /installation/repositories` cannot authenticate an arbitrary static token's installation lineage. The legacy token-provider inspector therefore refuses execution; its historical v1 identity remains available only for configuration inspection. Current evidence requires the real broker's authenticated issuance and durable accepted-attempt controls. User visibility and a native grant are separate observations, both required. Neither a browser digest, provider-supplied metadata, nor a configuration-only admin identity can mint successful evidence. A setup grant is not a daemon runtime-purpose grant or publication approval.

## Bounded protocol

The protected source-broker descriptor pins an exact API version and canonical endpoint, including an approved API base path where configured. The examples use `2026-03-10`; setup/admin admission requires a calendar-valid API date with year >=2000. Each inspector response is limited to 1 MiB. User installation discovery is limited to ten pages of 100 entries. The setup checker applies a 60-second total deadline around 30-second inspector requests. Native issuance independently validates the exact request, response, key pin, expiry, and durable attempt before exposing a grant. An unknown POST outcome is fenced, not retried as a new owner.

The inspector constructs and owns its transport; callers cannot supply one. It uses a private 10-second dialer, system trust roots, TLS 1.2 or newer, a 10-second TLS-handshake deadline, a 10-second response-header deadline, and a 1 MiB header limit. It permits HTTP/1 only and disables environment proxies, cookies, connection reuse, alternate TLS callbacks, and redirects. Plain HTTP is accepted only for numeric-loopback conformance fixtures.

Critical response objects use exact-member duplicate rejection. Permission members are also duplicate-checked before map decoding. Provider bodies, tokens, account data, repository names, installation IDs, and permission details do not enter setup state.

## Ownership and migration

See [Setup planning](setup.md#github-integration-permissions) for the exact descriptor fields, CLI/TUI flags, browser consent, and seven-field schema 2 configuration-only admin output. The descriptor remains schema 1. Active integration requests alone use schema 2; plan, receipt, result, and unrelated request wires remain schema 1. Old admin quartet output and historical receipts remain readable but cannot execute current integration or webhook operations.

The command, interactive TUI, or web handler owns one lazy setup session. It retains content-free owner and attempt records, not tokens. Cached tokens and foreground demand renewal stay within that owner lifetime. There is no background renewal, transparent generation replacement, or recovery by deleting owner records. Restart needs an explicit fresh generation and reapproval. Ownership is `single_host_exclusive`, even for `kubernetes_ha` plans.

Web shutdown cancels owner lifetime, allows five seconds for HTTP Shutdown and forces server Close on failure, then uses a separate bounded five-second credential drain. Incomplete cleanup is reported and cached; repeated Close does not prove later physical quiescence. Cleanup failure never rolls back a persisted receipt or accepted issuance. Receipt-only current pending recovery does not open a broker.

Old Ready is historical. Initialize a fresh protected state path and current plan, rerun all nondeterministic checks, and never import old receipts or rewrite old catalog bytes. The browser current marker is diagnostic only; the server independently gates integration and webhook before pending recovery. Runtime and publication approvals remain separate. No live issuance or owner-record deletion is authorized by this documentation.

## Official sources

- [List app installations accessible to the user access token](https://docs.github.com/en/rest/apps/installations?apiVersion=2026-03-10#list-app-installations-accessible-to-the-user-access-token)
- [List repositories accessible to the app installation](https://docs.github.com/en/rest/apps/installations?apiVersion=2026-03-10#list-repositories-accessible-to-the-app-installation)
- [Get an installation for the authenticated app](https://docs.github.com/en/rest/apps/apps?apiVersion=2026-03-10#get-an-installation-for-the-authenticated-app)
- [Create an installation access token for an app](https://docs.github.com/en/rest/apps/apps?apiVersion=2026-03-10#create-an-installation-access-token-for-an-app)
- [Authenticating as a GitHub App installation](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app-installation)
- [Generating a user access token for a GitHub App](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-user-access-token-for-a-github-app)
- [REST API versioning](https://docs.github.com/en/rest/about-the-rest-api/api-versions)
