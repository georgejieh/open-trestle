# GitHub integration permissions check

Before Open Trestle works with a GitHub repository, an operator can check that the GitHub App installed on it has the permissions Open Trestle needs and no more. This page describes that check. It is separate from webhook signature validation, source acquisition, review execution, and it requires explicit approval because it can create an installation token. No current setup profile requires this check.

## Tokens and endpoints

The check combines two observations, and both are required.

The first observation comes from a short-lived GitHub App user access token, which calls `GET /user/installations`. GitHub documents this endpoint for user access tokens. For each installation the user can see, it returns the permission map, the subscribed events, the repository-selection mode, the account, the installation ID and whether the installation is suspended.

The second observation comes from the native setup-purpose broker. The broker is the component that holds the App key and issues tokens. After the user visibility check, it may load the pinned App key, sign an App JWT, authenticate `GET /app/installations/{installation_id}`, and send `POST /app/installations/{installation_id}/access_tokens` for the exact numeric repository and a read-only permission map. The accepted native grant records the installation, the repository, the expiry, the issuance attempt, and the host's approvals for the common and setup purposes. A token or signed metadata object supplied by a caller cannot take the place of this grant.

The inspector does not revoke a token, change which repositories an installation can see, or change App permissions. Creating a token is a write, so it needs several approvals: the host's common approval, the request's consent, the approval of the permission check, and matching actor, scope and current-plan checks. Configuration-only identities and the setup-service bearer token do not give that approval.

GitHub installation tokens are opaque, and `GET /installation/repositories` cannot show which installation an arbitrary static token came from. The older token-provider inspector therefore refuses to run, and its v1 identity is available only for inspecting configuration. A successful result requires the broker to issue the token in an authenticated call and record the accepted attempt durably. A browser digest, provider-supplied metadata or a configuration-only admin identity cannot produce one. A setup grant is not a daemon runtime grant.

## Accepted permissions

The installation passes the check only if it meets all of these conditions:

- It is not suspended.
- It belongs to the configured repository owner.
- It uses selected-repository access.
- Its permission map contains exactly `metadata: read`, `contents: read` and `pull_requests: read`.
- Its event list contains exactly `pull_request`.

Source acquisition uses `contents: read` for commit objects, recursive trees, tar archives and one commit comparison. GitHub lists the comparison (`GET /repos/{owner}/{repo}/compare/{base}...{head}`) under the Contents read permission, so it needs no new permission. The daemon reads it because a pull request is reviewed from the merge base of its base and head, and the webhook payload does not carry that. See [GitHub source acquisition](github-source-acquisition.md#merge-base) and GitHub's [permissions required for GitHub Apps](https://docs.github.com/en/rest/authentication/permissions-required-for-github-apps).

The native grant must cover exactly the configured repository. The check fails, and nothing proceeds, in any of these cases: extra permissions, write access, extra events, all-repository selection, extra repositories, inconsistent pagination, or an account or repository identity that does not match.

## Limits and transport

The protected source-broker descriptor pins an exact API version and a canonical endpoint, including an approved API base path where one is configured. The examples use `2026-03-10`. Setup and admin approval require a valid calendar date with a year of 2000 or later.

- Each inspector response is limited to 1 MiB.
- User installation discovery is limited to ten pages of 100 entries.
- The setup checker applies a 60-second total deadline around inspector requests of 30 seconds each.
- Native issuance separately validates the request, the response, the key pin, the expiry and the durable attempt before it exposes a grant.
- If the outcome of a `POST` is unknown, the attempt stays blocked. It is not retried as a new owner.

The inspector builds its own transport, and callers cannot supply one. The transport has these properties:

- It uses a private 10-second dialer, the system trust roots and TLS 1.2 or newer.
- It sets a 10-second TLS-handshake deadline, a 10-second response-header deadline and a 1 MiB header limit.
- It permits HTTP/1 only.
- It disables environment proxies, cookies, connection reuse, alternate TLS callbacks and redirects.
- It accepts plain HTTP only for numeric-loopback test fixtures.

For critical response objects, a duplicate member is an error. Permission members are also checked for duplicates before the map is decoded. Provider response bodies, tokens, account data, repository names, installation IDs and permission details do not enter setup state.

## Ownership and migration

The seven-field schema 2 admin output holds configuration only. The descriptor stays at schema 1. Only active integration requests use schema 2. The plan, receipt, result and unrelated request formats stay at schema 1. Output in the old four-field admin format, and old receipts, can still be read but cannot run current integration or webhook operations.

The command, the interactive TUI or the web handler owns one lazy setup session. The session keeps owner and attempt records that hold no content and no tokens. Cached tokens and renewals that a foreground request triggers stay within the lifetime of that owner. There is no background renewal, no transparent replacement of a generation, and no recovery by deleting owner records. After a restart you need a new generation and a new approval. Ownership is `single_host_exclusive`.

On web shutdown, Open Trestle cancels the owner's lifetime, waits up to five seconds for the HTTP server to shut down (forcing a close if that fails), and then allows a separate five-second period to drain credentials. If cleanup is incomplete, the web handler reports it and caches the result. A cleanup failure does not roll back a saved receipt or an accepted issuance. Recovering a pending receipt, with no broker involved, does not open a broker.

A Ready result from an older setup is historical. To start again, initialize a fresh protected state path and a current plan, rerun every check that is not deterministic, and do not import old receipts or rewrite old catalog bytes. The current marker in the browser is only a diagnostic. The server checks integration and webhook state itself before recovering anything pending. Runtime approvals remain separate.

## Official sources

- [List app installations accessible to the user access token](https://docs.github.com/en/rest/apps/installations?apiVersion=2026-03-10#list-app-installations-accessible-to-the-user-access-token)
- [List repositories accessible to the app installation](https://docs.github.com/en/rest/apps/installations?apiVersion=2026-03-10#list-repositories-accessible-to-the-app-installation)
- [Get an installation for the authenticated app](https://docs.github.com/en/rest/apps/apps?apiVersion=2026-03-10#get-an-installation-for-the-authenticated-app)
- [Create an installation access token for an app](https://docs.github.com/en/rest/apps/apps?apiVersion=2026-03-10#create-an-installation-access-token-for-an-app)
- [Authenticating as a GitHub App installation](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app-installation)
- [Generating a user access token for a GitHub App](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-user-access-token-for-a-github-app)
- [REST API versioning](https://docs.github.com/en/rest/about-the-rest-api/api-versions)
