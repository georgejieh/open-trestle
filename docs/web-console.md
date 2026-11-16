# Web console

The web console is a read-only browser view of one Open Trestle review run. `trestled` serves it at `/console/`, and it uses the same authenticated REST API as the CLI and the editor clients. It shows a run that the daemon already holds. It cannot start a review, and it is not a way to review your own change: use `trestle review` for that.

The console has no way to publish, change policy, take a worker lease, run a shell, edit source or execute tools. `/console` redirects to `/console/`. The daemon's routes are listed in the [daemon API](daemon-api.md#http-contracts).

## Connect to a run

Enter one exact tenant ID, repository ID, review run ID and API token. The console makes only these requests:

- `GET /api/v1/tenants/{tenant}/repositories/{repository}/runs/{run}`
- `GET /api/v1/tenants/{tenant}/repositories/{repository}/runs/{run}/progress`
- `GET /api/v1/tenants/{tenant}/repositories/{repository}/runs/{run}/diagnostics`
- `GET /api/v1/tenants/{tenant}/repositories/{repository}/runs/{run}/refusal`, only when the run is not found
- `GET /api/v1/tenants/{tenant}/repositories/{repository}/runtime`

The token stays in React memory for the current page and is sent only in the `Authorization` header. It is never placed in a URL, in browser storage, in a log message, in an error message or in a rendered view. The console may keep the tenant, repository and run, which are not secret, in session storage. If that storage is blocked or full, the connection still works, but the scope is not saved.

When you change the scope, the console clears the in-memory token, discards pending UI updates, and stops late responses from starting more reads with the old token. Requests that were already sent may still finish.

If a refresh times out or the daemon is unavailable, the console keeps the last verified receipt, the in-memory token and the selected task. It clears the counts that come from artifacts and shows an alert that names the journal revision on display. Failures of authentication, authorization, scope or validation still end the session.

The browser client rejects all of these:

- Invalid scopes.
- Unsafe tokens.
- Redirects.
- Unexpected media types.
- Unknown object fields.
- Receipts from another scope.
- Malformed identities.
- Invalid state values.
- Response shapes that are inconsistent.

It streams response bodies through a counter that allows a 1 MiB payload plus 4 KiB of API framing, and it cancels on overflow before the whole body is buffered. Its requests use no-store caching and omit ambient credentials, and it applies a 15-second timeout. Repository and diagnostic text is rendered only through React text nodes.

The console does not infer review success from daemon health. It does not infer authority to publish from publication readiness.

## Views

A shortened visual identity includes the full digest as assistive text and in the accessible name of the copy action. A missing diagnostic set is labeled `n/a`, never zero.

### Overview

The overview shows the exact run status, the journal revision, the number of completed tasks, the number of review results (aware of the schema), the content-addressed identities of the boundaries, and the progress counts that come from artifacts, from the `progress` route.

### Tasks

The tasks view shows the task journal, which is derived by replaying the run. An inspector shows each task's attempts, failures, recorded failure reason, handler identity, input and output. The overview lists each recorded reason next to the run's failure.

The console accepts three receipt versions and refuses a receipt whose version does not match its tasks:

- Version 1.
- Version 2, which adds a linked context abstention.
- Version 3, which adds a source failure reason on source acquisition, a context route refusal on context assembly, or a provider refusal on candidate generation or verification.

A provider refusal shows a label, the explanation and a `Hint` with the same action as the local review. The console accepts these refusals, each paired with a failure kind. A refusal with any other failure, or on any other task kind, is rejected.

| Refusal | Failure | Label (where this page names one) |
| --- | --- | --- |
| `provider_payment_required` | `policy` | none named |
| `provider_model_unavailable` | `policy` | none named |
| `provider_model_retired` | `policy` | none named |
| `provider_authentication_failed` | `policy` | none named |
| `provider_authorization_denied` | `policy` | none named |
| `provider_request_rejected` | `policy` | Provider request rejected |
| `provider_rate_limited` | `transient` | none named |
| `provider_response_invalid` | `internal` | Provider reply refused |
| `model_output_invalid` | `internal` | Model answer not a review document |

A `route_context_insufficient` refusal carries its token counts. It shows the same hint as the local review: the required, input, output and declared counts, and the context length to raise. A `no_eligible_route` refusal carries no counts.

When a run is not found, the console reads the scope's delivery refusal (`GET .../refusal`). If intake refused that webhook delivery instead of opening its run, the connection ends with a message. The message names the reason token, a fixed explanation and the time of the refusal. The console validates the refusal against the exact scope, and it carries no delivery content.

### Runtime

The runtime view shows the storage posture for the repository, the configuration identities that are not secret, the exact handler bindings with controls to copy their full values, and whether the supervised services are ready. A token without runtime access does not block the run or diagnostics views.

### Review

The review view is a queue for human review. How it presents a result depends on the diagnostic-set version.

For versions 1 through 5, the independently verified finding totals stay separate from the outcomes of deterministic checks:

- Version 2 also shows the exact counts of accepted, verified, rejected and inconclusive candidates.
- Version 3 ties in the validated verification-context identity. It adds bounded counts of analyzed, selected and omitted sources.
- Version 4 adds sorted reasons for omissions, as aggregates that contain no content.
- Version 5 adds one deterministic static-debug check that contains no content, with an exact lineage to the analysis and the change.

The check appears as a `Cleared gate`, `Failed check`, `Incomplete check` or `Abstention`. Only a pass with full coverage and zero matches counts as cleared, and only for that exact rule. Not applicable means that no changed Go range could be checked, and it does not clear the rule. The console does not present rejected candidates as cleared deterministic gates. It labels any inconclusive candidate or omitted source count as incomplete. Source counts and reasons do not claim coverage of the whole repository and do not expose paths.

The console never presents candidate model output as a finding. When the verified set is empty, the console states that zero findings and terminal coverage do not approve the change or prove it correct. Versions 1 through 4 remain readable, with no invented check outcomes.

Versions 6 and 7 are different:

- Version 6 shows the exact deterministic observations and the rule coverage instead. It has no verified finding set, and the console labels every observation as deterministic and not independently verified.
- Version 7 is the final full-review result. It names the terminal outcome and shows only the deterministic and verified parts it carries. A failed result whose context task recorded a route refusal also shows that refusal, with the same hint for `route_context_insufficient`.
- A result recorded after the run's evidence retention lapsed carries `evidence_expired` and no evidence part. The console says that the outcome comes from the run journal only and that no findings or observations are available. This is not a clear result.

Each verified finding and each deterministic observation has a closed `Inspect evidence` disclosure:

- A verified finding shows the exact diagnostic identity, the source finding identity, the finding fingerprint and every evidence reference.
- A deterministic observation shows the observation, analysis-result, check, fingerprint and evidence identities, without calling them verified.

Long values are shortened on screen, while assistive text and the copy controls keep the complete value. The review console and the guided setup share one copy implementation for identity rows. After a successful clipboard write, the console announces `Copied`. If the clipboard is unavailable or rejects the write, it announces `Copy failed`, without exposing a browser error or the value. When you click quickly several times, only the newest attempt can update the feedback, and its message keeps its full lifetime. If a refreshed identity changes, the feedback for the previous value disappears, so it cannot appear next to the new value. The disclosure does not fetch or render source, evidence or model payloads.

## Guided setup surface

`trestle setup web --state PATH` serves the same self-contained assets on a numeric loopback listener, and it opens the setup mode at `/console/setup`. Unlike the daemon console, this local surface has a narrow API that writes receipts. It uses a dedicated `OPEN_TRESTLE_SETUP_TOKEN`, which must differ from the operator and observer tokens. The server accepts only its exact numeric loopback Host authority.

The setup client calls only these routes:

- `GET /api/v1/setup`
- `POST /api/v1/setup/init`
- `POST /api/v1/setup/check`

### Available checks

The guided checker covers the following:

- Local-administrator approval.
- Exact validation of a protected backup snapshot.
- PostgreSQL authority.
- KMS secret-backend and envelope-storage checks.
- Remote-provider authorization.
- GitHub integration-permission inspection.
- Local GitHub webhook conformance.
- PostgreSQL shared API rate-limit conformance.
- Storage and observer credentials.
- Runtime policy.
- Explicit local inference.
- The dry run that publishes nothing.

Creating and restoring a snapshot remain explicit CLI operations. Local inference stays disabled until the exact policy receipt exists. Its confirmation makes at most two calls to fixed, independently routed numeric-loopback addresses and requires both to pass within one 90-second bound. It does no retry, fallback, publication or dynamic validation.

The backup result covers setup state only. It does not claim that the media is independent, or that disaster recovery works.

### What each check does

The envelope-storage check keeps its S3 and KMS configuration and its approval values in browser memory only. Its separate confirmation lets the server create, read, exactly delete, and verify the absence of one fixed public object that has envelope encryption. If a failure is partial, the deterministic encrypted object can remain, so that you can retry with exactly the same authority. A pass requires the object to be absent. The check grants no general deletion or other authority to act.

The GitHub integration-permission check keeps only non-secret fields in browser memory: endpoint, version, installation, repository and approval. The dedicated GitHub setup token and the separate runtime installation token stay in the server environment. After confirmation, the server makes bounded, read-only GET requests for the installation and the repository. It cannot modify the integration.

The GitHub webhook conformance check keeps only a non-secret authority identity, key ID and approver in browser memory, and it renders no secret field. It requires the passing integration receipt. After confirmation and the stale-plan fence, the server reads the webhook secret. It runs five direct requests inside the process against the production handler and a disposable private file inbox, clears the verifier, and removes the inbox before it passes. It opens no listener and makes no GitHub request.

The Kubernetes HA shared-rate-limit check shows only the approved conformance and database identities and the name of the approver. After the PostgreSQL and stale-plan fences, the server reads the database URL and runs the bounded quota cycle across instances. A pass requires exact cleanup of the namespace. Replica reconciliation uses the same credential boundary to prove several things: that both stores see the plan, that notifications and task leases are fenced, that completion works across instances, that the run converges to a terminal state, and that the disposable scope is cleaned up exactly. No database credential enters the browser or the setup state.

The air-gapped signed-bundle check keeps only these values in browser memory: the absolute path, and the public digest, size, Ed25519 key, signature, authority and approver. It streams one opaque file. It makes no claim about extraction, import, execution, archives, SBOMs, provenance, malware or the absence of network egress.

The remote-provider authorization check reuses the protected runtime configuration paths and three exact approval identities. It reads no provider credential value and makes no provider request. Its receipt grants no authority to dispatch or publish.

The KMS check keeps its region, key ARN, optional endpoint and approval values in browser memory only. After confirmation, the server reads AWS credentials from its environment and performs one bounded generate and unwrap sequence. It stores no key material and makes no S3 request. It proves neither that envelope storage is ready nor any authority to act.

### Confirmation and validation

Initialization and every check each need their own inline confirmation. A check request binds the exact plan identity on display and `run REQUIREMENT_KEY`. The service revalidates the protected state before it opens a writer, and the setup runner fences out stale transitions. The browser saves no setup token, path, approval identity or progress value, and it omits cookies and other ambient credentials. Before displaying a response, the browser validates it against the closed setup profiles, the posture relationships, the ordered requirements, the checker authorities, the receipt history, the derived readiness and the binding to the latest receipt.

The guided path can create a plan and run these built-in checks:

- Local and PostgreSQL storage.
- Envelope storage.
- KMS secret backend.
- Remote-provider authorization.
- GitHub integration-permission inspection.
- GitHub webhook conformance.
- PostgreSQL shared-rate-limit conformance.
- Replica reconciliation.
- Signed offline bundle.
- Local administrator.
- Backup snapshot.
- Observer credential posture.
- Exact policy.
- Explicit local inference.
- The dry run that publishes nothing.

It does not invent results for checks that have no built-in implementation. Those requirements stay pending, with a clear explanation. The dry run stays local and deterministic. It has no publisher, source writer, process runner, credential resolver or network client.

## Browser boundary

The embedded handler supports only `GET` and `HEAD`. It rejects query strings and noncanonical paths, and it serves only the root document, the favicon and the hashed build assets.

The root document is not cached. Existing hashed assets are immutable. Responses for missing assets are `no-store`, and the stable favicon uses short revalidation instead of immutable caching. Responses set a restrictive Content Security Policy, same-origin opener and resource policies, a no-referrer policy, MIME sniffing protection, frame denial and disabled browser permissions. Network connections are restricted to the origin that serves the console.

## Build and test

Use the Node version in `.node-version` so that the assets are reproducible. The committed `web/dist` output is embedded into the Go daemon, so a clean Go build does not require Node. When you change the console source, rebuild and verify the committed output:

```sh
npm ci --prefix web
npm run format:check --prefix web
npm test --prefix web
npm run check --prefix web
npm run build --prefix web
npm run dist:check --prefix web
go test ./web ./cmd/trestled
```

CI snapshots the checked-out `web/dist` directory before rebuilding, and then compares the generated output with that snapshot recursively. Stale assets therefore fail even before Git tracking is available locally.

`npm run visual --prefix web` starts a temporary loopback fixture server and launches the installed Chromium binary. It captures desktop and narrow-screen screenshots of the review and setup screens, checks for browser console errors and horizontal overflow, and then shuts everything down. It does not contact a daemon or any external service.

The separate packaged system driver runs `web/scripts/daemon-visual-check.mjs` against the real daemon, both before shutdown and after a restart. Each phase receipt binds the exact run, the diagnostic set, the identity and state of the deterministic check, the observation identities, the viewport, the PNG image dimensions and digest, the counts of console errors and egress, overflow, keyboard focus, reduced motion and the floor on tap-target size. The Python driver separately requires the canonical tracked browser script and validates the receipt contract and the metrics. It parses bounded PNG signatures, chunks, CRCs, IHDR dimensions and the IDAT and IEND structure, and it rehashes every receipt and screenshot from disk. Fixture screenshots remain focused evidence of state, and they cannot substitute for these phases that run against the daemon.

### Distribution limits

The distribution check enforces these size limits:

- Each JavaScript chunk: 256 KiB.
- All JavaScript together: 320 KiB.
- All JavaScript together, gzipped at level 9: 90 KiB.
- CSS: 32 KiB.

The setup application is a separate lazy-loaded chunk, so the review console does not pay for its interaction cost. The check permits only `public/favicon.svg`, `public/not-found.css` and `public/not-found.html` as public inputs.

The complete distribution contains only `index.html`, `favicon.svg`, `not-found.css`, `not-found.html` and an `assets` directory. That directory holds one hashed `index-*.js`, one hashed `SetupApp-*.js` and one hashed `index-*.css`. Hash suffixes use ASCII letters, digits, underscores and hyphens. Both trees reject extra files, nested or empty directories, source maps and symlinks. The embedded handler also rejects asset names outside these hashed patterns, and files that are not regular files.

The web build has no runtime dependency on a CDN, font, icon, analytics or telemetry service. The package lock pins every JavaScript dependency and its integrity digest.
