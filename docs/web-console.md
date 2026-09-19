# Web console

`trestled` serves the read-only Open Trestle console at `/console/`. The console uses the same authenticated REST API as the CLI and editor clients. It has no publication, policy mutation, worker lease, shell, source edit, or tool-execution capability.

## Connect to a run

Enter one exact tenant ID, repository ID, review run ID, and API token. The console requests only:

- `GET /api/v1/tenants/{tenant}/repositories/{repository}/runs/{run}`
- `GET /api/v1/tenants/{tenant}/repositories/{repository}/runs/{run}/diagnostics`
- `GET /api/v1/tenants/{tenant}/repositories/{repository}/runtime`

The token remains in React memory for the current page and is sent only in the `Authorization` header. It is not placed in a URL, browser storage, log message, error message, or rendered view. The non-secret tenant, repository, and run scope may be retained in session storage. If optional storage is blocked or full, the connection still works without saving the scope. Changing scope clears the in-memory token, invalidates pending UI updates, and prevents late responses from starting further reads with the old token. Requests already sent may still finish.

The browser client rejects invalid scopes, unsafe tokens, redirects, unexpected media types, unknown object fields, cross-scope receipts, malformed identities, invalid state values, and inconsistent response shapes. It streams response bodies through a counter allowing a 1 MiB payload plus 4 KiB of API framing, cancels on overflow before full buffering, uses no-store requests, omits ambient credentials, and applies a 15-second timeout. Repository and diagnostic text is rendered only through React text nodes.

## Views

Shortened visual identities include the full digest as assistive text and in the copy action's accessible name. Missing diagnostic sets are labeled `n/a`, never zero.

- **Overview** shows exact run status, journal revision, completed task count, verified diagnostic count, and content-addressed boundary identities.
- **Tasks** shows the replay-derived task journal and an inspector for attempts, failures, handler identity, input, and output.
- **Runtime** shows repository-scoped storage posture, non-secret configuration identities, exact handler bindings with full-value copy controls, and supervised service readiness. A token without runtime access does not block the run or diagnostics views.
- **Findings** is a human-review queue for the independently verified diagnostic set. It keeps verified finding totals separate from deterministic check outcomes. Version 2 also shows exact admitted-candidate, verified, rejected, and inconclusive counts. Version 3 binds the validated verification-context identity and adds bounded analyzed, selected, and omitted source counts. Version 4 adds sorted content-free aggregate omission reasons. Version 5 adds one content-free deterministic static-debug check with exact analysis and change lineage. The check appears as a `Cleared gate`, `Failed check`, `Incomplete check`, or `Abstention`. Only a fully covered zero-match pass is called cleared for that exact rule. Not-applicable means no changed Go range was applicable and does not clear the rule. Rejected candidates are not presented as cleared deterministic gates, and any inconclusive candidate or omitted source count is labeled incomplete. Source counts and reasons do not claim repository-wide coverage or expose paths. Candidate model output is never presented as a finding. An empty verified set explicitly states that zero findings and terminal coverage do not approve the change or prove correctness. Versions 1 through 4 remain readable without invented check outcomes.

Each verified finding has a closed `Inspect evidence` disclosure. It shows the exact diagnostic identity, source finding identity, finding fingerprint, and every evidence reference from the authenticated set. Visible long values are shortened, while assistive text and copy controls retain the complete value. Review-console and guided-setup identity rows share one copy implementation. A successful clipboard write announces `Copied`; an unavailable or rejected clipboard announces `Copy failed` without exposing a browser error or the value. For rapid repeated clicks, only the newest attempt can update feedback, and its message keeps the full bounded lifetime. If a refreshed identity changes, feedback for the previous value disappears and cannot be shown beside the new value. The disclosure does not fetch or render source, evidence, or model payloads.

The console does not infer review success from daemon health. It does not infer effect authority from publication readiness.


## Guided setup surface

`trestle setup web --state PATH` serves the same self-contained assets on a numeric loopback listener and opens the setup mode at `/console/setup`. Unlike the daemon console, this local surface has a narrow receipt-writing API. It uses a dedicated `OPEN_TRESTLE_SETUP_TOKEN` that must differ from operator and observer tokens. The server accepts only its exact numeric loopback Host authority.

The setup client calls only:

- `GET /api/v1/setup`
- `POST /api/v1/setup/init`
- `POST /api/v1/setup/check`

The guided checker set includes local-administrator approval, exact protected backup-snapshot validation, PostgreSQL authority, KMS secret-backend and envelope-storage checks, remote-provider authorization, GitHub integration-permission inspection, local GitHub webhook conformance, PostgreSQL shared API rate-limit conformance, storage, observer credentials, runtime policy, explicit local inference, and the non-publishing dry run. Snapshot creation and restore remain explicit CLI operations. Local inference remains disabled until the exact policy receipt exists; its confirmation attempts at most two fixed independently routed numeric-loopback calls and requires both to pass under one 90-second bound, without retry, fallback, publication, or dynamic validation. The backup result is limited to setup state and does not claim independent media or disaster-recovery success. The envelope-storage check keeps its S3 and KMS configuration and approval values in browser memory only. Its separate confirmation permits the server to create, read, exactly delete, and verify absence of one fixed public envelope-encrypted object. A partial failure can leave that deterministic encrypted object for an exact-authority retry; a pass requires absence. It grants no general deletion or other effect authority. GitHub integration-permission validation keeps only non-secret endpoint, version, installation, repository, and approval fields in browser memory. The dedicated GitHub setup token and separate runtime installation token stay in the server environment. After confirmation, the server makes bounded read-only installation and repository GET requests and cannot modify the integration. GitHub webhook conformance keeps only a non-secret authority identity, key ID, and approver in browser memory and renders no secret field. It requires the passing integration receipt. After confirmation and the stale-plan fence, the server reads the webhook secret, runs five direct in-process requests against the production handler and a disposable private file inbox, clears the verifier, and removes the inbox before passing. It opens no listener and makes no GitHub request. Kubernetes HA shared-rate-limit validation renders only the approved conformance and database identities plus the named approver. After the PostgreSQL and stale-plan fences, the server reads the database URL and runs the bounded cross-instance quota cycle. A pass requires exact namespace cleanup. Replica reconciliation uses the same credential boundary to prove two-store plan visibility, notification and task lease fencing, cross-instance completion, terminal convergence, and exact disposable-scope cleanup. No database credential enters the browser or setup state. Air-gapped signed-bundle validation keeps only the absolute path and public digest, size, Ed25519 key, signature, authority, and approver in browser memory. It streams one opaque file and makes no extraction, import, execution, archive, SBOM, provenance, malware, or no-egress claim. Remote-provider authorization reuses the protected runtime configuration paths and three exact approval identities. It reads no provider credential value and makes no provider request; its receipt grants no dispatch or publication authority. The KMS check keeps its region, key ARN, optional endpoint, and approval values in browser memory only. After confirmation, the server reads AWS credentials from its environment, performs one bounded generate and unwrap sequence, stores no key material, and makes no S3 request. It proves neither envelope-storage readiness nor effect authority.

Initialization and every check use separate inline confirmation. Check requests bind the exact displayed plan identity and `run REQUIREMENT_KEY`. The service revalidates protected state before opening a writer and the setup runner fences stale transitions. The browser persists no setup token, path, approval identity, or progress value. It omits cookies and other ambient credentials. Responses are validated against the closed setup profiles, posture relationships, ordered requirements, checker authorities, receipt history, derived readiness, and latest receipt binding before display.

The guided path can create a plan and run the built-in local and PostgreSQL storage, envelope-storage, KMS secret-backend, remote-provider authorization, GitHub integration-permission inspection, GitHub webhook conformance, PostgreSQL shared-rate-limit conformance, replica reconciliation, signed offline bundle, local-administrator, backup-snapshot, observer credential posture, exact policy, explicit local-inference, and non-publishing dry-run checks. It does not invent results for checks without a built-in implementation. Those requirements stay pending with a clear explanation. The dry run remains local and deterministic and has no publisher, source writer, process runner, credential resolver, or network client.


## Browser boundary

The embedded handler supports only `GET` and `HEAD`, rejects query strings and noncanonical paths, and serves only the root document, favicon, and hashed build assets. The root document is not cached. Existing hashed assets are immutable. Missing asset responses are `no-store`, and the stable favicon uses short revalidation rather than immutable caching. Responses set a restrictive Content Security Policy, same-origin opener and resource policies, no-referrer policy, MIME sniffing protection, frame denial, and disabled browser permissions. Network connections are restricted to the serving origin.

## Build and test

Use the Node version in `.node-version` for reproducible assets. The committed `web/dist` output is embedded into the Go daemon so a clean Go build does not require Node. When changing console source, rebuild and verify the committed output:

```sh
npm ci --prefix web
npm run format:check --prefix web
npm test --prefix web
npm run check --prefix web
npm run build --prefix web
npm run dist:check --prefix web
go test ./web ./cmd/trestled
```

CI snapshots the checked-out `web/dist` directory before rebuilding and recursively compares the generated output with that snapshot, so stale assets fail even before Git tracking is available locally.

`npm run visual --prefix web` starts a temporary loopback fixture server, launches the installed Chromium binary, captures desktop and narrow-screen review and setup screenshots, checks browser console errors and horizontal overflow, then shuts everything down. It does not contact a daemon or external service.

The distribution check caps each JavaScript chunk at 250 KiB, aggregate JavaScript at 288 KiB, aggregate level-9 gzip JavaScript at 90 KiB, and CSS at 32 KiB. The setup application is a separate lazy-loaded chunk, so the review console does not pay its interaction cost. The check permits only `public/favicon.svg` as a public input. The complete distribution contains only `index.html`, `favicon.svg`, and an `assets` directory with one hashed `index-*.js`, one hashed `SetupApp-*.js`, and one hashed `index-*.css`. Hash suffixes use ASCII letters, digits, underscores, and hyphens. Extra files, nested or empty directories, source maps, and symlinks are rejected in both trees. The embedded handler also rejects asset names outside these hashed patterns and non-regular files. The web build has no runtime CDN, font, icon, analytics, or telemetry dependency. The package lock pins every JavaScript dependency and integrity digest.
