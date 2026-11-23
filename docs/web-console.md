# Web console

The daemon and the surfaces that depend on it are frozen: no new work is planned, and they may be removed. For reviews, use `trestle review`, the `trestle` home screen or the [VS Code command](vscode.md).

The web console is a read-only browser view of one Open Trestle review run. `trestled` serves it at `/console/`, and it uses the same authenticated REST API as the CLI and the editor clients. It shows a run that the daemon already holds. It cannot start a review, and it is not a way to review your own change: use `trestle review` for that.

The console has no way to publish, change policy, take a worker lease, run a shell, edit source or execute tools. `/console` redirects to `/console/`. The daemon's routes are listed in the [daemon API](daemon-api.md#http-contracts).

## Connect to a run

Enter a tenant ID, repository ID, review run ID and API token. The console makes only these requests:

- `GET /api/v1/tenants/{tenant}/repositories/{repository}/runs/{run}`
- `GET /api/v1/tenants/{tenant}/repositories/{repository}/runs/{run}/progress`
- `GET /api/v1/tenants/{tenant}/repositories/{repository}/runs/{run}/diagnostics`
- `GET /api/v1/tenants/{tenant}/repositories/{repository}/runs/{run}/refusal`, only when the run is not found
- `GET /api/v1/tenants/{tenant}/repositories/{repository}/runtime`

The token stays in React memory for the current page and is sent only in the `Authorization` header. It is not placed in a URL, in browser storage, in a log message, in an error message or in a rendered view. The console may keep the tenant, repository and run, which are not secret, in session storage. If that storage is blocked or full, the connection still works, but the scope is not saved.

When you change the scope, the console clears the in-memory token, discards pending UI updates, and stops late responses from starting more reads with the old token. Requests that were already sent may still finish.

If a refresh times out or the daemon is unavailable, the console keeps the last verified receipt, the in-memory token and the selected task. It clears the counts that come from artifacts and shows an alert that names the journal revision on display. Failures of authentication, authorization, scope or validation still end the session.

The browser client rejects invalid scopes, unsafe tokens, redirects, unexpected media types, unknown object fields, receipts from another scope, malformed identities, invalid state values and inconsistent response shapes.

It streams response bodies through a counter that allows a 1 MiB payload plus 4 KiB of API framing, and it cancels on overflow before the whole body is buffered. Its requests use no-store caching and omit ambient credentials, and it applies a 15-second timeout. Repository and diagnostic text is rendered only through React text nodes.

## Views

A shortened identity includes the full digest as assistive text and in the accessible name of the copy action. A missing diagnostic set is labeled `n/a`, not zero.

### Overview

The overview shows the run status, the journal revision, the number of completed tasks, the number of review results, the content-addressed identities of the boundaries, and the progress counts that come from artifacts, from the `progress` route.

### Tasks

The tasks view shows the task journal, which is derived by replaying the run. An inspector shows each task's attempts, failures, recorded failure reason, handler identity, input and output. The overview lists each recorded reason next to the run's failure.

The console accepts three receipt versions and refuses a receipt whose version does not match its tasks:

- Version 1.
- Version 2, which adds a linked context abstention.
- Version 3, which adds a source failure reason on source acquisition, a context route refusal on context assembly, or a provider refusal on candidate generation or verification.

A provider refusal shows a label, the explanation and a `Hint` with the same action as the local review. The console accepts these refusals, each paired with a failure kind, and rejects a refusal with any other failure or on any other task kind:

- `policy`: `provider_payment_required`, `provider_model_unavailable`, `provider_model_retired`, `provider_authentication_failed`, `provider_authorization_denied` and `provider_request_rejected` (labeled Provider request rejected).
- `transient`: `provider_rate_limited`.
- `internal`: `provider_response_invalid` (labeled Provider reply refused) and `model_output_invalid` (labeled Model answer not a review document).

A `route_context_insufficient` refusal carries its token counts. It shows the same hint as the local review: the required, input, output and declared counts, and the context length to raise. A `no_eligible_route` refusal carries no counts.

When a run is not found, the console reads the scope's delivery refusal (`GET .../refusal`). If intake refused that webhook delivery instead of opening its run, the connection ends with a message. The message names the reason token, a fixed explanation and the time of the refusal. The console validates the refusal against the scope, and it carries no delivery content.

### Runtime

The runtime view shows the local storage and artifact protection posture for the repository, the configuration identities that are not secret, the handler bindings with controls to copy their full values, and whether the supervised services are ready. A token without runtime access does not block the run or diagnostics views.

### Review

The review view is a queue for human review. How it presents a result depends on the diagnostic-set version.

For versions 5 and 8, the verified finding totals stay separate from the outcomes of deterministic checks:

- Version 2 also shows the exact counts of accepted, verified, rejected and
  inconclusive candidates. The console calls accepted candidates admitted
  candidates.
- Version 3 ties in the validated verification-context identity. It adds counts of analyzed, selected and omitted sources.
- Version 4 adds sorted reasons for omissions, as aggregates that contain no content.
- Version 5 adds one deterministic static-debug check that contains no content, with lineage to the analysis and the change.
- Version 8 is version 5 plus findings on removed base lines. The console shows such a finding with its path and the removed base line range instead of head lines.

The check appears as a `Cleared gate`, `Failed check`, `Incomplete check` or `Abstention`. Only a pass with full coverage and zero matches counts as cleared, and only for that rule. Not applicable means that no changed Go range could be checked, and it does not clear the rule. The console does not present rejected candidates as cleared deterministic gates. It labels any inconclusive candidate or omitted source count as incomplete. Source counts and reasons do not claim coverage of the whole repository and do not expose paths.

When the verified set is empty, the console states that zero findings and terminal coverage do not approve the change.

Versions 6 and 7 are different:

- Version 6 shows the deterministic observations and the rule coverage instead. It has no verified finding set, and the console labels every observation as deterministic and not verified.
- Version 7 is the final full-review result. It names the terminal outcome and shows only the deterministic and verified parts it carries. A failed result whose context task recorded a route refusal also shows that refusal, with the same hint for `route_context_insufficient`.
- A result recorded after the run's evidence retention lapsed carries `evidence_expired` and no evidence part. The console says that the outcome comes from the run journal only and that no findings or observations are available. This is not a clear result.

Each verified finding and each deterministic observation has a closed `Inspect evidence` disclosure:

- A verified finding shows the diagnostic identity, the source finding identity, the finding fingerprint and every evidence reference.
- A deterministic observation shows the observation, analysis-result, check, fingerprint and evidence identities, without calling them verified.

Long values are shortened on screen, while assistive text and the copy controls keep the complete value.  After a successful clipboard write, the console announces `Copied`. If the clipboard is unavailable or rejects the write, it announces `Copy failed`, without exposing a browser error or the value. Only the newest copy attempt updates the feedback, and the feedback for a previous value disappears if the identity is refreshed. The disclosure does not fetch or render source, evidence or model payloads.

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

CI snapshots the checked-out `web/dist` directory before rebuilding, and then compares the generated output with that snapshot recursively. 

`npm run visual --prefix web` starts a temporary loopback fixture server and launches the installed Chromium binary. It captures desktop and narrow-screen screenshots of the review screens, checks for browser console errors and horizontal overflow, and then shuts everything down. It does not contact a daemon or any external service.

The packaged system driver runs `web/scripts/daemon-visual-check.mjs` against the real daemon before shutdown and after a restart, and its receipts record the run, the diagnostic set, the deterministic check, the viewport, the screenshot digest and the accessibility measurements.

### Distribution limits

The distribution check enforces these size limits:

- The JavaScript bundle: 256 KiB.
- All JavaScript together: 320 KiB.
- All JavaScript together, gzipped at level 9: 90 KiB.
- CSS: 32 KiB.

The check permits only `public/favicon.svg`, `public/not-found.css` and `public/not-found.html` as public inputs.

The complete distribution contains only `index.html`, `favicon.svg`, `not-found.css`, `not-found.html` and an `assets` directory. That directory holds one hashed `index-*.js` and one hashed `index-*.css`. Hash suffixes use ASCII letters, digits, underscores and hyphens. Both trees reject extra files, nested or empty directories, source maps and symlinks. The embedded handler also rejects asset names outside these hashed patterns, and files that are not regular files.

The web build has no runtime dependency on a CDN, font, icon, analytics or telemetry service. The package lock pins every JavaScript dependency and its integrity digest.
