# Daemon API and client

`trestled` is the Open Trestle daemon. It keeps review runs in durable storage and exposes them through a versioned HTTP API. The Go client and the `trestle runs` commands use the same contracts. The daemon does not publish reviews to a forge, and workers must pass the provider authorization gates.

## Start a local daemon

Set an operator credential, which must be a random secret of at least 32 bytes. It has run, worker and runtime authority. You can also set a different observer credential for a person or a read-only console that only needs to inspect runs and the runtime. If you do not set it, only the full-authority operator credential is accepted. Keep both credentials out of command-line arguments and repository files.

```sh
export OPEN_TRESTLE_API_TOKEN="replace-with-a-random-operator-secret-of-at-least-32-bytes"
export OPEN_TRESTLE_OBSERVER_TOKEN="replace-with-a-different-observer-secret"
go run ./cmd/trestled \
  --listen 127.0.0.1:8741 \
  --state-dir "$HOME/.local/state/open-trestle/runs" \
  --tenant example \
  --repository example-repository
```

Plain HTTP is accepted only on a numeric loopback address. A listener that is not on loopback requires both `--tls-cert` and `--tls-key`. The TLS private key must be a regular file without group or other permissions, and the daemon requires TLS 1.3 for direct TLS listeners.

The file journal takes an exclusive writer lock, so a second daemon cannot open the same journal root. It also provides these protections:

- Private directory and file permissions.
- Bounded canonical records.
- Atomic replacement.
- File and directory synchronization.
- Corruption checks.

### Limits of path consistency

The read, write and rename paths of the file journal and the artifact store use absolute pathnames after sampled checks of the root. At startup the daemon captures the root and runs a preflight with borrowed `os.Root` handles, but those handles do not pin later operations to the original directory. A process running as the same user that renames an ancestor of the state directory during an operation can defeat the path checks.

Keep writable roots and their ancestors under the operator's exclusive control. Crash-consistent recovery across several roots is not covered.

### Startup inspection of the journal

Every startup with `metadata=local` inspects the entire bounded historical journal. It does this before it builds audit or diagnostics, starts workers or opens a listener. A valid historical v4 context-packet-prepared event blocks startup, even when its run is terminal or belongs to an old tenant or repository. This is a conservative rejection, not packet recovery.

The local artifact store is constructed first and can recover pending deletions. The journal constructor also creates the state, changes its permissions and locks it before inspection. This is therefore not a check that runs before any effect on storage.

### What the state directory may contain

The private `--state-dir` root accepts only these direct entries:

- `.run-writer.lock`.
- Pairs of `.run-plan.json` and `.run.jsonl` files, named with an exact lowercase hexadecimal, 64-character scope digest.
- The private directories `artifacts`, `audit`, `diagnostics`, `webhook-inbox` and `setup`.

The inventory does not inspect what is inside `setup`. Startup fails on any of these:

- Unknown direct entries.
- Symlinks.
- Broad permissions on direct entries.
- Orphan streams.
- Incomplete prefixes that hold only a plan.
- Corrupt journal records.

The scan has fixed limits:

- 1,024 direct entries, including the lock and the directories.
- 500 plans.
- 128 KiB per encoded plan.
- 64 MiB per stream.
- 256 MiB of encoded plans and streams in total.

An older root that is otherwise valid but exceeds a limit needs offline review. A scan that hits a limit, or that is incomplete or corrupt, does not show whether v4 events are present. Open Trestle does not repair or delete rejected entries automatically.

A `--setup-state` directory placed directly inside `--state-dir` is not supported. This includes `plan.json` or `setup.json` and their lock and receipt siblings. Put the setup plan at `--state-dir/setup/plan.json` or outside the daemon root. The documented `runs` root has `setup` as a sibling, while the webhook example can use a nested `setup/plan.json`.

If your existing plan sits directly in the root, stop both writers and follow the [verified offline setup backup and restore](setup.md#offline-move-of-a-direct-root-setup-plan). The guard does not move or delete existing files. Leftover files at the direct root still block startup and need manual offline review.

## Optional GitHub webhook endpoint

You can configure one webhook endpoint for a repository. The secret lives only in the environment, and a key version that is not secret is used for receipt lineage:

```sh
export OPEN_TRESTLE_GITHUB_WEBHOOK_SECRET="$(openssl rand -hex 32)"
# The value must remain exactly 64 lowercase hexadecimal characters.
trestled \
  --listen 127.0.0.1:8741 \
  --state-dir "$HOME/.local/state/open-trestle" \
  --tenant example \
  --repository example-repository \
  --github-webhook-repository example-repository \
  --github-webhook-key-id key-2026-01
```

This mounts `POST /webhooks/github`. The fixed subscription accepts the `pull_request` actions `opened`, `reopened`, `synchronize` and `ready_for_review`. The secret is not written to the inbox. When you rotate the secret, change `--github-webhook-key-id` so that later delivery receipts bind the new verifier configuration. See [Verified webhook ingress](webhook-ingress.md).

## CLI

The CLI reads `OPEN_TRESTLE_API_TOKEN` and uses `OPEN_TRESTLE_API_URL`, which defaults to `http://127.0.0.1:8741`.

```sh
trestle runs submit --plan review-run-plan.json
trestle runs status --tenant example --repository example-repository --run run-123
trestle runs cancel --tenant example --repository example-repository --run run-123
```

By default, `runs status` prints one canonical `ReviewRunReceipt` JSON record that contains no secrets. With `--format json|sarif` it reads the stored diagnostic set instead. With `--format progress` it prints one object with exactly `run` and `progress`, taken from a single scoped progress response. It does not fetch a second receipt or merge receipt revisions. It is not the HTTP response envelope: it leaves out the contract, version and request ID.

`runs status` adds diagnostics on stderr in these cases, and stdout stays unchanged:

- If the receipt or the final set records a context route refusal, it writes `runs status: task context refused: REASON (EXPLANATION)`. For `route_context_insufficient` it also writes a `hint:` line with the same text as the local review.
- If a final set was recorded after its evidence expired, it writes `runs status: ` followed by the shared evidence-expired text. The SARIF log then sets the `trestleEvidenceExpired` run property, appends the expiry to `trestleReason` and adds the same text as a `note` tool-execution notification. This way, an empty result list is not read as a clean review.

The plan input must be a regular file that does not change while it is read, and it is limited to 1 MiB. The command accepts one trailing newline and otherwise parses the canonical plan byte for byte. The client rejects plaintext remote endpoints. It does not follow a redirect while it holds bearer authority.

## Runtime status

`GET /api/v1/tenants/{tenant}/repositories/{repository}/runtime` requires the separate `runtime_read` capability. It returns a snapshot, scoped to the repository, that contains no content. The snapshot describes these things:

- Storage posture.
- Review mode.
- Configured ingress and workers.
- Route and policy identities.
- Exact handler bindings.
- Startup state of the supervisors.

The snapshot does not include source, prompts, model or provider bodies, credentials, bearer leases, endpoints, queue contents or other repository identifiers. The configuration identity is derived from the projection for the one repository, so the membership of unrelated repositories does not change it. 

Use the optional observer credential for read-only inspection:

```sh
OPEN_TRESTLE_API_TOKEN="$OPEN_TRESTLE_OBSERVER_TOKEN" \
  trestle admin runtime status --tenant example --repository example-repository
```

`trestle admin runtime status` prints one canonical `RuntimeStatus` snapshot. Failure output contains no content. A status of `starting` means that at least one configured supervisor has not yet completed its initial durable reconciliation. If a supervisor fails, the daemon stops instead of staying up as a stale `ready` process.

## Health probes

`GET` or `HEAD /healthz` returns whether the process is alive, with no other content. `GET` or `HEAD /readyz` returns `503 not_ready` until every configured durable supervisor has completed its initial reconciliation of the journal or the inbox. These two endpoints need no bearer credentials and expose no tenant, repository, queue, provider or storage detail. They reject other methods and query parameters.

## HTTP contracts

Every endpoint requires exactly one `Authorization: Bearer <credential>` header. Endpoints reject query parameters, unsupported content encodings, excessive request targets, oversized bodies, cross-tenant access, and repositories outside the principal's allowlist. Responses use `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`. Error responses contain public codes instead of internal errors.

### Administration endpoint

`GET /api/v1/tenants/{tenant}/repositories/{repository}/runtime` returns a canonical `RuntimeStatus`, only to a principal that is authorized for the repository and has `runtime_read`.

### Run endpoints

- `POST /api/v1/runs` accepts a canonical `ReviewRunPlan`. Run IDs that begin with `webhook-` are reserved for webhook intake. A plan or local review intent that names one gets `400 invalid_request` after the scope is authorized, so a caller cannot open a delivery's run scope before intake does.
- `GET /api/v1/tenants/{tenant}/repositories/{repository}/runs/{run}` returns a `ReviewRunReceipt`.
- `GET .../runs/{run}/progress` requires `run_read` and returns read-only counts of evidence that are bound to an unchanged canonical receipt.
- `GET .../runs/{run}/refusal` requires `run_read`. It returns the refusal that intake recorded for the webhook delivery that owns the run scope (`webhook-{deduplication key}`), instead of opening its run. The refusal has no content. It is returned as `open-trestle/delivery-refusal-response` v1, with the `open-trestle/webhook-delivery-refusal` record and its reason token. The response is `404 not_found` when no refusal is recorded or the daemon has no webhook planner, and `503 unavailable` when the inbox cannot be read. The daemon answers from its inbox for the planner identity that it admits deliveries with. `trestle runs refusal` prints the record, and `trestle runs status` names the reason when no run exists.
- `GET .../runs/{run}/diagnostics` returns the immutable canonical diagnostic set for that scope. See the version list below.
- `POST .../runs/{run}/cancel` accepts an empty body.
- `POST .../runs/{run}/finalize` accepts a canonical `TaskCompletion` from a controller that has explicit authorization. Its output or failure must exactly equal the disposition derived from the replayed task state. A daemon that runs with the runtime enabled normally finalizes runs automatically.

The diagnostic set comes in these versions:

- Versions 1 through 5 contain the state of verified findings.
- Version 2 includes counts of candidates, verified, rejected and inconclusive results.
- Version 3 also includes the identity of the verification context that supplied the result, and counts of analyzed, selected and omitted sources.
- Version 4 adds sorted reasons for omissions. They are aggregates that contain no content, and their counts equal the total omitted.
- Version 5 adds one deterministic check, bound to its analysis result and the change.
- Version 6 instead contains one deterministic check and observations, bound to an analysis-result identity. It has no verified-finding set.
- Version 7 is a set for the end of a full review only. It has a final outcome and optional evidence: deterministic evidence in the version 6 form and verified evidence in the version 5 form. Its top-level snapshot identifies the physical head source. The nested verified snapshot identifies the selected review snapshot, and the two need not be equal. An absent verified section means unknown, not zero findings.

### Read-only run progress

`GET /api/v1/tenants/{tenant}/repositories/{repository}/runs/{run}/progress` accepts no body. It requires one bearer credential, the tenant and repository allowlist, and `run_read`. The rate limits before authentication and per principal, described below, apply.

The success response follows [`run-progress-response-v1.schema.json`](../schemas/controlplane/run-progress-response-v1.schema.json). It has exactly these members: `contract: open-trestle/run-progress-response`, `schema_version: 1`, a bounded `request_id`, `run` and `progress`. Its `run` member is the unchanged canonical `ReviewRunReceipt` (version 1, 2 or 3). It is not a new receipt version that carries progress. Its `progress` member has four independent axes:

- `change`: the changed `files` and `ranges`.
- `deterministic`: `applicable_files`, `applicable_ranges`, `checked_files`, `checked_ranges` and, when the recorded schema supplies it, the count of `observations`, which are not verified findings.
- `context`: the counts of `analyzed`, `selected` and `omitted` sources.
- `verification`: the counts of `candidates`, `verified`, `rejected` and `inconclusive`.

Each axis has a `state` and, when it refers to evidence, an immutable `artifact_identity`. The states mean the following:

- `not_run`: no completed result is recorded. This includes work that is pending, available or leased.
- `unavailable`: the evidence cannot be established. This includes failed or skipped tasks, artifacts that are missing, expired, unsupported or malformed, and an unavailable upstream lineage. A task that succeeded may keep its output identity while its counts remain unavailable.
- `available`: the counts came from canonical evidence.
- `partial`: only deterministic coverage uses it, when its recorded check explicitly reports incomplete coverage.

Missing counts are unknown, not zero. Counts are absent for `not_run` and `unavailable`. A numeric zero is returned only when recorded evidence shows zero. Historical deterministic evidence may supply all four check counts without observations, or it may omit the check counts.

For `change`, `deterministic` and `verification`, a present `artifact_identity` is the output identity of the matching task that succeeded. For an available `context` axis, it is the recorded context-packet artifact, which is proved through the output of the context task and the upstream lineage. A v6 context-input settlement can have a different, sanitized generation-input output identity in the receipt. The progress packet identity does not replace or relabel that output. Before the provenance of the packet is established, an unavailable context axis can keep the original output identity of the task that succeeded.

The counts follow two rules: `analyzed = selected + omitted` for context, and `candidates = verified + rejected + inconclusive` for verification. 

The handler reads only the exact scoped artifacts that completed tasks refer to and their canonical lineage, with at most ten indexed artifact loads. The existing limits on artifact and parser bytes apply. The handler does not scan storage, execute tasks, call providers, publish preliminary diagnostics or change canonical state. After it retrieves the evidence, it checks the receipt identity again. If the run has advanced, `409 progress_changed` asks the caller to refresh, rather than combine counts from different receipt revisions. 

### Worker endpoints

- `POST .../runs/{run}/worker/notifications/claim` accepts bounded wait and notification-lease durations. It returns a scheduling hint that has no content, or `204 No Content`.
- `POST .../runs/{run}/worker/notifications/acknowledge` accepts the current notification delivery capability and returns `204 No Content`.
- `POST .../runs/{run}/tasks/{task}/claim` accepts an approved handler identity.
- `POST .../runs/{run}/tasks/{task}/renew` accepts the current `TaskLease`.
- `POST .../runs/{run}/tasks/{task}/complete` accepts the current lease and a closed task completion.

A task notification is a hint. Workers must still read the canonical run receipt and acquire the exact task lease. A notification claim may wait for up to ten seconds. Delivery leases are fenced by worker, token digest, delivery number and expiry, so a stale or duplicate notice cannot authorize execution.

A lease document is a bearer capability. It contains the random lease token. Do not log it, put it in URLs, or save it anywhere except a protected worker store. The durable run journal stores only its digest. Completion and renewal check the tenant scope, principal identity, plan, task, handler, attempt, token digest and expiry again. Repeating an identical completion is idempotent. Work that has expired or been replaced is fenced. After a task completes, the daemon derives the unique result output, or the earliest required terminal failure, and appends the terminal run event. At startup, a supervisor closes any run that has settled but was left active when a process stopped.

### Rate limits

The daemon applies rate limits before authentication and per principal.

- The limiter uses fixed windows within the process, and reports that limitation in the runtime status.
- Keys before authentication use the canonical, unmapped IP address of the direct TCP peer. The daemon does not accept forwarded-address headers, so a reverse proxy must add its own limit that knows the client where that is needed.
- Exhaustion of the limiter's key cardinality returns 503 and grants no request.
- Exhausting the request quota of an established key returns 429.

An external ingress may add a stricter limit.

## Local setup API

`trestle setup web` serves a separate setup API with its own dedicated setup bearer token. The API listens on a numeric loopback address only, and it checks the Host. It is not an endpoint that issues credentials for the daemon.

On shutdown, the handler allows HTTP Shutdown five seconds and forces a server Close if that fails.

## Go client

The public `client`, `controlplane` and `runtimeadmin` packages expose types for plans, receipts, leases, completions, and runtime status without content. The client supports runtime inspection, submission, observation, cancellation, waiting for and acknowledging notifications, task claims, renewal, completion and finalization. It limits responses to 1 MiB, requires JSON media types, rejects unknown response fields, applies a request timeout and disables redirects.

## Storage

The daemon keeps all state under `--state-dir`: the run journal, the audit ledger, the diagnostics store and the webhook inbox are local files. Task notifications use an in-process queue, and API rate limits apply within the process. The daemon runs as one process and does not support several replicas.

Long-poll API requests and the notification supervisor wake up on a signal. If a notification is missed, the durable journal remains the source of truth. The daemon exposes liveness probes without content and readiness probes that the supervisors back.

## GitHub run opening

GitHub ingress durably acknowledges deliveries without requiring runs to be created automatically. To enable the durable run supervisor, add all of these:

- `--github-open-runs`.
- `--github-repository-full-name`.
- `--github-review-policy-identity`.
- `--github-review-mode`.
- `--github-publisher-id`.
- One `--github-handler KIND=IDENTITY` for each required task kind.

The plans require handlers from `acquire_source` through `evaluate_publication`. The `--github-review-mode` flag accepts `local` and `advisory`, and the daemon rejects `required` at startup. The daemon rejects bindings that are missing, duplicated, unknown or malformed before the listener starts.

## Daemon-owned deterministic workers

Add `--github-local-deterministic-workers` to execute the built-in handlers for GitHub source acquisition, the change model, deterministic evidence and memory retrieval inside the daemon process. The option requires `--github-open-runs`. The handler identities for those four task kinds are derived from the configured built-ins and merged into the planner, and a conflicting explicit `--github-handler` is rejected. The handlers for context, the model and readiness are configured separately.

Without a broker descriptor, `OPEN_TRESTLE_GITHUB_API_TOKEN` keeps the legacy configuration for source acquisition. If it is not set, acquisition is anonymous. If it is set, the value must be safe for an HTTP header. This static token is not current evidence of setup permissions. The daemon rejects it, rather than ignoring it, when local deterministic workers are disabled.

Broker mode uses the protected `OPEN_TRESTLE_GITHUB_SOURCE_BROKER_CONFIG` descriptor and a common approval, `--approve-github-source-broker-authority-identity`. The daemon rejects static credentials mixed in. Runtime source acquisition owns a separate broker for the runtime purpose, and grants and receipts from setup cannot authorize it. The descriptor remains schema 1, with `single_host_exclusive` ownership and explicit consent to create tokens and to renew them on demand. It does not provide recovery after an automatic restart or authority to publish.

## Policy-bound model pipeline

To run the complete advisory pipeline in `trestled`, set both `--runtime-route-inventory PATH` and `--runtime-policy PATH` together with `--github-local-deterministic-workers`. The files must conform to the published runtime schemas. Each path must resolve directly to a regular file that belongs to the daemon user or root and is not writable by group or world.

Every ancestor must have trusted ownership and must prevent another local principal from replacing it. Writable ancestors are allowed only with sticky-directory protection for a child with a trusted owner. The daemon rejects symlinks, files with a foreign owner, unsafe ancestry, and replacement during the open. On platforms where the ownership checks are not implemented, runtime configuration is rejected. These checks do not replace a setup approval of the runtime policy digest.

The runtime policy must name the same review-policy identity that is supplied to GitHub planning, and it must bind the decoded identity of the inventory. The daemon rejects partial configuration, identities that are cross-wired, and explicit handler identities that conflict.

At startup the daemon builds one catalog of the pipeline. It contains source acquisition, change construction, deterministic evidence, memory retrieval, context assembly, candidate generation, verification and publication readiness. The same snapshot of the inventory drives the policy for generation and for verification. The policy refers to OpenAI credentials by the name of an environment variable, and the daemon reads them only when an authorized provider request is dispatched. A credential that is missing or invalid at request time produces a closed provider failure, without changing the catalog identity or exposing the value.

## Local deterministic admission on the runs endpoint

You can configure `trestled` with `--setup-state`, `--expected-setup-root-identity`, all three `--local-git-repository-*` labels and `--local-git-objects-root`. When you do, the existing `POST /api/v1/runs` also accepts `open-trestle/local-deterministic-review-intent` version 1. The intent has no field for a filesystem path, source content, provider, credential, egress or publication. The daemon validates the scope, then saves the two root input artifacts and opens the plan of four tasks. Retrying the same intent resumes the same plan, and another intent at the same scope is a conflict.

This mode requires all of these:

- Local metadata and artifacts.
- One authorized logical repository.
- A numeric loopback listener.
- No TLS flags.
- No GitHub runtime.
- No configuration of model routes.

The startup process opens its configured loose-object root and keeps it open. An identity of the source root is bound into the source inputs and the handler identity. The HTTP request cannot select or replace that root.

The setup plan serves only as a fence on the scope and the posture of denied effects, for an initialized `local_single_node`. Its root identity, profile, tenant, repository, local storage posture, denied egress, disabled publication and disabled dynamic validation must match. This deterministic path performs no setup, inference, provider, egress or publication effect, so it does not use `Plan.Ready()`. The gates for policy, local inference, dry run, backup and observer, and other setup gates, remain pending. This admission is for evaluation and is not setup readiness or a supported deployment.

You can read a successful local run through the existing run, plan, diagnostics, runtime, TUI and embedded-console paths. Diagnostic set version 6, from the deterministic-only path, carries observations instead of verified findings. Version 7, from a full review, keeps observations and verified findings as separate sections. `runs status --format json|sarif` reads that same stored set. Receipts of active runs report the task status, and their wire format, which is unchanged, does not include coverage counts. The read-only progress endpoint for the scope supplies counts of evidence without creating provisional diagnostics.
