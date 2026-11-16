# Daemon API and client

`trestled` is the Open Trestle daemon. It keeps review runs in durable storage and exposes them through a versioned HTTP API. The Go client and the `trestle runs` commands use the same contracts. The daemon does not perform provider or forge effects by itself: workers must still pass the narrower provider and publication authorization gates.

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

The ordinary read, write and rename paths of the file journal and the artifact store use absolute pathnames after sampled checks of the root. At startup the daemon captures the root and runs a preflight with borrowed `os.Root` handles, but those handles do not pin later operations to the original directory for their whole lifetime. A process running as the same user that can rename an ancestor of the state directory during an operation is outside the current path-consistency guarantee. Checks of identity before an operation do not close that race.

Keep writable roots and their ancestors under the operator's exclusive control. This is not protection against a concurrent writer running as the same principal, and it is not a finished protocol for crash-consistent recovery across several roots. Before Open Trestle can claim the stronger guarantee, its normal operations still need to use rooted handles, and it needs tests for replacement during an operation.

### Startup inspection of the journal

Every startup with `metadata=local` inspects the entire bounded historical journal. It does this before it builds audit or diagnostics, starts workers or opens a listener. A valid historical v4 context-packet-prepared event blocks startup, even when its run is terminal or belongs to an old tenant or repository. This is a conservative rejection. It is not packet recovery, authority to dispatch a packet, attestation by the source owner or evidence that v1 is ready.

The local artifact store is constructed first and can recover pending deletions. The journal constructor also creates the state, changes its permissions and locks it before inspection. This is therefore not a check that runs before any effect on storage.

### What the state directory may contain

The private `--state-dir` root accepts only these direct entries:

- `.run-writer.lock`.
- Pairs of `.run-plan.json` and `.run.jsonl` files, named with an exact lowercase hexadecimal, 64-character scope digest.
- The private directories `artifacts`, `audit`, `diagnostics`, `webhook-inbox` and `setup`.

The inventory does not inspect or vouch for what is inside `setup`. Startup fails closed on any of these:

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

An older root that is otherwise valid but exceeds a limit needs offline review. A result that hits a limit, or that is incomplete or corrupt, proves neither that v4 events are present nor that they are absent. Open Trestle does not repair or delete rejected entries automatically.

A `--setup-state` directory placed directly inside `--state-dir` is now unsupported. This includes `plan.json` or `setup.json` and their lock and receipt siblings. This is a compatibility break in availability and layout for configurations that were accepted before. Put the setup plan at `--state-dir/setup/plan.json` or outside the daemon root. The documented `runs` root has `setup` as a sibling, while the webhook example can use a nested `setup/plan.json`.

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

By default, `runs status` prints one canonical `ReviewRunReceipt` JSON record that contains no secrets. With `--format json|sarif` it reads the stored diagnostic set instead. With `--format progress` it prints one object with exactly `run` and `progress`, taken from a single scoped progress response. It does not fetch a second receipt or merge receipt revisions. This CLI object leaves out the HTTP contract, version and request ID, so it is not the HTTP response envelope.

`runs status` adds diagnostics on stderr in these cases, and stdout stays unchanged:

- If the receipt or the final set records a context route refusal, it writes `runs status: task context refused: REASON (EXPLANATION)`. For `route_context_insufficient` it also writes a `hint:` line with the same text as the local review.
- If a final set was recorded after its evidence expired, it writes `runs status: ` followed by the shared evidence-expired text. The SARIF log then sets the `trestleEvidenceExpired` run property, appends the expiry to `trestleReason` and adds the same text as a `note` tool-execution notification. This way, an empty result list is not read as a clean review.

The plan input must be a regular file that does not change while it is read, and it is limited to 1 MiB. The command accepts one trailing newline and otherwise parses the canonical plan byte for byte. The client rejects plaintext remote endpoints. It never follows a redirect while it holds bearer authority.

## Runtime status

`GET /api/v1/tenants/{tenant}/repositories/{repository}/runtime` requires the separate `runtime_read` capability. It returns a snapshot, scoped to the repository, that contains no content. The snapshot describes these things:

- Storage posture.
- Review mode.
- Configured ingress and workers.
- Verification of the publication fence.
- Route and policy identities.
- Exact handler bindings.
- Startup state of the supervisors.

The snapshot never includes source, prompts, model or provider bodies, credentials, bearer leases, database names, bucket names, endpoints, queue contents or other repository identifiers. The configuration identity is derived from the projection for the one repository, so the membership of unrelated repositories does not change it. The configuration and observation identities make a stale or cross-wired status detectable.

Use the optional observer credential for read-only inspection:

```sh
OPEN_TRESTLE_API_TOKEN="$OPEN_TRESTLE_OBSERVER_TOKEN" \
  trestle admin runtime status --tenant example --repository example-repository
```

`trestle admin runtime status` prints one canonical `RuntimeStatus` snapshot. PostgreSQL configurations include the verified database authority identity, so the status identity changes if the storage authority changes. Failure output contains no content. A status of `starting` means that at least one configured supervisor has not yet completed its initial durable reconciliation. If a supervisor fails, the daemon stops instead of staying up as a stale `ready` process.

Budgeted artifact erasure does not add a field to `RuntimeStatus` v1. When startup builds the budgeted artifact store successfully, the status component list can include `artifact_erasure_budgeted` with state `ready`. That component means that startup built the protected policy, the explicit S3 erasure backend, the KMS provider, the verified PostgreSQL index and the budgeted envelope store. It is not a current health check for S3, KMS, bucket versioning, physical erasure, erasure authorization, policy freshness after startup, backups or provider availability. The v1 configuration identity continues to bind the existing status fields only. It does not bind the erasure mode.

In budgeted mode, artifact callers that the daemon owns use UTC millisecond timestamps before they call the store. The public store and erasure APIs still reject invalid or sub-millisecond times from callers instead of repairing them.

## Health probes

`GET` or `HEAD /healthz` returns whether the process is alive, with no other content. `GET` or `HEAD /readyz` returns `503 not_ready` until every configured durable supervisor has completed its initial reconciliation of the journal or the inbox. These two endpoints need no bearer credentials and expose no tenant, repository, queue, provider or storage detail. They reject other methods and query parameters.

## HTTP contracts

Every endpoint requires exactly one `Authorization: Bearer <credential>` header. Endpoints reject query parameters, unsupported content encodings, excessive request targets, oversized bodies, cross-tenant access, and repositories outside the principal's allowlist. Responses use `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`. Error responses contain bounded public codes instead of internal errors.

### Administration endpoint

`GET /api/v1/tenants/{tenant}/repositories/{repository}/runtime` returns a canonical `RuntimeStatus`, only to a principal that is authorized for the repository and has `runtime_read`.

Budgeted artifact erasure adds no administration or operator erasure route. The daemon's HTTP surface remains the endpoints listed here. Preparing, resuming and reading back erasure remain Go library APIs, and this daemon does not expose controls for them.

### Run endpoints

- `POST /api/v1/runs` accepts a canonical `ReviewRunPlan`. Run IDs that begin with `webhook-` are reserved for webhook intake. A plan or local review intent that names one gets `400 invalid_request` after the scope is authorized, so a caller cannot open a delivery's run scope before intake does.
- `GET /api/v1/tenants/{tenant}/repositories/{repository}/runs/{run}` returns a `ReviewRunReceipt`.
- `GET .../runs/{run}/progress` requires `run_read` and returns read-only counts of evidence that are bound to an unchanged canonical receipt.
- `GET .../runs/{run}/refusal` requires `run_read`. It returns the refusal that intake recorded for the webhook delivery that owns the run scope (`webhook-{deduplication key}`), instead of opening its run. The refusal has no content. It is returned as `open-trestle/delivery-refusal-response` v1, with the `open-trestle/webhook-delivery-refusal` record and its reason token. The response is `404 not_found` when no refusal is recorded or the daemon has no webhook planner, and `503 unavailable` when the inbox cannot be read. The daemon answers from its inbox for the planner identity that it admits deliveries with. `trestle runs refusal` prints the record, and `trestle runs status` names the reason when no run exists.
- `GET .../runs/{run}/diagnostics` returns the immutable canonical diagnostic set for that scope. See the version list below.
- `POST .../runs/{run}/cancel` accepts an empty body.
- `POST .../runs/{run}/finalize` accepts a canonical `TaskCompletion` from a controller that has explicit authorization. Its output or failure must exactly equal the disposition derived from the replayed task state. A daemon that runs with the runtime enabled normally finalizes runs automatically.

The diagnostic set comes in these versions:

- Versions 1 through 5 contain the state of independently verified findings.
- Version 2 includes exact counts of candidates, verified, rejected and inconclusive results.
- Version 3 also includes the identity of the verification context that supplied the result, and bounded counts of analyzed, selected and omitted sources.
- Version 4 adds sorted reasons for omissions. They are aggregates that contain no content, and their counts equal the total omitted.
- Version 5 adds one exact deterministic check, bound to its analysis result and the change.
- Version 6 instead contains one deterministic check and exact observations, bound to an analysis-result identity. It has no verified-finding set and grants no authority of independent verification.
- Version 7 is a set for the end of a full review only. It has a final outcome and optional exact evidence: deterministic evidence in the version 6 form and verified evidence in the version 5 form. Its top-level snapshot identifies the physical head source. The nested verified snapshot identifies the selected review snapshot, and the two need not be equal. An absent verified section means unknown, not zero findings.

### Read-only run progress

`GET /api/v1/tenants/{tenant}/repositories/{repository}/runs/{run}/progress` accepts no body. It requires one bearer credential, the exact tenant and repository allowlist, and `run_read`. The ordinary rate limits before authentication and per principal, described below, apply. This read has no separate permission for workers, models or publication.

The success response follows [`run-progress-response-v1.schema.json`](../schemas/controlplane/run-progress-response-v1.schema.json). It has exactly these members: `contract: open-trestle/run-progress-response`, `schema_version: 1`, a bounded `request_id`, `run` and `progress`. Its `run` member is the unchanged canonical `ReviewRunReceipt` (version 1, 2 or 3). It is not a new receipt version that carries progress. Its `progress` member has four independent axes:

- `change`: the changed `files` and `ranges`.
- `deterministic`: `applicable_files`, `applicable_ranges`, `checked_files`, `checked_ranges` and, when the recorded schema supplies it, the exact count of `observations`. Observations are not independently verified findings.
- `context`: the counts of `analyzed`, `selected` and `omitted` sources.
- `verification`: the counts of `candidates`, `verified`, `rejected` and `inconclusive`.

Each axis has a `state` and, when it refers to evidence, an immutable `artifact_identity`. The states mean the following:

- `not_run`: no completed result is recorded. This includes work that is pending, available or leased.
- `unavailable`: the evidence cannot be established. This includes failed or skipped tasks, artifacts that are missing, expired, unsupported or malformed, and an unavailable upstream lineage. A task that succeeded may keep its output identity while its counts remain unavailable.
- `available`: the counts came from canonical evidence.
- `partial`: only deterministic coverage uses it, when its recorded check explicitly reports incomplete coverage.

Missing counts are unknown, not zero. Counts are absent for `not_run` and `unavailable`. A numeric zero is returned only when recorded evidence proves zero. Historical deterministic evidence may supply all four check counts without observations, or it may omit the check counts.

For `change`, `deterministic` and `verification`, a present `artifact_identity` is the output identity of the matching task that succeeded. For an available `context` axis, it is the recorded context-packet artifact, which is proved through the output of the context task and the upstream lineage. A v6 context-input settlement can have a different, sanitized generation-input output identity in the receipt. The progress packet identity does not replace or relabel that output. Before the provenance of the packet is established, an unavailable context axis can keep the original output identity of the task that succeeded.

The counts follow two rules: `analyzed = selected + omitted` for context, and `candidates = verified + rejected + inconclusive` for verification. Neither available coverage nor a verified count says anything about approval or authority to publish.

The handler reads only the exact scoped artifacts that completed tasks refer to and their canonical lineage, with at most ten indexed artifact loads. The existing limits on artifact and parser bytes apply. The handler does not scan storage, execute tasks, call providers, publish preliminary diagnostics or change canonical state. After it retrieves the evidence, it checks the receipt identity again. If the run has advanced, `409 progress_changed` asks the caller to refresh, rather than combine counts from different receipt revisions. A progress read does not promise that the run cannot advance after the response.

### Worker endpoints

- `POST .../runs/{run}/worker/notifications/claim` accepts bounded wait and notification-lease durations. It returns a scheduling hint that has no content, or `204 No Content`.
- `POST .../runs/{run}/worker/notifications/acknowledge` accepts the current notification delivery capability and returns `204 No Content`.
- `POST .../runs/{run}/tasks/{task}/claim` accepts an exact approved handler identity.
- `POST .../runs/{run}/tasks/{task}/renew` accepts the current `TaskLease`.
- `POST .../runs/{run}/tasks/{task}/complete` accepts the current lease and a closed task completion.

A task notification is a hint and gives no authority over the task. Workers must still read the canonical run receipt and acquire the exact task lease. A notification claim may wait for up to ten seconds. Delivery leases are fenced by worker, token digest, delivery number and expiry, so a stale or duplicate notice cannot authorize execution.

A lease document is a bearer capability. It contains the random lease token. Do not log it, put it in URLs, or save it anywhere except a protected worker store. The durable run journal stores only its digest. Completion and renewal check the tenant scope, principal identity, plan, task, handler, attempt, token digest and expiry again. Repeating an identical completion is idempotent. Work that has expired or been replaced is fenced. After a task completes, the daemon derives the unique result output, or the earliest required terminal failure, and appends the terminal run event. At startup, a supervisor closes any run that has settled but was left active when a process stopped.

### Rate limits

The daemon applies bounded rate limits before authentication and per principal.

- Local metadata mode uses fixed windows within the process, and reports that limitation in the runtime status.
- PostgreSQL metadata mode uses fixed windows that follow the database clock, shared by every daemon with the same exact rate-limit authority. It stores only digests of the keys, separated by domain.
- Keys before authentication use the canonical, unmapped IP address of the direct TCP peer. The daemon never accepts forwarded-address headers as authority, so a reverse proxy must add its own limit that knows the client where that is needed.
- A database failure, a conflict over the live limiter authority, or exhaustion of the namespace cardinality returns 503 and grants no request.
- Exhausting the request quota of an established key returns 429.

A trusted external ingress may add a stricter, independent limit, but the application does not need one to be correct across daemons.

## Local setup API

`trestle setup web` serves a separate setup API with its own dedicated setup bearer token. The API listens on a numeric loopback address only, and it checks the exact Host. It is not an endpoint that issues credentials for the daemon.

For integration effects, the host must capture `OPEN_TRESTLE_GITHUB_SOURCE_BROKER_CONFIG` and an exact `--approve-github-source-broker-authority-identity` cap at startup. The protected descriptor remains `open-trestle/github-source-broker` schema 1 with exactly 20 fields; see [Setup planning](setup.md#github-integration-permissions). No request can provide configuration paths, PEM data, tokens, overrides of the owner generation, or the old endpoint, version, installation and repository quartet.

`POST /api/v1/setup/check` uses `open-trestle/setup-check-request` schema 2 for the integration check only. These are the nine required fields, in encoder order:

| Field | Value |
|---|---|
| `contract` | `open-trestle/setup-check-request` |
| `schema_version` | integer `2` |
| `plan_identity` | current nonzero lowercase HEX64 |
| `key` | `integration_permissions_validated` |
| `confirmation` | `create GitHub installation token and run integration_permissions_validated` |
| `approve_integration_permission_authority_identity` | independently approved nonzero lowercase HEX64 |
| `approve_github_source_broker_authority_identity` | exact host common cap, nonzero lowercase HEX64 |
| `allow_github_installation_token_creation` | boolean `true` |
| `approved_by` | exact recovery owner, ASCII setup label of 1..128 bytes |

The order of the members in the input is not authority. All fields are required, and extra members are rejected. These cases all get `400 invalid_request` before state is accessed:

- Missing, false, null or string consent.
- Duplicate or case-folded keys.
- Mixed fields.
- The old confirmation.
- A v2 request for another check.

An unsupported content type gets 415, and a body above 64 KiB gets 413. Host fencing and bearer authentication come before decoding, and a bearer token alone never approves creation.

A legacy v1 integration request that is well formed returns `422 check_unavailable` before any state is accessed or any builder runs. A malformed v1 integration request gets 400. Unrelated v1 requests keep their wire format and response behavior. A valid v2 request then opens the protected state: invalid state gets `409 state_conflict`, and an expected plan that does not match gets `409 stale_plan`.

Only after the plans are equal may the captured host and session builder check the common approval and the scope. If there is no host, or the common approval or scope does not match, the result is `422 check_unavailable`, with no work on the owner, key or HTTP. The Runner rejects historical integration and webhook authority before it recovers anything pending or runs a check (`422 check_failed`). A wrong actor or permission approval uses the existing blocked-receipt behavior, without probing.

A current success still uses the setup-check-result and setup-check-receipt schema 1, with the current integration checker identity. Parsing of historical plans and receipts is unchanged. A Ready result from before is historical and is not an active approval. Initialize a fresh protected state and a current plan, and rerun every check that is not deterministic. Never import or relabel old receipts. The marker in the browser is only a diagnostic.

Native effects require all of these: the host cap, consent in the request, both authorities, scope, actor, the expected current plan, user visibility and an actual native setup-purpose grant. Approvals for runtime and for publication remain separate.

`trestle admin github permissions identity --broker-config PATH` prints a schema 2 `open-trestle/github-permission-admin-result`. It has exactly these members: contract, schema version, `status: configuration_only`, `operation: identity`, `broker_authority_identity`, `setup_issuance_authority_identity` and `permission_authority_identity`. It reads protected configuration and derives the identities natively, and does nothing else: no approval, no owner creation, no credential reads and no issuance. The legacy admin quartet is mutually exclusive with it. It remains schema 1, can still be read, and cannot execute for current setup.

### Credential session and shutdown

One lazy credential session belongs to the lifetime of the web handler, not to each request. Records of the owner and of attempts, which contain no content, remain. Tokens are not saved. Renewal happens only on foreground demand. After a restart you need an explicit new generation and a new approval. Open Trestle never deletes the owner or rebuilds it automatically. `single_host_exclusive` ownership excludes ownership of credentials on a shared volume or in HA, even when a plan names `kubernetes_ha`.

On shutdown, the handler first cancels the owner's lifetime, allows HTTP Shutdown five seconds, and forces a server Close if that fails. It then closes the lifetime of the broker, with a separate bounded five-second drain. It reports both failures without internal details. An incomplete Close result is cached, and closing logically is not the same as being physically quiet. These are two separate budgets in sequence. They are not one five-second limit and not a hard ten-second guarantee. A cleanup failure does not roll back a saved receipt or a provider effect that was accepted. Recovering a pending receipt that is stored durably never needs a broker to be open. This contract grants no permission to issue tokens live or to delete anything.

## Go client

The public `client`, `controlplane` and `runtimeadmin` packages expose strict types for plans, receipts, leases, completions, and runtime status without content. The client supports runtime inspection, submission, observation, cancellation, waiting for and acknowledging notifications, task claims, renewal, completion and finalization. It limits responses to 1 MiB, requires JSON media types, rejects unknown response fields, applies a request timeout and disables redirects.

## Metadata storage selection

The daemon defaults to private local file journals. `--metadata-store postgres` selects the PostgreSQL run journal, the protected diagnostic metadata, the protected webhook metadata and the artifact index. It still uses the private local artifact directory, so this combination is a durability profile for a single node, not an HA profile.

Set `OPEN_TRESTLE_POSTGRES_URL` to the data source for the application role, and pass the runtime role's retained identity as `--postgres-database-authority-identity`. Before it serves requests, the daemon does the following:

1. Verifies that both authority relations resolve to the active schema.
2. Verifies the checksum of every embedded migration.
3. Derives the identity of the connected database, schema, role and namespace in the same repeatable-read snapshot.
4. Requires that this identity matches exactly.

By default, schema changes are not applied through the application role. To run them at startup, add `--apply-migrations` and set `OPEN_TRESTLE_POSTGRES_MIGRATION_URL` for the separate migration role. The daemon rejects an unused database URL, a migration URL without the flag, and the flag without a migration URL. The application role must not be a superuser, must not have `BYPASSRLS`, and needs no authority to create schemas.

### Shared S3 artifact storage

`--artifact-store s3` enables the shared profile with envelope storage, and it requires `--metadata-store postgres`. It also requires `--s3-endpoint`, `--s3-region`, `--s3-bucket`, `--kms-region` and `--kms-key-arn`. S3 signing uses `OPEN_TRESTLE_S3_ACCESS_KEY_ID`, `OPEN_TRESTLE_S3_SECRET_ACCESS_KEY` and the optional `OPEN_TRESTLE_S3_SESSION_TOKEN`. KMS uses the separate `OPEN_TRESTLE_AWS_ACCESS_KEY_ID`, `OPEN_TRESTLE_AWS_SECRET_ACCESS_KEY` and the optional `OPEN_TRESTLE_AWS_SESSION_TOKEN`. A secure `--kms-endpoint` is optional.

The daemon builds one exact registry that maps each tenant to its key, uses the bounded, version-required S3 backend, and records artifact metadata through `IndexedArtifactStore`. It rejects remote-storage configuration that is unused or incomplete.

Separate explicit S3 and KMS credentials sign their own requests, and the daemon rejects an access-key ID that is identical in both roles. Scope each production principal to the configured bucket prefix or the tenant's KMS key only. This daemon entry point accepts explicit credentials from the environment. A deployment that needs workload identity must provide a separately reviewed credential adapter, instead of quietly reusing these flags.

Both remote-storage clients disable environment proxies, reject redirects, bound the size of response headers, and close idle connections on shutdown. KMS bodies are capped at 1 MiB. S3 object reads keep the adapter's 32 MiB bound. HTTPS requires TLS 1.2 or newer, and plain HTTP is accepted only for an IP-literal loopback test endpoint. The daemon will not quietly treat a local wrapping key as envelope protection for production.

### Artifact erasure mode

`--artifact-erasure-mode` selects how artifact erasure is wired at runtime. It accepts `legacy` and `budgeted`, and `legacy` is the default. Existing local artifact storage and legacy S3 envelope storage keep their current defaults and startup behavior. `--erasure-policy` and `--s3-erasure-trusted-ca` are accepted only with `--artifact-erasure-mode budgeted`.

Budgeted erasure is valid only with PostgreSQL metadata and S3 artifacts. It requires all of these:

- `--metadata-store postgres`.
- `--artifact-store s3`.
- `OPEN_TRESTLE_POSTGRES_URL`.
- The exact `--postgres-database-authority-identity`.
- The existing S3 and KMS flags.
- The existing, separate environments for S3 and KMS credentials.
- `--erasure-policy`.
- `--s3-erasure-trusted-ca`.

It rejects `--apply-migrations` and any `OPEN_TRESTLE_POSTGRES_MIGRATION_URL`. An authorized migration administrator must manage schema changes separately, before this daemon starts.

```sh
trestled \
  --listen 127.0.0.1:8741 \
  --state-dir "$HOME/.local/state/open-trestle" \
  --tenant example \
  --repository example-repository \
  --metadata-store postgres \
  --postgres-database-authority-identity "$POSTGRES_DATABASE_AUTHORITY_IDENTITY" \
  --artifact-store s3 \
  --artifact-erasure-mode budgeted \
  --erasure-policy /etc/open-trestle/artifact-erasure-policy.json \
  --s3-erasure-trusted-ca /etc/open-trestle/s3-erasure-ca.pem \
  --s3-endpoint https://s3.example.invalid \
  --s3-region us-east-1 \
  --s3-bucket open-trestle-artifacts \
  --s3-prefix reviews \
  --kms-region us-east-1 \
  --kms-key-arn arn:aws:kms:us-east-1:123456789012:key/KEY-ID
```

The protected erasure policy must be current at the startup sample that the daemon takes itself. It must bind the configured PostgreSQL database authority, the identity of the S3 backend configuration, the configured S3 prefix and the expected storage namespace.

The S3 erasure CA is an explicit, protected trust file. It must be an absolute clean path to a regular file with a trusted owner. The daemon reads it twice to check that it is stable, and it must not be empty and must be at most 256 KiB. The budgeted erasure backend uses HTTPS with those explicit roots only. Through these flags it does not use ambient S3 trust roots, injected transports, hidden credentials or workload identity.

At startup in budgeted mode, the daemon builds the local state of the S3 erasure and KMS clients, loads the policy and CA files, and verifies the PostgreSQL authority and the budgeted erasure index. It makes zero S3 or KMS requests before it serves. Startup does not replace the checks that later store operations make. It also does not prove live S3 or KMS health, bucket versioning, physical erasure, authorization of erasure, backup recovery or future availability.

### Task notifications in PostgreSQL

PostgreSQL also stores task notifications that contain no content. A transaction trigger sends a `NOTIFY` with an empty payload after inserts into the run events and the queue. Long-poll API requests and the notification supervisor use `LISTEN` as a signal to wake up. If a notification is duplicated or missed, the durable queue and the canonical journal remain authoritative. The daemon exposes liveness probes without content and readiness probes that the supervisors back. Before Open Trestle can claim HA, it still needs webhook supervision that does not depend on a leader, and tested evidence of database failover.

## GitHub run opening

GitHub ingress durably acknowledges deliveries without requiring runs to be created automatically. To enable the durable run supervisor, add all of these:

- `--github-open-runs`.
- `--github-repository-full-name`.
- `--github-review-policy-identity`.
- `--github-review-mode`.
- `--github-publisher-id`.
- One `--github-handler KIND=IDENTITY` for each required task kind.

Advisory and local plans require handlers from `acquire_source` through `evaluate_publication`. Required plans also require `publish_result`. The daemon rejects bindings that are missing, duplicated, unknown or malformed before the listener starts.

## Daemon-owned deterministic workers

Add `--github-local-deterministic-workers` to execute the built-in handlers for GitHub source acquisition, the exact change model, deterministic evidence and bounded memory retrieval inside the daemon process. The option requires `--github-open-runs`. The handler identities for those four task kinds are derived from the configured built-ins and merged into the planner, and a conflicting explicit `--github-handler` is rejected. The handlers for context, the model, readiness and the optional publication remain separately configured authorities.

Without a broker descriptor, `OPEN_TRESTLE_GITHUB_API_TOKEN` keeps the legacy configuration for source acquisition. If it is not set, acquisition is anonymous. If it is set, the value must be safe for an HTTP header. This static token is not current evidence of setup permissions. The daemon rejects it, rather than ignoring it, when local deterministic workers are disabled.

Broker mode uses the protected `OPEN_TRESTLE_GITHUB_SOURCE_BROKER_CONFIG` descriptor and an independent common approval, `--approve-github-source-broker-authority-identity`. The daemon rejects static credentials mixed in. Runtime source acquisition owns a separate broker for the runtime purpose, and grants and receipts from setup cannot authorize it. The descriptor remains schema 1, with `single_host_exclusive` ownership and explicit consent to create tokens and to renew them on demand. It does not provide ownership of credentials in HA, recovery after an automatic restart or authority to publish.

## Policy-bound model pipeline

To run the complete advisory pipeline in `trestled`, set both `--runtime-route-inventory PATH` and `--runtime-policy PATH` together with `--github-local-deterministic-workers`. The files must conform to the published runtime schemas. Each path must resolve directly to a regular file that belongs to the daemon user or root and is not writable by group or world.

Every ancestor must have trusted ownership and must prevent another local principal from replacing it. Writable ancestors are allowed only with sticky-directory protection for a child with a trusted owner. The daemon rejects symlinks, files with a foreign owner, unsafe ancestry, and replacement during the open. On platforms where the ownership checks are not implemented, runtime configuration fails closed. These checks establish authority over the local file. They are not a separate setup approval of the digest of the runtime policy.

The runtime policy must name the same review-policy identity that is supplied to GitHub planning, and it must bind the exact decoded identity of the inventory. The daemon rejects partial configuration, identities that are cross-wired, required publication mode without the separate publication authority described below, and explicit handler identities that conflict.

At startup the daemon builds one exact catalog of the pipeline. It contains source acquisition, change construction, deterministic evidence, bounded memory retrieval, context assembly, candidate generation, independent verification and publication readiness. The same snapshot of the inventory drives the policy for generation and for verification. The policy refers to OpenAI credentials by the name of an environment variable, and the daemon reads them only when an authorized provider request is dispatched. A credential that is missing or invalid at request time produces a closed provider failure, without changing the catalog identity or exposing the value.

External publication in required mode is deliberately unavailable through these two files alone. It needs a separately configured effect authorizer, a publisher catalog and a current-head resolver. This keeps the configuration of model routing from granting write authority over a repository by implication.

## Required-mode GitHub publication

Publication by the daemon in required mode needs all of the following, in addition to the policy-bound model pipeline:

- PostgreSQL metadata storage, which supplies the durable publication fence on the operation key.
- `--postgres-database-authority-identity`, the exact identity of the runtime-role database, as reported by `trestle admin postgres identity`.
- `--postgres-authority-identity`, a stable digest that is not secret, verified against the fence namespace that the database generated.
- `--github-enable-publication`.
- `--github-publication-policy-identity` and `--github-publication-principal-identity`, both as nonzero canonical digests.
- `--github-publication-authorization-ttl`, between one minute and 24 hours.
- `OPEN_TRESTLE_GITHUB_PUBLICATION_TOKEN`, available when a publication request is dispatched.

The enable flag is an explicit policy grant for the whole repository, for the configured tenant and repository. When a task runs, the authorizer creates a short-lived `publication` grant for the exact review scope. It cannot authorize another tenant, repository, capability, readiness plan or target. Before it dispatches, the publication handler still requires protected lineage, a match with the fresh head, an exclusive claim on the operation, and the exact catalogs of publishers and resolvers.

The publication token is separate from the credentials for webhooks, source reads, the API, the database, object storage, KMS and the model provider. The daemon does not read its presence or value at startup. It reads the token only after the scope and the immutable repository target match. The daemon rejects any part of the publication configuration that is supplied without the explicit enable flag.

Local metadata mode rejects required publication, because it does not yet supply the durable fence across processes for the operation. A PostgreSQL store that is unbound or unverified also exposes no identity for the publication attempt guard. Initialize a new authority row only with `trestle admin postgres initialize`. Daemon startup never initializes publication authority, because startup output is not a suitable channel for a recovery receipt. If the PostgreSQL authority digest, the database name, the active schema or the generated namespace UUID changes, the identities of the GitHub publisher and the publication handler change. A database that was restored or replaced therefore cannot quietly stand in for the original fence namespace.

## Local deterministic admission on the runs endpoint

You can configure `trestled` with `--setup-state`, `--expected-setup-root-identity`, all three `--local-git-repository-*` labels and `--local-git-objects-root`. When you do, the existing `POST /api/v1/runs` also accepts `open-trestle/local-deterministic-review-intent` version 1. The intent has no field for a filesystem path, source content, provider, credential, egress or publication. The daemon validates the scope, then saves the two root input artifacts and opens the plan of four tasks. Retrying the exact same intent resumes the same plan, and another intent at the same scope is a conflict.

This mode requires all of these:

- Local metadata and artifacts.
- One authorized logical repository.
- A numeric loopback listener.
- No TLS flags.
- No GitHub runtime.
- No configuration of model routes.

The startup process opens its configured loose-object root and keeps it open. An identity of the source root is bound into the source inputs and the handler identity. The HTTP request cannot select or replace that root.

The setup plan serves only as a fence on the scope and the posture of denied effects, for an initialized `local_single_node`. Its root identity, profile, tenant, repository, local storage posture, denied egress, disabled publication and disabled dynamic validation must match. This deterministic path performs no setup, inference, provider, egress or publication effect, so it does not use or imply `Plan.Ready()`. The gates for policy, local inference, dry run, backup and observer, and other setup gates, remain pending. Do not describe this narrow admission for evaluation as readiness of setup or as authority for a supported deployment.

You can read a successful local run through the existing run, plan, diagnostics, runtime, TUI and embedded-console paths. Diagnostic set version 6, from the deterministic-only path, carries observations instead of verified findings. Version 7, from a full review, keeps observations and independently verified findings as separate sections. `runs status --format json|sarif` reads that same stored set. Receipts of active runs report the task status, and their wire format, which is unchanged, does not include coverage counts. The read-only progress endpoint for the scope supplies separately bound counts of evidence without creating provisional diagnostics.
