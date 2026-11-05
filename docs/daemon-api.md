# Daemon API and client

`trestled` exposes the durable review-run coordinator through a versioned HTTP API. The same contracts are used by the Go client and the `trestle runs` commands. The daemon does not perform provider or forge effects by itself. Workers must still pass the narrower provider and publication authorization gates.

## Start a local daemon

Set a random operator credential with at least 32 bytes. It has run, worker, and runtime authority. Optionally set a different observer credential when a person or read-only console only needs run and runtime inspection. If it is absent, only the full-authority operator credential is accepted. Keep both outside command-line arguments and repository files.

```sh
export OPEN_TRESTLE_API_TOKEN="replace-with-a-random-operator-secret-of-at-least-32-bytes"
export OPEN_TRESTLE_OBSERVER_TOKEN="replace-with-a-different-observer-secret"
go run ./cmd/trestled \
  --listen 127.0.0.1:8741 \
  --state-dir "$HOME/.local/state/open-trestle/runs" \
  --tenant example \
  --repository example-repository
```

Plain HTTP is accepted only on a numeric loopback address. A non-loopback listener requires both `--tls-cert` and `--tls-key`. The TLS private key must be a regular file without group or other permissions. The daemon requires TLS 1.3 for direct TLS listeners.

The file journal takes an exclusive writer lock. It uses private directory and file permissions, bounded canonical records, atomic replacement, file and directory synchronization, and corruption checks. A second daemon cannot open the same journal root.

The ordinary file-journal and artifact-store read/write/rename paths use absolute pathnames after sampled root checks. The startup root capture and preflight borrowed `os.Root` handles do not pin these later operations to the original directory for their entire lifetime. A same-UID process that can rename a state-directory ancestor during an operation is outside the current path-consistency guarantee; pre-operation identity checks do not close that race. Keep writable roots and their ancestors under exclusive operator control. Do not treat this as protection against a concurrent same-principal writer or as a completed crash-consistent multi-root recovery protocol. Rooted-handle normal operations and replacement-during-operation tests are still needed before claiming that stronger guarantee.

Every `metadata=local` startup inspects the entire bounded historical journal before constructing audit or diagnostics, starting workers, or opening a listener. A valid historical v4 context-packet-prepared event blocks startup even when its run is terminal or belongs to an old tenant/repository. This is a conservative rejection, not packet recovery, packet dispatch authority, source-owner attestation, or evidence of v1 readiness. The local artifact store is constructed first and can recover pending deletions; the journal constructor also creates, chmods, and locks state before inspection. Do not call this a pre-storage-effect check.

The private direct `--state-dir` root admits only `.run-writer.lock`, exact lowercase-hex 64-character scope digest `.run-plan.json`/`.run.jsonl` pairs, and private `artifacts`, `audit`, `diagnostics`, `webhook-inbox`, and `setup` directories. The inventory does not inspect or attest the contents of `setup`. Unknown direct entries, symlinks, broad permissions on direct entries, orphan streams, incomplete plan-only prefixes, and corrupt journal records fail closed. The scan has fixed bounds: 1,024 direct entries (including lock/directories), 500 plans, 128 KiB per encoded plan, 64 MiB per stream, and 256 MiB aggregate encoded plan/stream bytes. An otherwise valid older root over a bound requires offline review; a limit or incomplete/corrupt result proves neither v4 presence nor v4 absence. Do not automatically repair or delete rejected entries.

A configured `--setup-state` directly inside `--state-dir`, including `plan.json` or `setup.json` and their lock/receipt siblings, is newly unsupported. This is an availability and layout compatibility break for previously accepted configurations. Put the setup plan at `--state-dir/setup/plan.json` or outside the daemon root; the documented `runs` root has setup as a sibling, while the webhook example can use nested `setup/plan.json`. For an existing direct-root plan, stop both writers and follow the [verified offline setup backup and restore](setup.md#offline-move-of-a-direct-root-setup-plan). The guard does not move or delete existing files. Leftovers at the direct root still block startup and need manual offline review.

## Optional GitHub webhook endpoint

Configure one repository-scoped webhook endpoint with a secret held only in the environment and a non-secret key version used for receipt lineage:

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

This mounts `POST /webhooks/github`. The fixed subscription accepts `pull_request` actions `opened`, `reopened`, `synchronize`, and `ready_for_review`. The secret is not written to the inbox. Change `--github-webhook-key-id` when rotating the secret so later delivery receipts bind the new verifier configuration. See [Verified webhook ingress](webhook-ingress.md).

## CLI

The CLI reads `OPEN_TRESTLE_API_TOKEN` and uses `OPEN_TRESTLE_API_URL`, which defaults to `http://127.0.0.1:8741`.

```sh
trestle runs submit --plan review-run-plan.json
trestle runs status --tenant example --repository example-repository --run run-123
trestle runs cancel --tenant example --repository example-repository --run run-123
```

The default run output is one canonical, secret-free `ReviewRunReceipt` JSON record. `runs status --format json|sarif` instead reads the stored diagnostic set. `runs status --format progress` prints one bound object with exactly `run` and `progress`, obtained from one scoped progress response. It does not fetch a second receipt or merge receipt revisions. The CLI object omits the HTTP contract, version, and request ID; it is not the HTTP response envelope. The plan input must be an unchanged regular file and is bounded to 1 MiB. One trailing newline is accepted; the canonical plan is otherwise parsed byte for byte. The client rejects plaintext remote endpoints and never follows redirects with bearer authority.

## Runtime status

`GET /api/v1/tenants/{tenant}/repositories/{repository}/runtime` requires the separate `runtime_read` capability. It returns a content-free, repository-scoped snapshot of storage posture, review mode, configured ingress and workers, publication-fence verification, route and policy identities, exact handler bindings, and supervisor startup state. The snapshot never includes source, prompts, model or provider bodies, credentials, bearer leases, database names, bucket names, endpoints, queue contents, or other repository identifiers. The configuration identity is derived from the one-repository projection, so unrelated repository membership does not change it. Configuration and observation identities make stale or cross-wired status detectable.

Use the optional observer credential for read-only inspection:

```sh
OPEN_TRESTLE_API_TOKEN="$OPEN_TRESTLE_OBSERVER_TOKEN" \
  trestle admin runtime status --tenant example --repository example-repository
```

`trestle admin runtime status` prints one canonical `RuntimeStatus` snapshot. PostgreSQL configurations include the verified database authority identity, so status identity changes if storage authority changes. Failure output is content-free. A status of `starting` means at least one configured supervisor has not completed initial durable reconciliation. Supervisor failure stops the daemon rather than leaving a stale `ready` process.

Budgeted artifact erasure does not add a `RuntimeStatus` v1 field. When startup constructs the budgeted artifact store successfully, the status component list can include `artifact_erasure_budgeted` with state `ready`. That component means startup built the protected policy, explicit S3 erasure backend, KMS provider, verified PostgreSQL index, and budgeted envelope store. It is not a current health check for S3, KMS, bucket versioning, physical erasure, erasure authorization, policy freshness after startup, backups, or provider availability. The v1 configuration identity continues to bind the existing status fields only; it does not newly bind the erasure mode.

In budgeted mode, daemon-owned artifact callers use UTC millisecond timestamps before they call the store. Public store and erasure APIs still reject invalid or sub-millisecond caller times instead of repairing them.

## Health probes

`GET` or `HEAD /healthz` returns content-free process liveness. `GET` or `HEAD /readyz` returns `503 not_ready` until every configured durable supervisor completes its initial journal or inbox reconciliation. These two endpoints do not require bearer credentials and expose no tenant, repository, queue, provider, or storage detail. Other methods and query parameters are rejected.

## HTTP contracts

All endpoints require exactly one `Authorization: Bearer <credential>` header. They reject query parameters, unsupported content encodings, excessive request targets, oversized bodies, cross-tenant access, and repositories outside the principal allowlist. Responses use `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`. Error responses contain bounded public codes rather than internal errors.

Administration endpoint:

- `GET /api/v1/tenants/{tenant}/repositories/{repository}/runtime` returns a canonical `RuntimeStatus` only to a repository-authorized principal with `runtime_read`.

Budgeted artifact erasure adds no administration or operator erasure route. The daemon HTTP surface remains the endpoints listed here. Erasure preparation, resume, and historical readback remain Go library APIs. This daemon does not expose controls for them.

Run endpoints:

- `POST /api/v1/runs` accepts a canonical `ReviewRunPlan`.
- `GET /api/v1/tenants/{tenant}/repositories/{repository}/runs/{run}` returns a `ReviewRunReceipt`.
- `GET .../runs/{run}/progress` requires `run_read` and returns read-only evidence counts bound to an unchanged canonical receipt.
- `GET .../runs/{run}/diagnostics` returns the immutable canonical diagnostic set for that scope. Versions 1 through 5 contain independently verified finding state. Version 2 includes exact candidate, verified, rejected, and inconclusive counts. Version 3 also includes the supplying verification-context identity and bounded analyzed, selected, and omitted source counts. Version 4 adds sorted content-free aggregate omission reasons whose counts equal the omitted total. Version 5 adds one exact deterministic check bound to its analysis result and change. Version 6 instead contains one deterministic check and exact observations bound to an analysis-result identity; it has no verified-finding set and grants no independent-verification authority. Version 7 is a terminal-only full-review set with a final outcome and optional exact version 6 deterministic and version 5 verified evidence. Its top-level snapshot identifies the physical head source; the nested verified snapshot identifies the selected review snapshot and need not be equal. An absent verified section is unknown, not zero findings.
- `POST .../runs/{run}/cancel` accepts an empty body.
- `POST .../runs/{run}/finalize` accepts a canonical `TaskCompletion` for an explicitly authorized controller. Its output or failure must exactly equal the disposition derived from replayed task state. Runtime-enabled daemon operation normally finalizes automatically.

### Read-only run progress

`GET /api/v1/tenants/{tenant}/repositories/{repository}/runs/{run}/progress` accepts no body. It requires one bearer credential, the exact tenant/repository allowlist, and `run_read`. The ordinary pre-authentication and per-principal rate limits below apply. There is no separate worker, model, or publication permission in this read.

The success response follows [`run-progress-response-v1.schema.json`](../schemas/controlplane/run-progress-response-v1.schema.json). It has exactly `contract: open-trestle/run-progress-response`, `schema_version: 1`, a bounded `request_id`, `run`, and `progress`. Its `run` field is the unchanged canonical `ReviewRunReceipt` (version 1 or 2), not a new progress-bearing receipt version. Its `progress` field has four independent axes:

- `change`: changed `files` and `ranges`.
- `deterministic`: `applicable_files`, `applicable_ranges`, `checked_files`, `checked_ranges`, and exact `observations` count when the recorded schema supplies it. Observations are not independently verified findings.
- `context`: `analyzed`, `selected`, and `omitted` source counts.
- `verification`: `candidates`, `verified`, `rejected`, and `inconclusive` counts.

Each axis has a `state` and, when evidence is referenced, an immutable `artifact_identity`. `not_run` means no completed result is recorded, including pending, available, or leased work. `unavailable` means its evidence cannot be established, including failed or skipped tasks, missing, expired, unsupported, or malformed artifacts, or an unavailable upstream lineage. A succeeded task may retain its output identity while its counts remain unavailable. `available` means the counts came from canonical evidence. Only deterministic coverage uses `partial`: its recorded check explicitly reports incomplete coverage. Missing counts are unknown, not zero. Counts are absent for `not_run` and `unavailable`; numeric zero is returned only when recorded evidence proves zero. Historical deterministic evidence may supply all four check counts without observations, or omit the check counts.

For `change`, `deterministic`, and `verification`, a present `artifact_identity` is the matching succeeded task's output identity. For available `context`, it is the recorded context-packet artifact proved through the context task output and upstream lineage. A v6 context-input settlement can have a distinct sanitized generation-input output identity in the receipt; the progress packet identity does not replace or relabel that output. Before packet provenance is established, an unavailable context axis can retain the succeeded task's original output identity. Context counts obey `analyzed = selected + omitted`. Verification counts obey `candidates = verified + rejected + inconclusive`. Neither available coverage nor a verified count asserts approval or publication authority.

The handler reads only exact scoped artifacts referenced by completed tasks and their canonical lineage, with at most ten indexed artifact loads. Existing artifact and parser byte limits apply. It does not scan storage, execute tasks, call providers, publish preliminary diagnostics, or change canonical state. Receipt identity is checked again after evidence retrieval. If the run advanced, `409 progress_changed` asks the caller to refresh rather than combine counts from different receipt revisions. A progress read does not promise that the run cannot advance after the response.

Worker endpoints:

- `POST .../runs/{run}/worker/notifications/claim` accepts bounded wait and notification-lease durations. It returns a content-free scheduling hint or `204 No Content`.
- `POST .../runs/{run}/worker/notifications/acknowledge` accepts the current notification delivery capability and returns `204 No Content`.
- `POST .../runs/{run}/tasks/{task}/claim` accepts an exact approved handler identity.
- `POST .../runs/{run}/tasks/{task}/renew` accepts the current `TaskLease`.
- `POST .../runs/{run}/tasks/{task}/complete` accepts the current lease and a closed task completion.

A task notification is a hint, not task authority. Workers must still read the canonical run receipt and acquire the exact task lease. Notification claims may wait for up to ten seconds. Delivery leases are fenced by worker, token digest, delivery number, and expiry. A stale or duplicate notice cannot authorize execution.

A lease document is a bearer capability. It contains the random lease token and must not be logged, placed in URLs, or persisted outside a protected worker store. The durable run journal stores only its digest. Completion and renewal recheck tenant scope, principal identity, plan, task, handler, attempt, token digest, and expiry. Replayed identical completion is idempotent. Expired or replaced work is fenced. After task completion, the daemon derives the unique result output or earliest required terminal failure and appends the terminal run event. Supervisor startup closes any settled run left active by a process stop.

The daemon applies bounded pre-authentication and per-principal rate limits. Local metadata mode uses process-local fixed windows and reports that limitation in runtime status. PostgreSQL metadata mode uses database-clock fixed windows shared by every daemon with the same exact rate-limit authority. It stores domain-separated key digests only. Pre-authentication keys use the canonical unmapped IP of the direct TCP peer; forwarded-address headers are never accepted as authority, so a reverse proxy must add its own client-aware limit when needed. Database failure, live limiter-authority conflict, or namespace-cardinality exhaustion returns 503 and grants no request. Exhaustion of an established key's request quota returns 429. A trusted external ingress may add a stricter independent limit but is not required for cross-daemon application correctness.

## Local setup API

`trestle setup web` serves a separate numeric-loopback, exact-Host-fenced setup API with a dedicated setup bearer token. It is not a daemon issuance endpoint. For integration effects the host must capture `OPEN_TRESTLE_GITHUB_SOURCE_BROKER_CONFIG` and an exact startup `--approve-github-source-broker-authority-identity` cap. The protected descriptor remains `open-trestle/github-source-broker` schema 1 with exactly 20 fields; see [Setup planning](setup.md#github-integration-permissions). No request can provide configuration paths, PEM, tokens, owner-generation overrides, or the old endpoint/version/installation/repository quartet.

`POST /api/v1/setup/check` uses `open-trestle/setup-check-request` schema 2 only for integration. The exact nine required fields, in encoder order, are:

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

Input member order is not authority. All fields are required, and additional members are rejected. Missing, false, null, or string consent, duplicate or case-folded keys, mixed fields, old confirmation, and v2 for another check are `400 invalid_request` before state access. Unsupported content type is 415; a body above 64 KiB is 413. Host fencing and bearer authentication precede decoding. A bearer token alone never approves creation.

A well-shaped legacy v1 integration request returns `422 check_unavailable` before state access or builder work. Malformed v1 integration is 400. Unrelated v1 requests retain their wire and response semantics. A valid v2 request then opens protected state: invalid state is `409 state_conflict`, and expected-plan mismatch is `409 stale_plan`. Only after plan equality may the captured host/session builder check common approval and scope. Absent host or mismatched common/scope is `422 check_unavailable` without owner, key, or HTTP work. The Runner rejects historical integration and webhook authority before pending recovery or Check (`422 check_failed`). Wrong actor or permission approval uses the existing blocked receipt semantics without probing.

Current success still uses setup-check-result and setup-check-receipt schema 1 with the current integration checker identity. Historical plan and receipt parsing is unchanged. Old Ready is historical, not active approval. Initialize fresh protected state/current plan and rerun all nondeterministic checks; never import or relabel old receipts. The browser marker is diagnostic only. Native effects require host cap, request consent, both authorities, scope, actor, expected current plan, user visibility, and an actual native setup-purpose grant. Runtime-purpose and publication approvals remain separate.

`trestle admin github permissions identity --broker-config PATH` emits schema 2 `open-trestle/github-permission-admin-result`: exactly contract, schema version, `status: configuration_only`, `operation: identity`, `broker_authority_identity`, `setup_issuance_authority_identity`, and `permission_authority_identity`. It performs protected configuration reads and native pure derivation only, not approval, owner creation, credential reads, or issuance. The mutually exclusive legacy admin quartet remains schema 1, readable and non-executable for current setup.

One lazy credential session belongs to the web handler lifetime, not each request. Content-free owner/attempt records remain; tokens are not persisted. Renewal is foreground demand only. Restart needs an explicit fresh generation and reapproval, never owner deletion or automatic reconstruction. `single_host_exclusive` ownership excludes shared-volume and HA credential ownership even when a plan names `kubernetes_ha`.

Shutdown first cancels owner lifetime, gives HTTP Shutdown five seconds, and forces server Close on failure. It then closes the broker/open lifetime with a separate bounded five-second drain. Both failures are reported without internal details. An incomplete Close result is cached; logical closure is not physical quiescence. These are separate sequential budgets, not one five-second limit or a hard ten-second guarantee. Cleanup failure does not roll back a persisted receipt or an accepted provider effect. Current durable pending-receipt recovery never needs a broker open. This contract grants no live issuance or deletion permission.

## Go client

The public `client`, `controlplane`, and `runtimeadmin` packages expose strict plan, receipt, lease, completion, and content-free runtime-status types. The client supports runtime inspection, submission, observation, cancellation, notification wait and acknowledgement, task claim, renewal, completion, and finalization. It bounds responses to 1 MiB, requires JSON media types, rejects unknown response fields, applies a request timeout, and disables redirects.

## Metadata storage selection

The daemon defaults to private local file journals. `--metadata-store postgres` selects the PostgreSQL run journal, protected diagnostic metadata, protected webhook metadata, and artifact index. It still uses the private local artifact directory, so this combination is a single-node durability profile rather than an HA profile. Set `OPEN_TRESTLE_POSTGRES_URL` to the application-role data source and pass the retained runtime-role identity as `--postgres-database-authority-identity`. Before serving, the daemon verifies both authority relations resolve to the active schema, verifies every embedded migration checksum, derives the connected database/schema/role/namespace identity in the same repeatable-read snapshot, and requires an exact match.

Schema changes are not applied through the application role by default. To run them explicitly at startup, add `--apply-migrations` and set `OPEN_TRESTLE_POSTGRES_MIGRATION_URL` for the separate migration role. Supplying an unused database URL, a migration URL without the flag, or the flag without a migration URL is rejected. The application role must be non-superuser, must not have `BYPASSRLS`, and needs no schema-creation authority.

`--artifact-store s3` enables the shared envelope-storage profile and requires `--metadata-store postgres`. It also requires `--s3-endpoint`, `--s3-region`, `--s3-bucket`, `--kms-region`, and `--kms-key-arn`. S3 signing uses `OPEN_TRESTLE_S3_ACCESS_KEY_ID`, `OPEN_TRESTLE_S3_SECRET_ACCESS_KEY`, and optional `OPEN_TRESTLE_S3_SESSION_TOKEN`. KMS uses the separate `OPEN_TRESTLE_AWS_ACCESS_KEY_ID`, `OPEN_TRESTLE_AWS_SECRET_ACCESS_KEY`, and optional `OPEN_TRESTLE_AWS_SESSION_TOKEN`. A secure `--kms-endpoint` is optional. The daemon builds one exact tenant-to-key registry, uses the bounded version-required S3 backend, and records artifact metadata through `IndexedArtifactStore`. Unused or incomplete remote-storage configuration is rejected.

Separate explicit S3 and KMS credentials sign their respective requests, and the daemon rejects an identical access-key ID in both roles. Each production principal must be scoped only to the configured bucket prefix or tenant KMS key. This daemon entry point accepts explicit environment credentials; deployments that require workload identity must provide a separately reviewed credential adapter rather than silently reusing these flags. Both remote-storage clients disable environment proxies, reject redirects, bound response headers, and close idle connections during shutdown. KMS bodies are capped at 1 MiB; S3 object reads retain the adapter's 32 MiB bound. HTTPS requires TLS 1.2 or newer, with plain HTTP accepted only for an IP-literal loopback test endpoint. The daemon will not silently treat a local wrapping key as production envelope protection.

`--artifact-erasure-mode` selects the runtime erasure wiring for the artifact store. It accepts `legacy` and `budgeted`; `legacy` is the default. Existing local artifact storage and legacy S3 envelope storage keep their current defaults and startup behavior. `--erasure-policy` and `--s3-erasure-trusted-ca` are accepted only with `--artifact-erasure-mode budgeted`.

Budgeted erasure is valid only with PostgreSQL metadata and S3 artifacts. It requires `--metadata-store postgres`, `--artifact-store s3`, `OPEN_TRESTLE_POSTGRES_URL`, the exact `--postgres-database-authority-identity`, the existing S3 and KMS flags, separate existing S3 and KMS credential environments, `--erasure-policy`, and `--s3-erasure-trusted-ca`. It rejects `--apply-migrations` and any `OPEN_TRESTLE_POSTGRES_MIGRATION_URL`; an authorized migration administrator must manage schema changes separately before this daemon starts.

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

The protected erasure policy must be current at the daemon-owned startup sample. It must bind the configured PostgreSQL database authority, the S3 backend configuration identity, the configured S3 prefix, and the expected storage namespace. The S3 erasure CA is an explicit protected trust file: an absolute clean path to a trusted-owner regular file, read twice for stability, non-empty, and at most 256 KiB. The budgeted erasure backend uses HTTPS with those explicit roots only. It does not use ambient S3 trust roots, injected transports, hidden credentials, or workload identity through these flags.

Budgeted startup constructs local S3 erasure and KMS client state, loads policy and CA files, and verifies PostgreSQL authority and the budgeted erasure index. It makes zero S3 or KMS requests before serving. Startup does not remove the checks performed by later store operations. Startup does not prove live S3/KMS health, bucket versioning, physical erasure, erasure authorization, backup recovery, or future availability.

PostgreSQL also stores content-free task notifications. A transaction trigger emits an empty `NOTIFY` payload after run-event and queue inserts. Long-poll API requests and the notification supervisor use `LISTEN` as a wake-up signal. The durable queue and canonical journal remain authoritative when a notification is duplicated or missed. The daemon exposes content-free liveness and supervisor-backed readiness probes. Leader-independent webhook supervision and tested database failover evidence are still required before an HA claim.

## GitHub run opening

GitHub ingress durably acknowledges deliveries without requiring automatic work creation. Add `--github-open-runs`, `--github-repository-full-name`, `--github-review-policy-identity`, `--github-review-mode`, `--github-publisher-id`, and one `--github-handler KIND=IDENTITY` for each required task kind to enable the durable run supervisor. Advisory and local plans require handlers from `acquire_source` through `evaluate_publication`. Required plans also require `publish_result`. Missing, duplicate, unknown, or malformed bindings are rejected before the listener starts.

## Daemon-owned deterministic workers

Add `--github-local-deterministic-workers` to execute the built-in GitHub source acquisition, exact change model, deterministic evidence, and bounded memory retrieval handlers in the daemon process. The option requires `--github-open-runs`. Handler identities for those four task kinds are derived from the configured built-ins and merged into the planner; a conflicting explicit `--github-handler` is rejected. Context, model, readiness, and optional publication handlers remain separately configured authorities.

Without a broker descriptor, `OPEN_TRESTLE_GITHUB_API_TOKEN` retains the legacy source-acquisition configuration: an unset value selects anonymous acquisition; a set value must be HTTP-header-safe. This static token is not current setup-permission evidence. Supplying it while local deterministic workers are disabled is rejected rather than ignored.

Broker mode uses the protected `OPEN_TRESTLE_GITHUB_SOURCE_BROKER_CONFIG` descriptor and independent `--approve-github-source-broker-authority-identity` common approval. Mixed static credentials are rejected. Runtime source acquisition owns a separate runtime-purpose broker; setup-purpose grants and receipts cannot authorize it. The descriptor remains schema 1 with `single_host_exclusive` ownership and explicit token-creation/demand-renewal consent. It does not provide HA credential ownership, automatic restart recovery, or publication authority.

## Policy-bound model pipeline

Set both `--runtime-route-inventory PATH` and `--runtime-policy PATH` with `--github-local-deterministic-workers` to execute the complete advisory pipeline in `trestled`. The files must conform to the published runtime schemas. Each path must resolve directly to a regular file owned by the daemon user or root and not group- or world-writable. Every ancestor must have trusted ownership and prevent replacement by another local principal; writable ancestors are allowed only with sticky-directory protection for a trusted-owned child. Symlinks, foreign-owned files, unsafe ancestry, and replacement during open are rejected. Runtime configuration fails closed on platforms without implemented ownership checks. These checks establish local file authority, not a separate setup approval of the runtime-policy digest. The runtime policy must name the same review-policy identity supplied to GitHub planning and must bind the exact decoded inventory identity. Partial configuration, cross-wired identities, required publication mode without the separate publication authority described below, or conflicting explicit handler identities are rejected.

At startup, the daemon constructs one exact pipeline catalog containing source acquisition, change construction, deterministic evidence, bounded memory retrieval, context assembly, candidate generation, independent verification, and publication readiness. The same inventory snapshot drives generation and verification policy. OpenAI credentials are referenced by environment variable name in policy but are read only when an authorized provider request dispatches. Missing or invalid request-time credentials produce a closed provider failure without changing catalog identity or exposing the value.

Required-mode external publication is intentionally unavailable through these two files alone. It needs a separately configured effect authorizer, publisher catalog, and current-head resolver. This prevents model-routing configuration from implicitly granting repository write authority.

## Required-mode GitHub publication

Required-mode daemon publication needs all of the following in addition to the policy-bound model pipeline:

- PostgreSQL metadata storage, which supplies the durable operation-key publication fence;
- `--postgres-database-authority-identity`, the exact runtime-role database identity reported by `trestle admin postgres identity`;
- `--postgres-authority-identity`, a stable non-secret digest verified against that database's generated fence namespace;
- `--github-enable-publication`;
- `--github-publication-policy-identity` and `--github-publication-principal-identity` as nonzero canonical digests;
- `--github-publication-authorization-ttl` between one minute and 24 hours; and
- `OPEN_TRESTLE_GITHUB_PUBLICATION_TOKEN` available when a publication request dispatches.

The enable flag is an explicit repository-wide policy grant for the configured tenant and repository. At task execution, the authorizer creates a short-lived, exact review-scope `publication` grant. It cannot authorize another tenant, repository, capability, readiness plan, or target. The publication handler still requires protected lineage, a fresh-head match, an exclusive operation claim, and exact publisher/resolver catalogs before dispatch.

The publication token is separate from webhook, source-read, API, database, object-storage, KMS, and model-provider credentials. Its presence and value are not read at startup. It is read only after the scope and immutable repository target match. Supplying any part of the publication configuration without the explicit enable flag is rejected. Local metadata mode rejects required publication because it does not yet supply the durable cross-process operation fence. An unbound or unverified PostgreSQL store also exposes no publication-attempt-guard identity. Initialize a new authority row only with `trestle admin postgres initialize`. Daemon startup never initializes publication authority because startup output is not a suitable recovery-receipt channel. Changing the PostgreSQL authority digest, database name, active schema, or generated namespace UUID changes the GitHub publisher and publication-handler identities, so a restored or replaced database cannot silently stand in for the original fence namespace.


## Local deterministic admission on the runs endpoint

When `trestled` is explicitly configured with `--setup-state`, `--expected-setup-root-identity`, and all three `--local-git-repository-*` labels plus `--local-git-objects-root`, the existing `POST /api/v1/runs` also accepts `open-trestle/local-deterministic-review-intent` version 1. The intent has no filesystem path, source content, provider, credential, egress, or publication field. The daemon validates scope before it persists the two root input artifacts and opens the four-task plan. An exact retry resumes the same plan; another intent at the same scope conflicts.

This mode requires local metadata and artifacts, one authorized logical repository, a numeric loopback listener, no TLS flags, no GitHub runtime, and no model route configuration. The startup process opens and retains its configured loose-object root. A source-root identity is bound into the source inputs and handler identity. The HTTP request cannot select or replace that root.

The setup plan is an initialized `local_single_node` scope and denied-effect posture fence only. Its root identity, profile, tenant, repository, local storage posture, denied egress, disabled publication, and disabled dynamic validation must match. This deterministic path performs no setup, inference, provider, egress, or publication effect, so it does not consume or imply `Plan.Ready()`. Policy, local-inference, dry-run, backup, observer, and other pending setup gates remain pending. This narrow evaluation admission must not be described as setup readiness or supported deployment authority.

A successful local run can be read through the existing run, plan, diagnostics, runtime, TUI, and embedded-console paths. Deterministic-only diagnostic set version 6 carries observations rather than verified findings. Full-review version 7 retains observations and independently verified findings as separate sections. `runs status --format json|sarif` reads that same stored set. Active run receipts report task status; their unchanged wire does not include coverage counts. The scoped read-only progress endpoint supplies separately bound evidence counts without creating provisional diagnostics.
