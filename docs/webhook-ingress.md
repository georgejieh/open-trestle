# Verified webhook ingress

Webhook input crosses a separate authentication boundary from the daemon API. A forge delivery is not a review request until its unchanged bytes pass the source-specific signature verifier, event and action filters, repository scope checks, durable deduplication, and deterministic run planning.

## GitHub boundary

The GitHub adapter implements the current GitHub guidance:

- It accepts only `X-Hub-Signature-256` using HMAC-SHA-256.
- It compares signatures in constant time.
- It verifies the unchanged bounded payload before inspecting event content.
- It uses `X-GitHub-Delivery` with tenant and repository scope as the deduplication key. GitHub redelivery keeps this identifier.
- It applies an exact configured event/action allowlist. Authenticated but unwanted events are acknowledged without storage so they do not create retry storms.
- It rejects duplicate critical JSON keys before pull-request planning.
- Its HTTP handler bounds payloads to 1 MiB and uses a bounded nonblocking concurrency gate.

GitHub requires a 2xx response within 10 seconds. The handler responds only after the verified delivery has reached its durable inbox file and directory synchronization boundary. It does not fetch source, invoke a model, or publish output on the request path.

Primary references:

- https://docs.github.com/en/webhooks/using-webhooks/best-practices-for-using-webhooks
- https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries

## Setup conformance

`trestle admin github webhook identity` derives the exact non-secret runtime verifier and setup conformance authority from the tenant, repository, key ID, and fixed handler contract. `trestle setup check webhook` is available only to controlled-hybrid and Kubernetes HA plans after `integration_permissions_validated` has a passing receipt. It reads `OPEN_TRESTLE_GITHUB_WEBHOOK_SECRET` only after plan, dependency, actor, scope, and authority checks. The runtime secret must be a canonical 64-character lowercase hexadecimal encoding of 32 CSPRNG bytes. Structural validation rejects malformed, low-diversity, and repeated values but does not claim to prove entropy provenance.

The check runs five direct in-process requests against the production handler without a socket: an invalid signature, one accepted public fixture, its exact duplicate, a validly signed conflicting body with the same delivery ID, and a validly signed ignored action. A pass requires status and response-header parity, exactly one crash-safe `FileStore` record, stable duplicate identity, conflict preservation, ignored-action non-persistence, clearing of owned verifier and executor byte slices, and bounded nonrecursive deletion of the disposable private directory. Unexpected entries or replacement of that directory fail without recursive deletion. The check does not claim GitHub reachability or validate the configured PostgreSQL and encrypted artifact stores; those are separate setup authorities.

## Immutable delivery

A `VerifiedDelivery` binds:

- tenant and repository scope;
- source protocol and forge delivery identifier;
- event and action;
- exact verifier configuration identity;
- SHA-256 digest of the unchanged body; and
- receipt time.

The delivery identity includes the body digest and local receipt time. The deduplication key intentionally includes neither. Redelivery equivalence binds the same tenant and repository scope, source, delivery identifier, event, action, verifier identity, and body digest, but not a later local receipt time. Reuse of one scoped delivery identifier with different content or verifier authority is a hard conflict rather than a second event. Payload-bearing values redact their formatting.

## Durable inbox

The local `FileStore` provides one exclusive writer, private permissions, bounded canonical records, atomic rename, file synchronization, directory synchronization, cursor listing, restart recovery, and corruption detection. Equivalent redelivery returns the original acceptance receipt and preserves the first stored delivery identity, receipt time, and canonical bytes. The GitHub HTTP handler returns 202 for first acceptance and 200 with the same acceptance identity and `duplicate: true` for equivalent redelivery. The receipt is created only after verifier authority is matched to the exact tenant, repository, and source.

A payload is retained because asynchronous processing must survive a crash. Operators must place the inbox on protected storage and apply a retention policy after run admission evidence is retained. The inbox never stores webhook secrets or signature headers.

## Replay-safe run admission

The pull-request planner creates one deterministic review-run ID from the scoped delivery key. The review plan request identity must equal the verified delivery identity. Its tenant and repository must equal the inbox scope. The executable planner creates separate `source-base` and `source-head` root tasks. Their canonical protected input artifacts bind the GitHub repository identity, full Git object ID, built-in source adapter identity, delivery identity, classification, protection mode, and retention time. The `change` task depends on both successful source snapshots. Later task recipes bind the payload digest, pull-request number, exact base and head object IDs, task kind, and dependency task identities.

The prepared processor writes every exact root input artifact before opening the run. A crash after the immutable write but before journal open is safe: durable delivery reconciliation recreates the same artifact and plan identities. Extra, missing, expired, cross-scope, non-host, or non-root inputs are rejected.

Context assembly, candidate generation, independent verification, and publication each have one orchestration attempt. Source acquisition, change construction, deterministic analysis, memory retrieval, and readiness evaluation retain three bounded attempts. The version-4 pull-request planner identity binds this behavior; the prepared planner also binds that base identity. Stored plans retain their original identities and attempt limits. A planner upgrade does not rewrite journals or repair an incompatible stored plan, and redelivery is not a migration mechanism.

Processing does not need a second mutable delivery lease. Repeating plan creation after a crash produces the same plan, while the run journal makes open and advancement idempotent. Concurrent work is serialized later by the existing task leases. This keeps ingestion replayable and places side-effect fencing at the actual effect boundary. Publication remains a one-attempt orchestration task whose publisher uses the separately authorized stable operation key and bounded publication retry contract.

## PostgreSQL metadata profile

The PostgreSQL webhook store never places a delivery body in a database row. It encodes the verified delivery and acceptance receipt into a protected `webhook_delivery` artifact under the delivery's deterministic review-run scope. PostgreSQL retains only scoped identities and retention times. Production use requires an envelope-encrypted shared artifact store; a process-private file store is suitable only for one local daemon. A failed database insert can leave an unreachable encrypted artifact, which remains governed by its immutable expiry and retention sweep.

## Durable run supervision

`webhook.Supervisor` converts durable inbox records into idempotent review runs through the repository's exact planner and the shared coordinator. Startup performs a bounded reconciliation of the durable inbox. After acceptance, the HTTP handler sends a content-free, non-blocking delivery notice. If the bounded notice queue is full, it records an overflow wake-up and the supervisor reconciles the durable store instead of dropping authority or accepting an unbounded in-memory queue.

Processing retries are bounded with capped delay. Exhaustion stops the supervisor so the daemon can shut down and rely on its service manager to restart from durable state. Reprocessing is safe: the deterministic run scope, plan identity, coordinator open, and task availability transitions are idempotent. A matching existing run resumes before prepared inputs are touched. If a valid accepted delivery was never opened before every exact prepared root input expired, the processor returns the typed `ErrPreparedInputsExpired` outcome. Supervision treats only that fully validated outcome as a terminal skip, so a stale inbox record cannot poison readiness. All root identities, scope, media type, origin, creation time, provenance, uniqueness, and coverage are checked before expiry can cause a skip. No webhook payload enters the notice queue. PostgreSQL insertion serializes each repository and source at a 10,000-delivery bound, which matches the supervisor reconciliation limit.

The built-in GitHub planner currently accepts same-repository pull requests only. The top-level repository and both `pull_request.base.repo.full_name` and `pull_request.head.repo.full_name` must match the configured repository. Fork pull requests are rejected instead of assigning their head commit to false repository lineage.

`trestled --github-open-runs` enables this path only when an exact lowercase GitHub repository name, review policy identity, review mode, and every required task-handler identity are supplied. Ingress can remain enabled without automatic run opening. This separation permits an operator to validate signatures and durable intake before enabling work creation. The supervisor opens work; it does not claim tasks, invoke models, read source, or publish results.

Required-mode GitHub planning also prepares an exact protected publication input for the downstream publication task. Prepared processing admits task inputs for downstream tasks only when their artifact identity is the exact immutable input identity in the plan; complete root-input coverage remains mandatory.

## Retained delivery history

For PostgreSQL-backed intake, expired delivery bodies are excluded from reconciliation and active-capacity accounting before body retrieval. Their immutable metadata remains for deduplication. A signed redelivery of a retired ID returns `410 delivery_expired`, without an acceptance receipt or a new processing wake. Stale queued hints for explicitly expired deliveries are ignored; other store failures still block and surface through the normal retry path. This is a retention disposition, not physical-erasure evidence.
