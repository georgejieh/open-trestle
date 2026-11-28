# Verified webhook ingress

Webhook ingress turns a GitHub pull-request event into a review run in the daemon. A webhook delivery has its own authentication, separate from the daemon API, and a delivery from a forge becomes a review request only after its bytes pass all of these steps:

- The signature check for that source.
- The event and action filters.
- The repository scope checks.
- Durable deduplication.
- Run planning.

## GitHub boundary

The GitHub adapter follows GitHub's webhook guidance:

- It accepts only `X-Hub-Signature-256` using HMAC-SHA-256.
- It compares signatures in constant time.
- It verifies the size-limited payload before it looks at the event content.
- It uses `X-GitHub-Delivery`, together with the tenant and repository scope, as the deduplication key. GitHub keeps this identifier when it redelivers.
- It applies a configured allowlist of events and actions. An authenticated but unwanted event is acknowledged without being stored, so it does not cause a storm of retries.
- It rejects duplicate critical JSON keys before it plans a pull-request review.
- Its HTTP handler limits payloads to 1 MiB and uses a nonblocking concurrency gate.

GitHub requires a 2xx response within 10 seconds. The handler responds only after the verified delivery has reached its durable inbox file and the directory has been synchronized, and it does not fetch source or call a model while it handles the request.

Primary references:

- https://docs.github.com/en/webhooks/using-webhooks/best-practices-for-using-webhooks
- https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries

## Webhook secret

The runtime secret `OPEN_TRESTLE_GITHUB_WEBHOOK_SECRET` must be a canonical, 64-character, lowercase hexadecimal encoding of 32 bytes from a cryptographically secure random generator. Validation rejects malformed, low-diversity and repeated values.

## Verified deliveries

A `VerifiedDelivery` ties together these values:

- The tenant and repository scope.
- The source protocol and the forge's delivery identifier.
- The event and the action.
- The identity of the verifier configuration.
- The SHA-256 digest of the body.
- The time Open Trestle received it.

The delivery identity includes the body digest and the local receipt time, but the deduplication key includes neither. Two deliveries count as the same redelivery when they have the same tenant and repository scope, source, delivery identifier, event, action, verifier identity and body digest, whatever their local receipt times. If a scoped delivery identifier is reused with different content or a different verifier authority, that is a conflict, not a second event. Values that carry payload data redact themselves when formatted.

### Replay protection

The forge's signature covers the body but not the `X-GitHub-Delivery` header, so someone who holds one validly signed body could resend it under a new delivery ID and start a new review run. To prevent this, every store also keeps a replay key made from the scope, source, event type, action and body digest. A second delivery with the same replay key but a different delivery ID is refused with `webhook.ErrDeliveryReplayed`.

For such a delivery, the GitHub handler returns `409 delivery_replayed` with an empty body, creates no delivery or run, and sends no wake-up to processing. Redelivery under the same ID is unchanged and still returns `200` with `duplicate: true`. The delivery identity and the deduplication key are also unchanged.

The refusal outlasts retention, and each store keeps the replay key differently:

- The memory store holds the key for the life of the process.
- `FileStore` rebuilds the keys from its saved deliveries on the first write after it opens, and stops if it cannot read one.

## Durable inbox

The local `FileStore` is the durable inbox. It provides these properties:

- One exclusive writer.
- Private permissions.
- Canonical records of limited size.
- Atomic rename, file synchronization and directory synchronization.
- Cursor listing.
- Recovery after a restart.
- Detection of corruption.

Its root directory holds at most 10,000 files, not counting refusal and retry files; those 10,000 are the deliveries and the writer lock. Retry files have their own limit of 10,000, one per delivery. Refusal records also have their own limit of 10,000, one per delivery, whichever planner identity recorded it. Listing ignores both kinds of sidecar file, so the root holds at most three files per delivery however often the planner identity changes.

If the retry limit fills, a delivery whose retry state cannot be recorded is refused with `retry_capacity_exhausted`, and the other deliveries keep flowing. Only files that the store did not write can fill the retry limit or the refusal limit. A full refusal limit is a global failure, like any other inconsistent root.

An equivalent redelivery returns the original acceptance receipt and keeps the first stored delivery identity, receipt time and canonical bytes. The GitHub HTTP handler returns 202 for first acceptance, and 200 with the same acceptance identity and `duplicate: true` for an equivalent redelivery. Open Trestle creates the receipt only after the verifier identity matches the tenant, repository and source.

The file inbox does not expire deliveries. It keeps each accepted delivery's body and metadata under `webhook-inbox` in the state directory, so that asynchronous processing survives a crash, and uses them for deduplication and reconciliation. Place the inbox on protected storage and apply a retention policy, but only after the run has been admitted. The inbox does not store webhook secrets or signature headers.

## Run admission that is safe to replay

The pull-request planner creates one review-run ID from the scoped delivery key. The review plan request identity must equal the verified delivery identity, and its tenant and repository must equal the inbox scope.

The executable planner creates two separate root tasks, `source-base` and `source-head`, whose protected input artifacts record the following:

- The GitHub repository identity.
- The full Git object IDs.
- The identity of the built-in source adapter.
- The delivery identity.
- The classification.
- The protection mode.
- The retention time.

The `source-head` input (source input v1) names `pull_request.head.sha`. The `source-base` input (source input v3) names `pull_request.base.sha` as the requested base and `pull_request.head.sha` as the head, and it authorizes acquisition of their merge base, because GitHub presents a pull request as `merge-base...head` and `base.sha` is the tip of the base branch when the event fired. The source task resolves and records the merge base; see [source acquisition](runtime.md#merge-base-inputs).

Base and head must use one object format. If the base and head commits are equal, the planner still plans the run, and the run records `nothing_to_review` as the source task's reason. The `change` task depends on both source snapshots succeeding. The recipes of later tasks bind the payload digest, the pull-request number, the base and head object IDs, the task kind and the identities of the tasks they depend on.

### Planner versions

The prepared planner identity is `open-trestle/prepared-github-pull-request-planner` version 2, and Open Trestle no longer produces version 1 plans. A run opened under version 1 before an upgrade is resumed as that delivery's run and continues under its recorded version 1 plan, in which the `source-base` task names `pull_request.base.sha` directly. This happens only when the plan is the one that version 1 produces for the delivery with this daemon's task handlers. The planner rebuilds that plan (`SupersededPlanIdentities`), and the processor compares the plan identities.

Task handler identities are part of a plan, so a daemon cannot run the tasks of a run that was opened with a handler it does not run. If such a run otherwise has this planner's task graph, policy and mode for the delivery's request, it is refused as `run_opened_by_incompatible_release` and is not advanced. To open a new run, push a new commit or reopen the pull request. A redelivery with the same ID does not open one, because it duplicates the same delivery.

### Writing inputs and attempt limits

The prepared processor writes every root input artifact before it opens the run. After a crash between the write and the journal opening, delivery reconciliation recreates the same artifact and plan identities. The processor rejects inputs that are extra, missing, expired, from another scope, not from the host or not root inputs.

The attempt limits differ by stage:

- Context assembly, candidate generation and independent verification each get one orchestration attempt.
- Source acquisition, change construction, deterministic analysis, memory retrieval and readiness evaluation each get three attempts.

The version-4 pull-request planner identity binds this behavior, and the prepared planner also binds that base identity. Stored plans keep their original identities and attempt limits, and a planner upgrade does not rewrite journals or repair an incompatible stored plan.

Processing does not take a lease on a delivery. If plan creation is repeated after a crash, it produces the same plan, and the run journal makes opening and advancing the run idempotent. Task leases serialize concurrent work later.

## Durable run supervision

`webhook.Supervisor` turns durable inbox records into idempotent review runs, using the repository's planner and the shared coordinator. It reconciles the durable inbox at startup.

After the handler accepts a delivery, it sends a nonblocking delivery notice that has no content. If the notice queue is full, the handler records an overflow wake-up, and the supervisor reconciles the durable store. No webhook payload enters the notice queue.

### Refused deliveries

Planning does no I/O, so a planning error other than cancellation repeats on every attempt. The processor returns it as `webhook.ErrDeliveryRefused` with a reason that has no content:

- The planner's own named reason. The GitHub planner names `invalid_pull_request_payload`.
- `planning_refused` for any other planning error.
- `run_plan_not_bound` for a plan, or prepared inputs, outside the delivery's lineage.
- `run_plan_conflict` when the delivery's run scope already holds a plan that the planner did not produce for this delivery.
- `run_opened_by_incompatible_release` when that plan is one that an earlier release opened with task handlers this daemon does not run.

A run whose plan is exactly the plan that this planner produces for the delivery, or that an earlier version of it produces (`webhook.SupersedingPlanner`), is that delivery's run. Reprocessing resumes and advances it under its recorded plan and writes no new inputs.

Any other plan in the scope is refused with one of the last two reasons above, even if it names the delivery's request, and Open Trestle does not adopt or advance it. The daemon API also rejects caller-submitted run IDs that begin with `webhook-`.

The supervisor records the refusal once in the inbox and then skips the delivery. The record is one `open-trestle/webhook-delivery-refusal` v1 file per delivery, beside the delivery in the file inbox, and it names the planner identity that recorded it.

A refusal is terminal for its delivery and planner identity. The supervisor reads it before it processes a delivery, so a refused delivery is not processed again and its run is not opened later. Recording the same refusal again keeps the first record, and so does recording a different reason for the same delivery and planner, for example concurrently. The delivery stays refused under that record, the pass does not fail, and other deliveries are not blocked.

A refusal that a superseded planner identity left is kept until the current planner has its own outcome for the delivery. When the current planner admits the delivery, Open Trestle removes the old record. When the current planner refuses it, the new record replaces the old one.

### Failures and retries

For any other failure, the supervisor runs a probe. It reads the run journal, using a probe run scope that was never opened, and for prepared processing it also reads the artifact store, using an identity that names no artifact.

- If either does not answer, the failure is global. The pass fails and is retried with a capped delay. The failure does not count against a delivery, so an outage cannot cause deliveries to be refused.
- If both answer, the failure belongs to the delivery. That delivery backs off on its own capped exponential schedule, starting at the configured retry delay and doubling with each failure, and a timer wakes reconciliation when its retry is due. Every other delivery keeps flowing, and the pass does not fail.

A delivery that fails the configured maximum number of times in this way is recorded as refused with `retries_exhausted`, so it is visible and is not retried forever.

The retry state for each delivery (failure count and time of the next attempt) is stored durably beside the delivery in the inbox, in an `open-trestle/webhook-delivery-retry` v1 file. A restart therefore neither resets a delivery's failure count nor retries it before its recorded time.

A delivery has one retry state, which names the planner identity that recorded it. State that a superseded planner identity left does not hold the delivery back or count against it, and the current planner's own state replaces it once recorded. Open Trestle clears the state when the delivery is admitted or refused, including state that an interrupted pass left beside a refusal.

A failure to read or write the retry state is global, with one exception: a full retry limit in the file inbox refuses the delivery, as described above. Only global failures stop the supervisor, namely inbox store reads, refusal writes and the probe. They exhaust the supervisor's retries, so the daemon can shut down and rely on its service manager to restart it from durable state.

### Reprocessing and expired inputs

Reprocessing is safe because the run scope, the plan identity, the coordinator's open step and the task availability transitions are all idempotent. A matching run that already exists is resumed before prepared inputs are touched.

If every prepared root input of a valid accepted delivery expired before its run was opened, the processor returns `ErrPreparedInputsExpired`. Supervision treats only that outcome as a terminal skip, so a stale inbox record cannot prevent the supervisor from becoming ready. Before expiry can cause a skip, the processor checks every root identity and the scope, media type, origin, creation time, provenance, uniqueness and coverage.

## Which pull requests are planned

The built-in GitHub planner currently accepts only pull requests from the same repository. The top-level repository, `pull_request.base.repo.full_name` and `pull_request.head.repo.full_name` must all match the configured repository, so Open Trestle rejects fork pull requests.

`trestled --github-open-runs` turns on this path only together with a lowercase GitHub repository name and the other flags listed under [GitHub run opening](daemon-api.md#github-run-opening).

Ingress can stay enabled without opening runs automatically, so you can validate signatures and durable intake before you enable work creation. The supervisor opens runs but does not claim tasks, call models or read source.
