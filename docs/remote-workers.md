# Scoped remote workers

The `worker` package executes approved review task handlers through the authenticated daemon API. A runner is fixed to one exact tenant, repository, and review run. It retrieves the immutable run plan and public receipt, verifies their plan, scope, task, handler, and kind identities, and considers only tasks implemented by its exact immutable handler catalog.

## Control authority

The worker control interface contains only:

- read the public run receipt;
- read the immutable run plan;
- claim one exact task and handler identity;
- renew that live lease; and
- submit one typed completion.

The plan endpoint is `GET /api/v1/tenants/{tenant}/repositories/{repository}/runs/{run}/plan`. It requires exact scope authorization plus either `run:read` or `task:claim`. The endpoint returns canonical `ReviewRunPlan` JSON in the versioned API envelope. It exposes no lease secret, source content, provider credential, or artifact payload.

The runner does not cancel or finalize a run, alter policy, choose an unregistered handler, invoke publication authority, or enumerate another run. The daemon finalizes settled runs from replayed task state; a worker cannot choose the terminal output or failure. Multiple worker processes can compete safely because the daemon makes the claim and stale-worker fencing decision.

## Lease execution

A runner offers available, leased, and retryable failed work to the claim endpoint. The server alone decides whether retry time or lease expiry makes it claimable. A conflict is treated as another worker retaining authority. This keeps the server authoritative when clocks differ. `NewTaskExecutionRequestWithDependencies` binds the exact plan, task, handler, static input identity, successful or terminal-optional dependency outputs, and returned lease before the handler starts. The worker snapshots dependency outputs from the authenticated run receipt before claiming. Successful outputs are immutable, so the claim cannot change them.

Execution uses a bounded context. While the handler runs, the worker renews the same attempt at a configured interval. Every renewed lease retains the plan, task, handler, worker, and attempt identities. Its recovery horizon is the renewal time plus the immutable lease duration, not an accumulation of full durations on every heartbeat. Repeating an already-applied renewal returns the current lease without adding a journal event. Existing leases are not shortened; drain or cancel overextended legacy leases when upgrading from earlier renewal behavior. The newest lease is used for completion. Renewal leaves a conservative journal reserve for every possible remaining task transition and the run terminal event. If that reserve would be consumed, the API returns `409 lease_renewal_limit`; the worker cancels the current handler and records a `resource_limit` completion while its existing lease is valid. Cancellation and ordinary completion do not consume renewal authority and retain their reserved journal capacity. A renewal failure stops completion and leaves the durable lease to expire for another worker. An approved handler panic is converted to the closed `internal` failure class without retaining panic text.

Approved handlers must stop when their context is canceled. Go cannot forcibly terminate an in-process handler that ignores cancellation. Handlers requiring a hard resource boundary belong in the governed isolated-runner process, not in the trusted worker process.

## Artifact exchange

The worker API deliberately has no general artifact download or upload endpoint. A deployed handler receives the immutable task recipe identity and exact dependency outputs through `TaskExecutionRequest`. A root task reads its static input artifact. A downstream task reads only the artifact identities produced by its declared prerequisites. Shared workers should use the same PostgreSQL index, versioned S3 backend, and tenant KMS boundary as the daemon. `artifact.ValidatedTaskHandler` resolves the static input for a root task or every available dependency output for a downstream task. It ensures the successful output exists in the same scope and cites each resolved input artifact in provenance before completion crosses the lease boundary.

This keeps bulk source and model data away from the bearer-control API and prevents a task lease from becoming general object-store authority.

## Notification and polling bounds

`Runner.Run` performs one task at a time. A control implementation can also implement `NotificationControl`. In that mode, an idle runner long-polls for a content-free `TaskNotificationLease`, rereads the canonical plan and receipt, and still acquires the normal task lease before execution. It acknowledges the notification only after that authoritative check. A worker crash before acknowledgement leaves the hint eligible for bounded redelivery.

Notifications bind the exact tenant, repository, run, plan, task-state transition event, task, handler, next attempt, and availability time. They do not contain source, model output, credentials, or task lease authority. Delivery tokens are returned only to the authenticated worker; PostgreSQL stores their digests. Each notice has at most ten deliveries. Journal reconciliation creates notices idempotently and detects newly available retry work and expired task leases even if a wake-up was lost.

Notification waits range from 250 milliseconds through one minute in the runner and up to ten seconds per HTTP request. Notification delivery leases range from the execution timeout through 24 hours. Poll intervals remain bounded from 250 milliseconds through one minute as a fallback. Renewal intervals range from 10 milliseconds through one minute and must be shorter than the execution timeout. Execution timeouts range from one second through 24 hours. A runner exits when the run is terminal or all tasks are settled; it does not infer final review disposition.

## Daemon-owned execution

`worker.RepositorySupervisor` executes the same immutable handler catalog inside a trusted single-node daemon or embedding process. It discovers plans only inside an exact tenant and an allowlisted set of repositories. Discovery reads one bounded page per repository per pass and rotates a durable in-process cursor, so a large history cannot create an unbounded scan.

Each discovered run uses `LocalControl`, which delegates claims, lease renewal, completion, and replay to `controlplane.Coordinator`. It does not bypass task leases or construct execution requests itself. The normal `Runner` still verifies the plan, receipt, handler identity, dependency outputs, and lease authority. The supervisor runs at most one task at a time per discovered run and stops on control-plane corruption or an untyped runtime error.

Embedding code constructs handlers from approved adapters and policy records, creates `controlplane.TaskHandlerCatalog`, and supplies that exact catalog to the supervisor. `trestled --github-local-deterministic-workers` uses this path for its built-in source, change, analysis, and memory handlers. Arbitrary shared-library plugins are not loaded.
