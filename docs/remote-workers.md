# Scoped remote workers

A remote worker is a process that runs review tasks on behalf of the daemon. The `worker` package runs approved review task handlers through the authenticated daemon API. This page is for contributors and operators who deploy workers.

A runner is fixed to one exact tenant, repository and review run. It retrieves the immutable run plan and the public receipt, and verifies the plan, scope, task, handler and kind identities in them. It considers only tasks that its exact, immutable handler catalog implements.

## Control authority

The worker control interface can do only these things:

- read the public run receipt;
- read the immutable run plan;
- claim one exact task and handler identity;
- renew that live lease;
- submit one typed completion.

The plan endpoint is `GET /api/v1/tenants/{tenant}/repositories/{repository}/runs/{run}/plan`. It requires exact scope authorization plus either `run:read` or `task:claim`. It returns canonical `ReviewRunPlan` JSON in the versioned API envelope. It exposes no lease secret, source content, provider credential or artifact payload.

The runner does not cancel or finalize a run, change policy, choose a handler that is not registered, use publication authority or list another run. The daemon finalizes settled runs from the replayed task state, so a worker cannot choose the terminal output or failure. Several worker processes can compete safely, because the daemon makes the claim decision and the decision to fence off stale workers.

## Lease execution

A runner offers available, leased and retryable failed work to the claim endpoint. Only the server decides whether the retry time or a lease expiry makes a task claimable. A conflict means that another worker keeps authority. This keeps the server authoritative when clocks differ.

Before the handler starts, `NewTaskExecutionRequestWithDependencies` binds the exact plan, task, handler, static input identity and returned lease. It also binds the outputs of the dependencies, whether they succeeded or are terminal and optional. The worker copies the dependency outputs from the authenticated run receipt before it claims. Successful outputs are immutable, so the claim cannot change them.

Execution uses a bounded context. While the handler runs, the worker renews the same attempt at a configured interval. Every renewed lease keeps the plan, task, handler, worker and attempt identities. Its recovery horizon is the renewal time plus the immutable lease duration. It is not an accumulation of full durations on every heartbeat. Repeating a renewal that was already applied returns the current lease without adding a journal event. Existing leases are not shortened, so when you upgrade from earlier renewal behavior, drain or cancel any overextended legacy leases. The newest lease is used for completion.

Renewal leaves a conservative journal reserve for every possible remaining task transition and for the run's terminal event. If a renewal would use up that reserve, the API returns `409 lease_renewal_limit`. The worker then cancels the current handler and records a `resource_limit` completion while its existing lease is valid. Cancellation and ordinary completion do not use up renewal authority and keep their reserved journal capacity. A renewal failure stops the completion and leaves the durable lease to expire for another worker. A panic in an approved handler is converted to the closed `internal` failure class without keeping the panic text.

Approved handlers must stop when their context is canceled. Go cannot forcibly end an in-process handler that ignores cancellation. A handler that needs a hard resource boundary belongs in the governed isolated-runner process, not in the trusted worker process.

## Artifact exchange

The worker API deliberately has no general endpoint to download or upload artifacts. A deployed handler receives the immutable task recipe identity and the exact dependency outputs through `TaskExecutionRequest`. A root task reads its static input artifact. A downstream task reads only the artifact identities that its declared prerequisites produced. Shared workers should use the same PostgreSQL index, versioned S3 backend and tenant KMS boundary as the daemon.

`artifactvalidation.ValidatedTaskHandler` resolves the static input for a root task, or every available dependency output for a downstream task. Before the completion crosses the lease boundary, it makes sure that the successful output exists in the same scope and that its provenance cites each resolved input artifact.

This keeps bulk source and model data away from the bearer-controlled API, and it prevents a task lease from becoming general authority over the object store.

## Notification and polling bounds

`Runner.Run` performs one task at a time. A control implementation can also implement `NotificationControl`. In that mode, an idle runner long-polls for a content-free `TaskNotificationLease`, rereads the canonical plan and receipt, and still acquires the normal task lease before it runs anything. It acknowledges the notification only after that authoritative check. If a worker crashes before it acknowledges, the hint stays eligible for bounded redelivery.

Notifications bind the exact tenant, repository, run, plan, task-state transition event, task, handler, next attempt and availability time. They do not contain source, model output, credentials or task lease authority. Delivery tokens go only to the authenticated worker, and PostgreSQL stores their digests. Each notice has at most ten deliveries. Journal reconciliation creates notices idempotently. It detects newly available retry work and expired task leases even if a wake-up was lost.

These timing ranges apply:

- Notification waits range from 250 milliseconds through one minute in the runner, and up to ten seconds per HTTP request.
- Notification delivery leases range from the execution timeout through 24 hours.
- Poll intervals remain bounded from 250 milliseconds through one minute, as a fallback.
- Renewal intervals range from 10 milliseconds through one minute and must be shorter than the execution timeout.
- Execution timeouts range from one second through 24 hours.

A runner exits when the run is terminal or all tasks are settled. It does not infer the final review disposition.

## Daemon-owned execution

`worker.RepositorySupervisor` runs the same immutable handler catalog inside a trusted single-node daemon or embedding process. It discovers plans only inside one exact tenant and an allowlisted set of repositories. Each pass reads one bounded page per repository and rotates a durable in-process cursor, so a large history cannot cause an unbounded scan.

Each discovered run uses `LocalControl`, which hands claims, lease renewal, completion and replay to `controlplane.Coordinator`. It does not bypass task leases or build execution requests itself. The normal `Runner` still verifies the plan, the receipt, the handler identity, the dependency outputs and the lease authority. The supervisor runs at most one task at a time for each discovered run. It stops on corruption of the control plane or on an untyped runtime error.

Embedding code builds handlers from approved adapters and policy records, creates a `controlplane.TaskHandlerCatalog` and gives that exact catalog to the supervisor. `trestled --github-local-deterministic-workers` uses this path for its built-in source, change, analysis and memory handlers. Arbitrary shared-library plugins are not loaded.
