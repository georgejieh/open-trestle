# Scoped remote workers

A remote worker is a process that runs review tasks on behalf of the daemon. The `worker` package runs approved review task handlers through the authenticated daemon API. This page is for contributors and operators who deploy workers.

A runner is fixed to one tenant, repository and review run. It retrieves the run plan and the public receipt, and verifies the plan, scope, task, handler and kind identities in them. It considers only tasks that its handler catalog implements.

## Control authority

The worker control interface can:

- read the public run receipt;
- read the run plan;
- claim one task and handler identity;
- renew that lease;
- submit one completion.

The plan endpoint is `GET /api/v1/tenants/{tenant}/repositories/{repository}/runs/{run}/plan`. It requires scope authorization plus either `run:read` or `task:claim`. It returns canonical `ReviewRunPlan` JSON in the versioned API envelope. It returns no lease secret, source content, provider credential or artifact payload.

The runner does not cancel or finalize a run, change policy, use a handler that is not registered, publish or list another run. The daemon finalizes settled runs from the replayed task state, so a worker cannot choose the terminal output or failure. Several worker processes can compete safely, because the daemon decides each claim and fences off stale workers.

## Lease execution

A runner offers available, leased and retryable failed work to the claim endpoint. Only the server decides whether the retry time or a lease expiry makes a task claimable, so clock differences do not matter. A conflict means that another worker holds the task.

Before the handler starts, `NewTaskExecutionRequestWithDependencies` binds the plan, task, handler, static input identity and returned lease. It also binds the outputs of the dependencies, whether they succeeded or are terminal and optional. The worker copies the dependency outputs from the authenticated run receipt before it claims, and the claim cannot change them.

Execution has a timeout. While the handler runs, the worker renews the same attempt at a configured interval. Every renewed lease keeps the plan, task, handler, worker and attempt identities. Its recovery horizon is the renewal time plus the lease duration, not an accumulation of full durations on every heartbeat. Repeating a renewal that was already applied returns the current lease without adding a journal event. Existing leases are not shortened, so when you upgrade from earlier renewal behavior, drain or cancel any overextended legacy leases. The newest lease is used for completion.

Renewal leaves journal capacity in reserve for every remaining task transition and for the run's terminal event. If a renewal would use up that reserve, the API returns `409 lease_renewal_limit`. The worker then cancels the current handler and records a `resource_limit` completion while its existing lease is valid. Cancellation and ordinary completion keep their reserved journal capacity. A renewal failure stops the completion and leaves the durable lease to expire for another worker. A panic in an approved handler is converted to the `internal` failure class without keeping the panic text.

Approved handlers must stop when their context is canceled. Go cannot forcibly end an in-process handler that ignores cancellation. A handler that needs a hard resource limit belongs in the isolated-runner process, not in the worker process.

## Artifact exchange

The worker API has no endpoint to download or upload artifacts. A deployed handler receives the task recipe identity and the dependency outputs through `TaskExecutionRequest`. A root task reads its static input artifact. A downstream task reads the artifact identities that its declared prerequisites produced.

`artifactvalidation.ValidatedTaskHandler` resolves the static input for a root task, or every available dependency output for a downstream task. Before the completion crosses the lease boundary, it checks that the successful output exists in the same scope and that its provenance cites each resolved input artifact.

This keeps source and model data away from the worker API.

## Notification and polling bounds

`Runner.Run` performs one task at a time. A control implementation can also implement `NotificationControl`. In that mode, an idle runner long-polls for a content-free `TaskNotificationLease`, rereads the plan and receipt, and acquires the normal task lease before it runs anything. It acknowledges the notification only after that check. If a worker crashes before it acknowledges, the notice is delivered again.

Notifications bind the tenant, repository, run, plan, task-state transition event, task, handler, next attempt and availability time. They contain no source, model output, credentials or task lease. Delivery tokens go only to the authenticated worker, and only their digests are stored. Each notice has at most ten deliveries. Journal reconciliation creates notices idempotently. It detects newly available retry work and expired task leases even if a wake-up was lost.

These timing ranges apply:

- Notification waits range from 250 milliseconds through one minute in the runner, and up to ten seconds per HTTP request.
- Notification delivery leases range from the execution timeout through 24 hours.
- Poll intervals range from 250 milliseconds through one minute, as a fallback.
- Renewal intervals range from 10 milliseconds through one minute and must be shorter than the execution timeout.
- Execution timeouts range from one second through 24 hours.

A runner exits when the run is terminal or all tasks are settled.

## Daemon-owned execution

`worker.RepositorySupervisor` runs the same handler catalog inside a single-node daemon or embedding process. It discovers plans inside one tenant and an allowlisted set of repositories. Each pass reads one page per repository and rotates an in-process cursor, so a large history is not scanned at once.

Each discovered run uses `LocalControl`, which hands claims, lease renewal, completion and replay to `controlplane.Coordinator`. It does not bypass task leases or build execution requests itself. The normal `Runner` still verifies the plan, the receipt, the handler identity, the dependency outputs and the lease. The supervisor runs at most one task at a time for each discovered run. It stops on corruption of the control plane or on an untyped runtime error.

Embedding code builds handlers from approved adapters and policy records, creates a `controlplane.TaskHandlerCatalog` and gives that catalog to the supervisor. `trestled --github-local-deterministic-workers` uses this path for its built-in source, change, analysis and memory handlers. Arbitrary shared-library plugins are not loaded.
