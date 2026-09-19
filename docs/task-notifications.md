# Durable task notifications

Task notifications reduce idle worker polling without becoming a second source of scheduling authority. The review-run plan and hash-chained journal remain canonical. Every worker rereads the authenticated plan and receipt and acquires the normal task lease before a handler can run.

## Notification contract

`TaskNotification` is content-free. It binds:

- tenant, repository, and review-run scope
- immutable plan identity
- task-state transition revision and event identity
- task key, task identity, and exact handler identity
- next task attempt
- availability time

A notification can be stale, duplicated, delayed, or missed without granting execution. `TaskNotificationLease` protects delivery acknowledgement with a random bearer token. Persistent stores keep only its digest. The lease also binds worker identity, delivery number, issue time, and expiry. Formatting is redacted.

Canonical JSON encoders reject unknown fields, noncanonical bytes, invalid identities, excessive payloads, and cross-wired lease data. Delivery secrets are allowed only in authenticated request bodies and responses. They must not enter URLs, logs, journals, metrics, exports, or support bundles.

## Queue behavior

`TaskNotificationQueue` supports immutable enqueue, one scoped claim, and fenced acknowledgement. The in-memory implementation supports local foreground operation. The PostgreSQL implementation provides shared durable delivery.

Claims use exact scope. One notice can be delivered at most ten times. An active delivery cannot be replaced before expiry. A stale worker cannot acknowledge a newer delivery. Exhausting notification deliveries does not alter the run journal or make a task fail; journal reconciliation and bounded worker polling remain available for recovery.

## Journal reconciliation

`TaskNotificationScheduler` reconstructs each run from its immutable plan and complete journal, calls the coordinator's deterministic advance operation, and emits notices only for tasks that the replayed state says are available or have an expired task lease. Notice identities are deterministic for the state head, so concurrent schedulers enqueue the same value idempotently.

`TaskNotificationSupervisor` fixes one tenant and a bounded repository allowlist. It reconciles scheduling and deterministic terminal finalization for all plans before reporting readiness. It then responds to local wake-ups, queue wake-ups, and a bounded periodic fallback. Errors use bounded retries and fail closed after exhaustion. A restart repeats the same reconciliation from durable state.

## PostgreSQL wake-up

Migration `0005_task_notifications.sql` creates the tenant-scoped queue with forced row-level security. Claims use `FOR UPDATE SKIP LOCKED`. Committed run-event and queue inserts call `pg_notify` with a fixed channel and an empty payload. A pgx `LISTEN` connection wakes supervisors and long-poll requests without disclosing scope or content.

A signal can occur before a listener subscribes. This is safe: the long-poll endpoint claims once before waiting and once after timeout, while supervisors periodically rescan canonical plans and journals. The signal is only a latency optimization.

## Worker API

Authenticated workers use:

- `POST .../worker/notifications/claim`
- `POST .../worker/notifications/acknowledge`

A claim can wait for up to ten seconds and returns `204 No Content` when no scoped notice is available. The client exposes `ClaimTaskNotification` and `AcknowledgeTaskNotification`. `worker.Runner` uses them when its notification timing options are set, while retaining bounded polling as recovery.

## Published schemas

- `schemas/controlplane/task-notification-v1.schema.json`
- `schemas/controlplane/task-notification-lease-v1.schema.json`
- `schemas/controlplane/task-notification-claim-request-v1.schema.json`
