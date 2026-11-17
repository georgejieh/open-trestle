# Durable task notifications

A task notification is a small message that tells a worker a task may be ready. Notifications reduce idle polling by workers. They do not schedule anything: the review-run plan and its hash-chained journal stay canonical. Before a handler runs, every worker rereads the authenticated plan and receipt and acquires the normal task lease. This page is for contributors and operators.

## Notification contract

`TaskNotification` is content-free. It records the following:

- the tenant, repository and review-run scope;
- the plan identity;
- the revision of the task-state transition and its event identity;
- the task key, the task identity and the handler identity;
- the next task attempt;
- the time at which the task becomes available.

A notification can be stale, duplicated, delayed or missed without affecting execution. `TaskNotificationLease` protects the acknowledgement of a delivery with a random bearer token. Persistent stores keep only the digest of the token. The lease also records the worker identity, the delivery number, the issue time and the expiry. Formatting is redacted.

The canonical JSON encoders reject unknown fields, noncanonical bytes, invalid identities, oversized payloads and mismatched lease data. Delivery secrets belong only in authenticated request bodies and responses. They must not enter URLs, logs, journals, metrics, exports or support bundles.

## Queue behavior

`TaskNotificationQueue` supports an enqueue, one scoped claim and a fenced acknowledgement. A fenced acknowledgement is one that only the current holder of the delivery can make. The in-memory implementation supports local foreground operation, and the PostgreSQL implementation provides shared durable delivery.

Claims are scoped. One notice can be delivered at most ten times. An active delivery cannot be replaced before it expires. A stale worker cannot acknowledge a newer delivery. Using up all deliveries of a notification does not change the run journal or make a task fail. Journal reconciliation and worker polling remain available for recovery.

## Journal reconciliation

`TaskNotificationScheduler` rebuilds each run from its plan and journal and calls the coordinator's advance operation. It sends notices only for tasks that the replayed state shows as available or as having an expired task lease. Notice identities are derived from the state head, so concurrent schedulers enqueue the same value idempotently.

`TaskNotificationSupervisor` handles one tenant and an allowlist of repositories. Before it reports readiness, it reconciles scheduling and terminal finalization for all plans. It then responds to local wake-ups, queue wake-ups and a periodic fallback. Errors are retried a limited number of times and then stop the supervisor. A restart repeats the same reconciliation from durable state.

## PostgreSQL wake-up

Migration `0005_task_notifications.sql` creates the tenant-scoped queue with forced row-level security. Claims use `FOR UPDATE SKIP LOCKED`. Committed run-event and queue inserts call `pg_notify` with a fixed channel and an empty payload. A pgx `LISTEN` connection wakes supervisors and long-poll requests without disclosing scope or content.

A signal can occur before a listener subscribes. The long-poll endpoint claims once before it waits and once after the timeout, and supervisors periodically rescan the plans and journals, so the signal only reduces latency.

## Worker API

Authenticated workers use two endpoints:

- `POST .../worker/notifications/claim`
- `POST .../worker/notifications/acknowledge`

A claim can wait for up to ten seconds. It returns `204 No Content` when no notice is available in the worker's scope. The client exposes `ClaimTaskNotification` and `AcknowledgeTaskNotification`. `worker.Runner` uses them when its notification timing options are set, and it keeps polling as a recovery path.

## Published schemas

- `schemas/controlplane/task-notification-v1.schema.json`
- `schemas/controlplane/task-notification-lease-v1.schema.json`
- `schemas/controlplane/task-notification-claim-request-v1.schema.json`
