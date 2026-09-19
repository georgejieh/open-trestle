# Review run runtime

Open Trestle uses one review-run contract for local commands, CI, editors, APIs, and source-control integrations. A transport creates an immutable `ReviewRunPlan`. Workers interact with the plan through append-only events rather than private conversational state.

## Task graph

A plan binds the tenant and repository scope, canonical review request, policy, maximum effect posture, and a bounded acyclic task graph. Each task binds:

- a stable key and closed operation kind;
- an immutable task recipe or root input identity;
- canonical dependencies whose successful outputs are snapshotted into each leased execution request;
- whether completion is required;
- a maximum attempt count;
- a retry delay;
- a worker lease duration; and
- the exact approved handler identity.

Safety dependencies are structural. Source acquisition precedes change construction. Context assembly precedes candidate generation. Candidate generation precedes independent verification. Verification precedes publication evaluation. Publication depends on publication evaluation and is forbidden in local-only plans. Publication, candidate-generation, and independent-verification tasks have one orchestration attempt. Model retries require a new policy-authorized route attempt and cost reservation; generic task retry cannot create either. Its publisher handler uses the separately audited, idempotent publication-attempt and retry contracts so generic worker recovery cannot duplicate an external effect.

## Journal and recovery

Every state change is a canonical, content-addressed event in a hash chain. State is reconstructed by replaying the immutable plan and its complete event stream. Replay rejects gaps, forks, time reversal, cross-scope records, dependency bypass, stale lease results, attempts beyond the plan limit, and events after a terminal disposition.

The local file journal stores canonical plan JSON and event JSON Lines with private permissions. Plans can be listed through exact tenant and repository filters with bounded cursor pagination, allowing a restarted supervisor to discover unfinished work without crossing repository scope. It uses an exclusive writer lease, bounded files, atomic replacement, file synchronization, and directory synchronization. An unclean stop leaves the writer lease in place for explicit operator recovery. PostgreSQL and queue-backed implementations must preserve the same compare-and-append behavior.

## Worker leases

A worker claim returns a short-lived capability containing a random lease secret. Only the secret digest enters the journal. Formatting always redacts the capability. A claim requires the exact handler identity bound into the task. Handler dispatch rechecks the current reconstructed state, task kind, lease digest, attempt, and expiry before releasing work. A result must match the current task, attempt, lease digest, and expiry. Once a lease expires, another worker can acquire the next bounded attempt. Results from the prior worker then fail closed.

Retry timing comes from the immutable task definition. Only closed retryable failure classes can become available again. Permanent failures propagate through dependent tasks without executing them. Cancellation is terminal and invalidates outstanding work.

## Current boundary

The package provides the task graph, canonical encodings, memory and durable local journals, replay, optimistic coordination, claims, renewals, retries, dependency propagation, completion, cancellation, restart recovery, content-free task notifications, and automatic terminal finalization. The standalone daemon and PostgreSQL runtime adapter are available. An operational lock-recovery command is not included. See [PostgreSQL canonical ledgers](postgresql-storage.md).

## Transport boundary

The public `controlplane` package owns these runtime contracts. The authenticated HTTP adapter, Go client, CLI, and daemon use the same canonical plan, lease, completion, and receipt encodings. See [Daemon API and client](daemon-api.md).
