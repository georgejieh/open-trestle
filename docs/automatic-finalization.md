# Automatic run finalization

A review run ends when the control plane records a terminal event for it, either success or failure. `controlplane.RunFinalizer` records that event as soon as the replayed task state allows one. Replaying means rebuilding the current state from the run's immutable plan and its complete hash-chained journal, the log in which each entry is chained to the one before it. The finalizer derives the outcome from the plan and the journal alone, so a caller cannot supply a different output or failure class to this path.

## Success output

Every valid plan has one result task. It is the unique required task at the highest review stage in the graph. A plan with two required tasks at that same highest stage is rejected as ambiguous, and it must add an explicit aggregation task.

In required publication mode, the result task is normally `publish_result`. In advisory and local operation, it is normally `evaluate_publication`. A smaller valid plan can end at an earlier task kind. On success, the finalizer uses the exact immutable output identity that was recorded for the result task.

Optional work must still be terminal before the run can succeed. An optional task's allowed failure or skip does not replace the output of the required result task.

## Failure

A run can fail only after a required task meets one of these conditions:

- it has a non-retryable failure;
- it has used up its immutable attempt bound; or
- it was skipped because a required dependency failed.

The finalizer selects the earliest required terminal failure by task-event revision, and uses the task key to break ties. The run therefore keeps the failure class of the task that failed first, not the class of a later dependency skip.

A retryable task is not finalized while an attempt remains. An expired lease, which is the time-limited claim a worker holds on a task, can be reclaimed only within the attempt bound. When the final attempt expires, coordinator advancement records a terminal `resource_limit` failure against that attempt and lease. Replay allows the coordinator to record this failure after expiry, but it does not allow a late worker success or a new retry. The finalizer then handles the failure like any other. Explicit cancellation is a separate terminal action.

## Replay and concurrency

`ReconcileRun` first calls the coordinator's deterministic advance operation. It then derives a canonical `TaskCompletion` from the replayed state and calls `SucceedRun` or `FailRun`. The terminal event is appended with a compare-and-append check against the current journal head, which means the append succeeds only if the journal has not changed since it was read.

Concurrent finalizers either append the same terminal event or replay the event that another process already stored. The journal contains only one terminal outcome. After a restart, the finalizer derives the same result from the canonical state. Finalization itself has no provider, source-control or publication effect.

`ReconcileRepository` scans at most 10,000 plans through bounded, stable pages. The task-notification supervisor runs scheduling reconciliation and finalization for every configured repository before it reports readiness. It then repeats this after local signals, after PostgreSQL wake-ups, and periodically as a fallback.

The daemon API, when runtime is enabled, also runs finalization immediately after a task completes. If a process stops between a task completing and the terminal event being appended, the supervisor closes the run through its startup reconciliation.
