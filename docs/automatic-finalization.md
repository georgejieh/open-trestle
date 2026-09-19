# Automatic run finalization

`controlplane.RunFinalizer` records a terminal review-run event as soon as replayed task state permits one. It derives the disposition from the immutable plan and complete hash-chained journal. A caller cannot supply a different output or failure class to this path.

## Deterministic success output

Every valid plan has one result task. It is the unique required task with the highest review stage in the graph. Plans with two required tasks at that same highest stage are rejected as ambiguous and must add an explicit aggregation task.

For required publication mode, the result is normally `publish_result`. For advisory and local operation it is normally `evaluate_publication`. A smaller valid plan can end at an earlier task kind. Successful finalization uses the exact immutable output identity recorded for that result task.

Optional work must still be terminal before success. Its allowed failure or skip does not replace the required result output.

## Deterministic failure

A run can fail only after a required task has a non-retryable failure, has exhausted its immutable attempt bound, or is skipped because a required dependency failed. The finalizer selects the earliest required terminal failure by task-event revision, with task key as a deterministic tie-breaker. This preserves the originating closed failure class rather than replacing it with a later dependency skip.

A retryable task is not finalized while an attempt remains. An expired lease can be reclaimed only within the immutable attempt bound. Once the final attempt expires, coordinator advancement records a terminal `resource_limit` task failure against that exact attempt and lease identity. Replay permits this coordinator settlement after expiry but does not permit a late worker success or a new retry. The finalizer then propagates the failure normally. Explicit cancellation remains a separate terminal action.

## Replay and concurrency

`ReconcileRun` first calls the coordinator's deterministic advance operation. It then derives a canonical `TaskCompletion` from replayed state and calls `SucceedRun` or `FailRun`. The terminal event uses the current journal head as its compare-and-append boundary.

Concurrent finalizers either append the same deterministic terminal event or replay the event already stored by another process. The journal contains one terminal disposition. A restart performs the same derivation from canonical state. Finalization itself performs no provider, source-control, or publication effect.

`ReconcileRepository` scans at most 10,000 plans through bounded stable pages. The task-notification supervisor runs scheduling reconciliation and finalization for every configured repository before reporting readiness, then repeats after local signals, PostgreSQL wake-ups, and periodic fallback.

The runtime-enabled daemon API also runs finalization immediately after a task completion. If a process stops between task completion and terminal append, supervisor startup reconciliation closes the run.
