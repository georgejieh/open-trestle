# Review run runtime

The review-run runtime is the part of Open Trestle that plans a review, hands its tasks to workers and records every step. It is written for contributors. Local commands, CI, editors, APIs and source-control integrations all use the same review-run contract. A transport creates an immutable `ReviewRunPlan`. Workers interact with the plan through append-only events rather than private conversational state.

## Task graph

A plan fixes the tenant and repository scope, the canonical review request, the policy, the maximum effect posture and a bounded acyclic task graph. Each task fixes the following:

- a stable key and a closed operation kind;
- an immutable task recipe or root input identity;
- its canonical dependencies, whose successful outputs are copied into each leased execution request;
- whether completion is required;
- a maximum attempt count;
- a retry delay;
- a worker lease duration;
- the exact approved handler identity.

The order of the safety-critical tasks is part of the graph's structure:

1. Source acquisition comes before change construction.
2. Context assembly comes before candidate generation.
3. Candidate generation comes before independent verification.
4. Verification comes before publication evaluation.
5. Publication depends on publication evaluation, and plans that stay local never include it.

Publication, candidate generation and independent verification each get one orchestration attempt. A model retry needs a new route attempt that policy authorizes, together with a new cost reservation. Generic task retry can create neither. The publisher handler uses the separately audited, idempotent publication-attempt and retry contracts, so generic worker recovery cannot duplicate an external effect.

## Journal and recovery

Every state change is a canonical event, addressed by its content, in a hash chain. Open Trestle reconstructs state by replaying the immutable plan and its complete event stream. Replay rejects gaps, forks, time reversal, records from another scope, dependency bypass, results from stale leases, attempts beyond the plan's limit, and events after a terminal disposition.

The local file journal stores the canonical plan JSON and the event JSON Lines with private permissions. You can list plans by exact tenant and repository filters with bounded cursor pagination. A restarted supervisor can therefore find unfinished work without crossing repository scope.

The journal uses an exclusive writer lease, bounded files, atomic replacement, file synchronization and directory synchronization. An unclean stop leaves the writer lease in place, and an operator must recover it explicitly. PostgreSQL and queue-backed implementations must keep the same compare-and-append behavior.

## Worker leases

A worker claim returns a short-lived capability that contains a random lease secret. Only the digest of the secret enters the journal, and formatting always redacts the capability. A claim requires the exact handler identity bound into the task.

Before it releases work, handler dispatch rechecks the current reconstructed state, the task kind, the lease digest, the attempt and the expiry. A result must match the current task, attempt, lease digest and expiry. Once a lease expires, another worker can acquire the next bounded attempt, and results from the previous worker fail closed.

Retry timing comes from the immutable task definition. Only closed, retryable failure classes can make a task available again. Permanent failures pass through dependent tasks without running them. Cancellation is terminal and invalidates outstanding work.

## Owner context preparation and lease expiry

The opt-in local model pipeline uses an owner-only context handler. The owner is the single trusted process that prepares and settles context for a run. Its lease is fixed at 30 seconds and is not renewed. The work has three steps, each recorded as its own event and each distinct from generic task success:

- packet preparation (v4);
- input preparation (v5);
- input settlement (v6).

The owner checks the original lease before any new preparation, route, artifact or settlement work. Expiry cannot authorize a new route, a retry or a late successful output.

Production input preparation and settlement share the original typed scope intent, and the scope marker stays in place through the whole sequence:

- the route effects;
- the ordered writes of the request, the receipt and the input;
- the v6 append;
- the exact physical and audit readback;
- the checked removal of the marker.

The runner does not cancel the owner just because the lease timer expires. The execution timeout and the bounded drain still apply. This lets the owner finish a synchronous proof or a terminal cleanup, but not start new work after expiry.

| Observed boundary | Outcome |
| --- | --- |
| Expiry before v4 | Refuse preparation without a packet effect. |
| Marker-free complete v4, expiry before route preparation | No route or v5 is granted. The narrow startup proof below may record policy/no-output failure; uncertain or partial state remains refused. |
| Marker-free complete v4, route refusal while planning the input within the lease | Under the scope gate, before any marker, route effect or v5, the owner records policy/no-output failure carrying `route_context_insufficient` with its token counts or `no_eligible_route`. The packet is retained, the run fails, and later runs continue. If the lease expires before the refusal is recorded, the owner records the lease-expiry policy/no-output failure for the same exact v4 instead, and later runs still continue. |
| Route effect before v5 | Preserve the intent and audit. No route regrant; unknown effects remain quarantined. |
| v5 with an exactly known successful write prefix of zero, one, or two input envelopes | An in-process expiry may record policy/no-output failure, but retains the marker. Restart remains quarantined. A failed write is not proof of absence. |
| Complete v5 after expiry | Terminal recovery requires the exact packet and all three input envelopes plus the matching route audit. It records only policy/no-output failure and clears only an exact recognized marker. |
| Marker-free legacy v5 | Live state remains refused. Expired complete state requires the same full physical and audit proof before terminal recovery. |
| Expiry before v6 append | No late success. Preserve the intent for complete-v5 terminal proof. |
| v6 committed, verification or cleanup interrupted | Restart rechecks exact committed settlement, artifacts, and audit before marker reconciliation; no repeated dispatch. |
| Missing, mismatched, unknown partial, or retention-expired evidence, except a journal-settled packet or input past retention (below) | Preserve quarantine. Generic terminal events do not attest stored bytes or authorize marker removal. |

A successful task receipt alone is not proof that the owner finished correctly. Restarting a terminal v5 that has no marker still requires complete, matching physical envelopes and a complete route-audit lineage. Read-only historical facts and inventory predicates alone do not grant authority to start up or recover.

### Reopening a canceled run

Cancellation after v6 settlement can reopen the run only when replay proves two things. First, every candidate, verification and readiness task has no attempt and no output, and is still pending or available. Second, the exact context envelopes and the route-selection audit still match. Any route attempt, dispatch, cost reconciliation, continuation or publication effect rules out this narrow path. A claimed task is not proof that no effect happened, even when no response was seen. The canceled result stays terminal. It does not resume model work, and it does not prevent a later independent run.

### Startup recovery of a complete v4

Startup recovery of a marker-free, complete v4 is limited to the exact first-attempt local nine-task recipe. The run must be at its prepared head or at a recognized policy-failure cleanup prefix. The original lease must have expired at the time of the check (expiry inclusive), while the packet's retention must still be live (expiry exclusive).

A v4 whose lease holder already settled it as a recorded route refusal needs no lease expiry, because it holds no lease. This holds with or without part of the same cleanup suffix. Every other condition below still applies, and startup appends nothing to it.

Packet retention is 24 hours. Suppose the journal already settled a v4, by a recorded route refusal or by a lease-expiry termination, and any part of the closed cleanup suffix exists. Once its packet retention lapses, the journal and audit alone prove it terminal. Its no-output policy failure admits no retry, input preparation or settlement, so no later owner effect can read its artifacts.

Startup still requires the following for that case:

- the exact recipe;
- the current pipeline enrollment and review policy;
- no linked input;
- no route effect in the scope's audit;
- no scope marker.

Startup neither reads nor deletes the expired bytes, and it appends nothing, so every later boot reaches the same result. Removing an expired artifact file does not change that result.

A run that is first projected after its evidence retention lapsed gets the final result that its journal proves. An example is a daemon that stopped between finalization and projection. The result is marked `evidence_expired` and has no deterministic or verified part, and Open Trestle reads no expired artifact. The result follows these rules:

- A canceled run stays canceled.
- A failed run stays failed or inconclusive, and a recorded route refusal is kept.
- A succeeded run is reported inconclusive, never completed, because a completed result needs its verified evidence.
- A context abstention cannot be confirmed without its artifact, so it is reported failed.

The supervisor keeps serving later runs. A v4 that the journal has not settled still requires live packet retention. Only the byte proof authorizes its startup termination, so boot refuses it once retention lapses.

### Startup recovery of a settled input

The same applies to a context input that the journal already settled. There are two such cases: an owner-settled input (v6) whose run ended (succeeded, was canceled, or failed through a rejected candidate generation or an exhausted model lease), and an expired input (v5) that a no-output policy failure terminated. Once the shared packet and input retention lapses, startup proves the input from the journal and audit. It reads or deletes no expired envelope and makes no append.

Startup still checks the following:

- the recorded route selection;
- that a canceled run made no route attempt;
- for a failed run, the exact rejection or lease-expiry journal suffix and its closed audit chain (the kinds, the sequence and hash chain, and the selection, authorization, input and packet identities that the input recorded);
- the current generation handler, the scanner binding and the review policy;
- that no scope marker exists.

An input whose run is still active, or a prepared input (v5) that is not yet terminated, still requires live retention.

Each recorded envelope must expire no earlier than the packet. Before the store is activated, startup checks the canonical bytes and the exact same-scope names against the configured source root, repository and adapter. After the current pipeline is built, it repeats that proof and checks all current bindings and the review policy before any recovery append. The scope audit must be stable. It must be either empty or contain only snapshot-bound events, and that allowance does not validate source-audit lineage. Source-file names do not attest their contents or retention.

Startup runs under exclusive boot ownership before any service runs. It finishes the read-only witnesses, rechecks the exact journal head and the time under the scope gate, and may append only a policy/no-output failure. It then repeats the full proof before boot continues. The following all remain refused: any scope marker, a mixed v4/v5 history, an unknown effect, an unsupported tail and a failed proof. This path removes no marker and grants no route, retry or late success. A changed head refuses the append. An append of uncertain outcome, or a failed proof afterward, is not a successful recovery and needs a full reproof on restart.

This is cooperative owner custody. It does not protect against raw writes by the same user ID. The narrow synthetic path and the static guards do not establish a packaged full-boot result, coverage of faults that leave an append uncertain, general recovery from a partial crash, or v1 completion.

## Current boundary

The package provides the task graph, the canonical encodings, memory and durable local journals, replay, optimistic coordination, claims, renewals, retries, dependency propagation, completion, cancellation, restart recovery, content-free task notifications and automatic terminal finalization. The standalone daemon and the PostgreSQL runtime adapter are available. An operational lock-recovery command is not included. See [PostgreSQL canonical ledgers](postgresql-storage.md).

At restart, a context packet (V4) that policy already terminated may exist next to a later, owner-settled context input (V6). Recovery handles this as a narrow composition of two existing proofs, not as general recovery from mixed history. The conditions are:

- Every unlinked packet must have the exact expired policy-failure or recorded route-refusal tail, the current nine-task recipe and catalog, retained canonical source and context envelopes with exact same-scope file names, and no route effects in its audit stream.
- Each linked scope must have its own V6 settlement and pass the existing byte, replay and route-audit proof before the V4 proof completes.

A live packet, a prepared-only input (V5), an unknown marker, an extra same-scope artifact or an unmatched effect still refuses startup. Restart keeps both terminal diagnostic identities and does not dispatch either model route again.

## Transport boundary

The public `controlplane` package owns these runtime contracts. The authenticated HTTP adapter, the Go client, the CLI and the daemon use the same canonical plan, lease, completion and receipt encodings. See [Daemon API and client](daemon-api.md).

## Provider-free deterministic local runs

A local deterministic catalog is the exact subset of three handlers: `acquire_source`, `build_change` and `inspect_deterministic`. Preparation expands it to four tasks, because the base and head acquisitions are separate immutable roots. The two version 2 source inputs bind a source-root identity that the daemon retains. Model inventory and runtime-policy identities are prohibited in this request shape.

The analysis handler stores exact match locations in deterministic-evidence result version 4 (version 5, 6 or 7 when a file has only deleted lines) and projects diagnostic set version 6. The static rule detects the complete Go call span, but observation evidence never extends beyond the change model. When a multiline call only intersects a changed line, the stored observation is projected to that exact changed intersection.

Version 6 deliberately has `analysis_result_identity`, `checks` and `observations`. It has no `verified_set_identity`, no model-candidate coverage, no verification-context identity and no verified findings. The observation count and the canonical payload bytes are bounded before the analysis artifact is committed. Exceeding the durable diagnostic budget is a closed `resource_limit` failure, never silent truncation.

The repository supervisor finalizes settled runs only when its explicit local deterministic option is on. The existing GitHub and model pipeline supervisors keep their separate finalization behavior. A daemon restart reopens the file journal, the artifact store, the audit ledger and the diagnostic store. Terminal runs are read back without running their handlers again. An interrupted active deterministic run is still subject to the existing lease, attempt and source-root identity checks.
