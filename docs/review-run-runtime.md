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

## Owner context preparation and lease expiry

The opt-in local model pipeline uses an owner-only context handler. Its fixed
30-second lease is not renewed. Packet preparation (v4), input preparation (v5),
and input settlement (v6) remain distinct from generic task success. The owner
checks the original lease before new preparation, route, artifact, or settlement
work. Expiry cannot authorize a new route, a retry, or a late successful output.

Production input preparation and settlement share the original typed scope
intent. The marker remains through route effects, ordered request/receipt/input
writes, v6 append, exact physical and audit readback, and checked marker removal.
The runner does not cancel this owner solely because the lease timer expires;
the execution timeout and bounded drain still apply. This lets the owner finish
synchronous proof or terminal cleanup, not perform new expired work.

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

A successful task receipt alone is not owner proof. Marker-free v5 terminal
restart still requires complete matching physical envelopes and route-audit
lineage. Read-only historical facts and inventory predicates alone do not grant
startup or recovery authority.

Cancellation after v6 settlement can reopen only when replay proves every
candidate, verification, and readiness task has no attempt or output and remains
pending or available. The exact context envelopes and route-selection audit must
still match. Any route attempt, dispatch, cost reconciliation, continuation, or
publication effect refuses this narrow path. A claimed task is not proof of an
absent effect, even when no response was observed. The canceled result stays
terminal; it neither resumes model work nor prevents a later independent run.

Marker-free complete-v4 startup is limited to the exact first-attempt local
nine-task recipe, either at its prepared head or a recognized policy-failure
cleanup prefix. The original lease must be expired at the actual check time
(expiry inclusive), while packet retention must remain live (expiry exclusive).
A v4 its lease holder already settled as a recorded route refusal, with or
without part of the same cleanup suffix, needs no lease expiry because it holds
no lease; every other condition below applies unchanged, and startup appends
nothing to it.

Packet retention is 24 hours. A v4 the journal already settled, by a recorded
route refusal or a lease-expiry termination and with any part of the closed
cleanup suffix, is proved terminal from the journal and audit alone once its
packet retention lapses: its no-output policy failure admits no retry, input
preparation or settlement, so no later owner effect can read its artifacts.
Startup then still requires the exact recipe, current pipeline enrollment and
review policy, no linked input, no route effect in the scope's audit, and no
scope marker, but it neither reads nor deletes the expired bytes and appends
nothing, so every later boot reaches the same result. Removing an expired
artifact file does not change that result. A run first projected after its
evidence retention lapsed (for example a daemon stopped between finalization
and projection) gets the final result its journal proves, marked
`evidence_expired` and without any deterministic or verified part; no expired
artifact is read. A canceled run stays canceled and a failed run failed or
inconclusive, with a recorded route refusal kept. A succeeded run is reported
inconclusive, never completed, because a completed result needs its verified
evidence, and a context abstention cannot be confirmed without its artifact,
so it is reported failed. The supervisor keeps serving later runs. A v4 the journal has not
settled still requires live packet retention: its startup termination is
authorized only by the byte proof, so boot refuses it once retention lapses.

The same applies to a context input the journal already settled. That is an
owner-settled input (v6) whose run ended (succeeded, canceled, or failed by a
rejected candidate generation or an exhausted model lease), or an expired input
(v5) terminated by a no-output policy failure. Once the shared packet and input
retention lapses, startup proves it from the journal and audit without reading
or deleting the expired envelopes and without an append. It still checks the
recorded route selection, that a canceled run made no route attempt, and for a
failed run the exact rejection or lease-expiry journal suffix and its closed
audit chain: kinds, sequence and hash chain, and the selection, authorization,
input and packet identities the input recorded. It also still checks the
current generation handler, scanner binding and review policy, and that no
scope marker exists. An input whose run is still active, or a prepared input
(v5) not yet terminated, still requires live retention.
Each recorded envelope must expire no earlier than the packet. Before store
activation, startup checks canonical bytes and exact same-scope names against the
configured source root/repository/adapter. After current pipeline construction,
it repeats that proof and checks all current bindings and review policy before
any recovery append.
The scope audit must be stable and either empty or contain only snapshot-bound
events; that allowance does not validate source-audit lineage. Source-file names
do not attest their contents or retention.

Under exclusive boot ownership before services run, startup finishes the read-only
witnesses, rechecks the exact journal head and time under the scope gate, and may
append only policy/no-output failure. It then repeats the full proof before boot
continues. Any scope marker, mixed v4/v5 history, unknown effect, unsupported tail
or failed proof remains refused; this path removes no marker and grants no route,
retry or late success. A changed head refuses the append. An uncertain append or
failed postproof is not successful recovery and requires full reproof on restart.
This is cooperative owner custody, not protection against raw same-UID writes.
The narrow synthetic path and static guards do not establish a packaged full-boot
result, append-uncertainty fault coverage, general partial-crash recovery or v1
completion.

## Current boundary

The package provides the task graph, canonical encodings, memory and durable local journals, replay, optimistic coordination, claims, renewals, retries, dependency propagation, completion, cancellation, restart recovery, content-free task notifications, and automatic terminal finalization. The standalone daemon and PostgreSQL runtime adapter are available. An operational lock-recovery command is not included. See [PostgreSQL canonical ledgers](postgresql-storage.md).


A previously policy-terminated context packet (V4) may coexist with a later
owner-settled context input (V6) at restart. This is a narrow composition of two
existing proofs, not generic mixed-history recovery. Every unlinked packet must
have the exact expired policy-failure or recorded route-refusal tail, the current nine-task recipe and
catalog, retained canonical source/context envelopes and exact same-scope file
names, and no route effects in its audit stream. Each linked scope must have its
own V6 settlement and pass the existing byte, replay and route-audit proof before
the V4 proof completes. A live packet, prepared-only input (V5), unknown marker,
extra same-scope artifact, or unmatched effect still refuses startup. Restart
preserves both terminal diagnostic identities and does not dispatch either model
route again.

## Transport boundary

The public `controlplane` package owns these runtime contracts. The authenticated HTTP adapter, Go client, CLI, and daemon use the same canonical plan, lease, completion, and receipt encodings. See [Daemon API and client](daemon-api.md).


## Provider-free deterministic local runs

A local deterministic catalog is the exact three-handler subset `acquire_source`, `build_change`, and `inspect_deterministic`. Preparation expands it to four tasks because base and head acquisition are separate immutable roots. The two version 2 source inputs bind a daemon-retained source-root identity. Model inventory and runtime-policy identities are prohibited from this request shape.

The analysis handler stores exact match locations in deterministic-evidence result version 4 (version 5, 6 or 7 when a file only has deleted lines) and projects diagnostic set version 6. The static rule detects the complete Go call span, but observation evidence never widens beyond the change model: when a multiline call only intersects a changed line, the stored observation is projected to that exact changed intersection. Version 6 deliberately has `analysis_result_identity`, `checks`, and `observations`; it has no `verified_set_identity`, model-candidate coverage, verification-context identity, or verified findings. Observation count and canonical payload bytes are bounded before the analysis artifact is committed. Exceeding the durable diagnostic budget is a closed `resource_limit` failure, never silent truncation.

The repository supervisor finalizes settled runs only when its explicit local deterministic option is enabled. Existing GitHub and model pipeline supervisors preserve their separate finalization behavior. A daemon restart reopens the file journal, artifact store, audit ledger, and diagnostic store. Terminal runs are read back without rerunning handlers. An interrupted active deterministic run remains subject to the existing lease, attempt, and source-root identity checks.
