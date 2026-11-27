# Review run runtime

The review-run runtime plans a review, hands its tasks to workers and records every step. This page is for contributors. Local commands, CI, editors, APIs and source-control integrations all use the same review-run contract. A transport creates an immutable `ReviewRunPlan`, and workers interact with it through append-only events.

The terms used on this page:

- A handler is the code that runs one kind of task. Its identity is a digest of its implementation, and the plan records it.
- An artifact is a stored, protected task output.
- A route is one way to reach a model.
- An identity is a digest computed from content. A binding is a record that ties an object to the identities of the things it depends on.

## Task graph

A plan fixes the tenant and repository scope, the canonical review request, the policy, the maximum effect posture and an acyclic task graph. Each task fixes:

- a stable key and a closed operation kind;
- an immutable recipe or root input identity;
- its dependencies, whose successful outputs are copied into each leased execution request;
- whether completion is required;
- a maximum attempt count, a retry delay and a worker lease duration;
- the approved handler identity.

The task kinds, in the order of a full model review:

| Task kind | Handler | Section |
| --- | --- | --- |
| `acquire_source` | source acquisition | [Source acquisition](#source-acquisition) |
| `build_change` | change model | [Change model](#change-model) |
| `inspect_deterministic` | deterministic evidence | [Deterministic evidence](#deterministic-evidence) |
| `retrieve_context` | memory retrieval | [Memory retrieval](#memory-retrieval) |
| `assemble_context` | context assembly | [Context assembly](#context-assembly) |
| `generate_candidates` | model generation | [Candidate generation](#candidate-generation) |
| `verify_candidates` | model verification | [Verification](#verification) |
| `evaluate_publication` | publication readiness | [publication readiness](publication-readiness-handler.md) |
| `publish_result` | none built | |

Source acquisition comes before change construction, context assembly before candidate generation, candidate generation before verification, and verification before publication evaluation. Candidate generation and verification each get one attempt. A model retry needs a new route attempt that policy authorizes and a new cost reservation, and generic task retry can create neither.

## Journal

Every state change is a canonical event, addressed by its content, in a hash chain. Open Trestle rebuilds state by replaying the immutable plan and its complete event stream. Replay rejects gaps, forks, time reversal, records from another scope, dependency bypass, results from stale leases, attempts beyond the plan's limit and events after a terminal disposition.

Sequence numbers carry the order. Event times never decrease: a transition observed at a wall-clock time earlier than the last event is recorded at the last event's time. Lease expiry, renewal and retry delays are measured against recorded times, so a clock stepped backward cannot expire or extend a lease. A clock stepped forward can expire one.

The local file journal stores the canonical plan JSON and the event JSON Lines with private permissions, under an exclusive writer lease, with atomic replacement and file and directory synchronization. Plans can be listed by tenant and repository with cursor pagination, so a restarted supervisor finds unfinished work without crossing repository scope. An unclean stop leaves the writer lease in place, and an operator must recover it explicitly. No lock-recovery command is included.

## Worker leases, retry and cancellation

A worker claim returns a short-lived capability that contains a random lease secret. Only the digest of the secret enters the journal, and formatting always redacts the capability. A claim requires the exact handler identity bound into the task.

Before it releases work, dispatch rechecks the reconstructed state, the task kind, the lease digest, the attempt and the expiry. A result must match the current task, attempt, lease digest and expiry. Once a lease expires, another worker can take the next bounded attempt, and results from the previous worker are rejected.

Retry timing comes from the task definition. Only closed, retryable failure classes make a task available again. A permanent failure passes through dependent tasks without running them. Cancellation is terminal and invalidates outstanding work.

[Remote workers](remote-workers.md) describes how an external worker claims, executes and renews leases through the daemon API.

## Task notifications

A task notification tells a worker that a task may be ready. It reduces idle polling and schedules nothing: the plan and its journal stay canonical, and a worker rereads the authenticated plan and receipt and takes the normal lease before a handler runs.

`TaskNotification` is content-free. It records the tenant, repository and run scope, the plan identity, the task-state revision and its event identity, the task key, task identity and handler identity, the next attempt, and the time the task becomes available. A notification can be stale, duplicated, delayed or missed without affecting execution.

`TaskNotificationLease` protects the acknowledgement of a delivery with a random bearer token, and persistent stores keep only its digest. It also records the worker identity, the delivery number, the issue time and the expiry. The canonical JSON encoders reject unknown fields, noncanonical bytes, invalid identities, oversized payloads and mismatched lease data. Delivery tokens belong only in authenticated request bodies and responses, never in URLs, logs, journals or exports.

`TaskNotificationQueue` supports enqueue, one scoped claim and a fenced acknowledgement, which only the current holder of a delivery can make. A notification is delivered at most ten times. An active delivery cannot be replaced before it expires, and a stale worker cannot acknowledge a newer delivery. Using up the deliveries changes neither the journal nor the task. The daemon uses the in-memory implementation.

`TaskNotificationScheduler` rebuilds each run from its plan and journal and enqueues a notice for each task that replay shows as available or as having an expired lease. Notice identities derive from the state head, so concurrent schedulers enqueue the same value. `TaskNotificationSupervisor` serves one tenant and an allowlist of repositories. Before it reports readiness it reconciles scheduling and finalization for all plans, then it reacts to local and queue wake-ups and to a periodic fallback. Errors are retried a limited number of times and then stop the supervisor, and a restart repeats the reconciliation from durable state.

The schemas are `task-notification-v1`, `task-notification-lease-v1` and `task-notification-claim-request-v1` under `schemas/controlplane/`.

## Finalization

`controlplane.RunFinalizer` records the terminal event of a run as soon as the replayed task state allows one. It derives the outcome from the plan and the journal, so a caller cannot supply an output or failure class.

Every valid plan has one result task: the unique required task at the highest review stage in the graph. A plan with two required tasks at that stage is rejected as ambiguous and must add an explicit aggregation task. The result task is normally `evaluate_publication`. On success, the finalizer uses the output identity recorded for it. Optional tasks must be terminal first, and their failure or skip does not replace the result.

A run fails only after a required task has a non-retryable failure, has used up its attempts, or was skipped because a required dependency failed. The finalizer selects the earliest required terminal failure by task-event revision, with the task key as tie-break, so the run keeps the failure class of the task that failed first. A retryable task is not finalized while an attempt remains. When the final attempt's lease expires, the coordinator records a terminal `resource_limit` failure against that attempt, and a late worker success is rejected. See [failure details](failure-details.md) for the reasons a failed run reports.

`ReconcileRun` advances the coordinator, derives a `TaskCompletion` from the replayed state and calls `SucceedRun` or `FailRun`. The terminal event is appended with a compare-and-append check against the current journal head, so concurrent finalizers append the same event or replay the stored one. Finalization has no provider, source-control or publication effect. `ReconcileRepository` scans at most 10,000 plans through stable pages. The daemon API also finalizes immediately after a task completes, and the supervisor closes any run left open by a stop in between.

## Handler catalogs and routing configuration

The public `runtimecatalog` package builds a catalog from approved task implementations. A catalog holds one handler for every task kind the run mode requires, and it ends at publication readiness. Building fails on a missing or duplicate task kind, a malformed handler identity or an extra handler. The catalog identity is a digest of the run mode, the task kinds and the handler identities. A `controlplane.TaskHandlerCatalog` works with `worker.RepositorySupervisor` or a scoped remote `worker.Runner`. Source and model credentials stay inside their configured adapters.

### Route inventory

The route inventory is the operator's list of model routes with the facts needed to choose between them. `runtimeconfig.DecodeRouteInventory` accepts a document that conforms to `schemas/runtime/runtime-route-inventory-v1.schema.json`. Each entry holds a route reference, capability and logging declarations, fixed or unknown pricing, a quality evidence tier, a registry revision and lifecycle status, an inline evidence manifest, health and quota observations and a sampled P95 latency. All records share one registry and performance revision.

The decoder limits the document to 8 MiB and 64 routes. It rejects unknown fields, duplicate or noncanonical keys, trailing values, values that are both known and unknown, malformed base64, duplicate record identities, invalid evidence digests and mixed revisions. A route whose record is not `approved` stays in the inventory but fails eligibility. The generation and verification authorizers use the same validated inventory, so privacy filtering, cost eligibility, ranking and verifier independence all work from one snapshot.

Route dispatcher catalogs bind `ConfigurationIdentity()` for every registered adapter. Adapters include all non-secret connection settings in that identity, and credential providers are used only when a request is sent.

### Runtime policy

`runtimeconfig.DecodeRuntimePolicy` loads a versioned policy against one route-inventory identity. The versions and their schemas are listed in [protocol contracts](protocol-contracts.md). A policy binds:

- an external review-policy identity and the model requirements;
- the data classification, allowed zones and whether content logging is permitted;
- token and micro-USD budgets;
- an optional generation pin and an ordered list of preferred records;
- verifier independence;
- provider connection authorities.

The pin applies to generation only. For verification the policy keeps the ordered preferences, first excludes routes that fail the required independence level, and never relaxes independence to reuse the pinned generation route. If no eligible route remains, verification stops with an error.

A provider connection holds an implementation token, an adapter ID, an endpoint and a credential environment reference, and no secret. Credential references must use the `OPEN_TRESTLE_PROVIDER_` namespace, so routing configuration cannot name API, webhook or other daemon secrets. Endpoints must use HTTPS, or HTTP on a canonical numeric loopback address, with no user information, query, fragment, encoded or unclean path, noncanonical host or port. Decoding also rejects unknown fields, duplicate or noncanonical keys, records from a different inventory, duplicate preferences or connections, malformed credential references and all-zero authority identities. `runtimecatalog` converts the decoded policy into generation, verification and provider dispatcher authorities.

## Artifacts

Artifacts are the records that tasks pass to each other. Each one records its tenant, repository and run scope, a kind and canonical media type, a data classification and producer origin, its storage protection, ordered provenance identities, the payload digest, and the creation and expiry times. The artifact identity covers all of that metadata. The wire contract is `schemas/artifact/runtime-artifact-v1.schema.json`.

Payloads are capped at 16 MiB before base64 encoding and the encoded envelope at 22 MiB. Decoding rejects unknown fields, noncanonical JSON, duplicate provenance, altered payloads, expired timestamps and identity mismatches, and formatting is redacted. Kinds such as `investigation_turn` and `investigation_tool_result` are labels only: the payload codec and the expected identity, scope and origin are checked separately. Artifacts never contain credentials or raw lease capabilities.

The daemon opens a private artifact store under its state root. The store provides:

- partitioning by review scope and lookup by content address;
- deduplication;
- advisory writer locking that is reclaimed after a process dies;
- checks that each object is a regular file with a stable inode;
- `0600` permissions on objects and locks;
- atomic rename with file and directory synchronization;
- limits on object count and size, and corruption detection;
- denial of expired artifacts on read and write.

Its protection is `process_private`.

## Source acquisition

`handlers/source` fetches the source a run needs and stores it as artifacts. It connects an approved `scm.SourceAdapter` to the task contract and artifact storage, and implements `controlplane.TaskAcquireSource`.

A planner creates a canonical `source-acquisition-input` artifact before it makes the task available. It holds one repository identity, one full Git commit identity, one source-adapter descriptor, the fixed `manifest_and_content` request and the fixed `read_only` effect. The task's input identity must be that artifact's identity. Before touching any source, the handler rejects inputs that are missing, expired, repository-originated, noncanonical, from another scope or for another adapter. Webhook, API, CI and local planners share this contract. The webhook path plans separate `source-base` and `source-head` inputs, so both sides are fetched at fixed commits and never from a moving branch.

### Merge-base inputs

A pull request diff is taken against the merge base. A merge-base input (`source-acquisition-input` version 3) names a requested base and a head with `base_derivation: merge_base`. The handler asks the adapter, which must implement `scm.MergeBaseResolver`, for the forge's merge base and then acquires that commit. It never falls back to the requested base. The resulting `source-snapshot` version 2 records the merge base as its revision, with the requested base and head in `revision_derivation`. If the handler refuses, the task fails with a reason that holds no repository content:

| Condition | Run failure | Reason |
| --- | --- | --- |
| The requested base equals the head, or the merge base is the head | `policy` | `nothing_to_review` |
| Both commits exist and share no history (the GitHub adapter never reports this, see [merge base](github-source-acquisition.md#merge-base)) | `policy` | `no_merge_base` |
| The merge base could not be read | by the mapping below | `merge_base_unavailable` |
| The adapter cannot resolve merge bases | `policy` | `merge_base_unavailable` |
| The adapter returned a malformed result | `internal` | `merge_base_unavailable` |

### Output and failures

A successful acquisition writes one protected `source_file` artifact per manifest entry (path, SHA-256 digest, byte count, bytes and execution identity; empty files are allowed; 10 MiB per file) and then one protected `source_snapshot` index that binds the request, receipt, repository, revision, adapter, manifest and ordered file references. The snapshot is written only after all files are durable. Outputs keep the scope, classification, protection and expiry of the input, and their provenance includes the task input and the acquisition execution.

`ParseSnapshotArtifact` verifies the index. `ParseFileArtifact` then takes the verified snapshot and one listed reference and checks scope, classification, protection, identity, encoding, origin, provenance, digest, byte count and lineage before it returns a copy. Downstream handlers resolve only file identities that a verified snapshot lists.

Adapter outcomes map to run failures:

| Acquisition reason | Run failure |
| --- | --- |
| Authorization, policy or capability blocked | `policy` |
| Adapter unavailable | `transient` |
| Resource limit exceeded | `resource_limit` |
| Malformed or inconsistent source data | `internal` |
| Canceled execution | `canceled` |

Provider error strings and repository content never enter task completions. Once execution has started, the handler follows the worker's execution context and renewed lease, not the original lease expiry. The schemas are `source-acquisition-input-v1` to `-v3` (v2 binds a daemon-retained source-root identity), `source-file-v1` and `source-snapshot-v1` and `-v2`, under `schemas/artifact/`. GitHub specifics are in [GitHub source acquisition](github-source-acquisition.md).

## Change model

`handlers/change` turns the `source-base` and `source-head` outputs into one `change_model` artifact that lists the changed files, with ranges linked back to the source. It makes no repository or network access.

The handler requires exactly two successful source dependencies. For each it resolves the root input, the snapshot index and every file the index names, then rechecks scope, classification, protection, repository and revision identity, adapter identity, acquisition lineage, file size and digest, and the manifest identity. Base and head must share a repository and adapter. A merge-base `source-base` input must have a version 2 snapshot whose derivation names the requested base and the head that `source-head` acquired, and the change then runs from the merge base. A plain input needs a plain snapshot, and the head input cannot be a merge-base input. At most 256 MiB of source is loaded, and it is cleared after execution.

The handler builds a `RepositoryManifestDelta` and records one `RepositoryFileDeltaExecution` for each changed path:

- Modified supported text records a normalized file-change identity, a line-map identity and the changed ranges on the head side.
- Added text that is nonempty, valid and within budget records full-file change data and the complete head range.
- Removed files stay in the result without a head range.
- Empty files, invalid UTF-8 or binary files and files over budget keep an unsupported reason from a fixed list.

A result holds at most 4,096 changed paths and binds both snapshots, the repository, the revisions, the manifests, the delta, the per-path identities and digests, the status, the omission reason and the ranges. Its artifact has deterministic-tool origin and cites both dependency outputs, both root inputs and the delta. The schema is `change-model-result-v1`.

## Deterministic evidence

`handlers/analysis` collects facts about a change that do not depend on a model: source slices, a semantic impact profile and one check. It takes the `change_model` dependency, makes no network calls and infers no defects beyond the rule of its check.

**Source slices.** The handler resolves the base and head snapshots named by the change result, finds each changed head file, reloads its artifact and rebuilds the repository-file identity from the bytes. Only lines the change model names become slices. Each records a `SourceSliceBinding` (file identity and digest, range, slice digest and size), so the context handler can reload the file and rebind the slice before a model sees it.

**Semantic impact.** The handler loads the changed Go files from both snapshots and derives structural declaration changes, public API changes and explicit coverage gaps. The profile binds both snapshots, the change model, every loaded file digest, the Go adapter identity and the graph schema. See [semantic impact profiles](semantic-impact.md).

**Check.** One `static_debug_output` check uses the Go AST and type-aware scanner to find `fmt.Println("debug")` calls that overlap changed Go ranges. It records the rule version, the change identity, the counts of applicable and checked ranges, the match count and the state:

- `passed`: every applicable changed Go range parsed and had zero matches.
- `failed`: at least one match. Coverage can still be incomplete, and the counts show it.
- `incomplete`: an applicable range could not be checked and no match was found.
- `not_applicable`: no changed Go range.

The check holds no repository content and repeats the source-check, analysis-result and change identities so consumers can tell it apart from model findings.

**Bounds and coverage.**

- At most 8,192 evidence or gap records are written.
- At most 64 MiB of changed head source is read in one execution. The removed text of emptied and removed files is read from a separate 64 MiB bound and charged only by the bytes bound.
- Each slice is at most 1 MiB.
- Every changed range is represented once, by evidence or by a typed gap. Removed, binary, unsupported and empty added files, and the source, slice and aggregate limits, all appear in the output. An added file without a reviewable range gets `empty_added_file` only when it has zero bytes, `unsupported_content` when the change model cannot diff it, and `resource_limit` past the size bound.
- A file the change model could not diff because of its size (over 1 MiB) becomes one whole-entry `resource_limit` gap. If the number of required records exceeds the limit, one `evidence_limit` gap covers each changed entry. Ranges are never truncated.

**Deletion points.** For a file with deleted lines, the handler binds up to 8 unchanged head lines on each side of each deletion point and adds one `deleted_lines` gap for the point. It reads the base file from the base snapshot reference whose digest matches the change entry, rebuilds its identity from the bytes and binds the removed base lines of each point as one `removed_lines` record, a slice binding to the base file with base line numbers and the `head_line` beside which the lines were removed. An emptied or removed file keeps its whole-entry gap and also binds its removed base text as line-aligned chunks of at most 64 lines and 8 KiB, up to 32 KiB per file, with no head line. The rest becomes one trailing `removed_lines_limit` gap.

Removed text is bound after every other entry, from the budget they left, so it takes nothing from a changed file. A file past the 64 MiB bound, or with no budget left, records one whole-entry `removed_lines_limit` gap. A base file that is not text binds no records and is charged nothing. A point whose removed text exceeds 64 lines or 8 KiB, or would take the entry past 32 KiB, is recorded whole as a `removed_lines_limit` gap at its base range. The lines of that gap are base lines, unlike every other ranged gap. Removed base ranges of an entry never overlap, and every entry accounts for its removed text through records, limit gaps or both. See [deletion-only changes](local-model-review.md#deletion-only-changes).

The protected `deterministic_evidence` artifact has `deterministic_tool` origin, binds the change artifact and result, repository, head revision and snapshot, manifest, slice proofs and coverage accounting, and expires no later than any source it used. The handler writes `deterministic-evidence-result-v7` with a `semantic-impact-profile-v2` profile.

## Memory retrieval

`handlers/memory` looks up stored memory records that relate to the changed files. It takes the `change_model` artifact and returns advisory context, never findings.

A handler installation binds its handler identity to one approved review policy, the memory backend identity, the actor, an allowlist of path prefixes, a query limit and a result limit. At execution it requires the plan's policy identity and creates a fresh memory scope from the run's tenant and repository, the actor and path authorization, `exact` ref visibility and the acquired head revision as the ref-set identity. The scope applies before any scoring, so records from another tenant, repository, actor, revision set or path partition are never queried.

The handler validates the change artifact and both snapshots, then runs path-only lexical queries for the changed paths: at most 64 queries and 50 ranked records for the whole task. Every changed path is covered by a query or recorded with an omission reason (`path_not_authorized`, `query_limit` or `result_limit`). Each item keeps its query, index revision and retrieval identity, rank and score components, record identity, kind, taint, path and text, evidence, derivation and counterevidence, producer, validity interval, freshness watermark and confidence basis. Parsing the output rebuilds every scope, query, record and retrieval identity, and expired or stale records fail that rebuild.

The protected `retrieval_result` artifact has `memory` origin and binds the change, the review policy, the memory scope and the backend identity. It expires within one hour, sooner if the source or a selected record expires. The schema is `memory-retrieval-result-v1`.

## Context assembly

`handlers/context` decides what source text a model sees. It takes the deterministic evidence and memory outputs and builds one protected input for generation. It does not call a model.

- The context packet is the source text and metadata sent to the model, with the records of what was left out.
- A source is one piece of text in the packet, such as a changed hunk or an instruction file.
- An omission is a record that something was left out, with a reason.
- A taint says where data came from.

**Reconstruction.** The handler requires successful `analysis` and `memory` dependencies and runs in one attempt. It reloads the change artifact, both snapshot indexes and every head source file, and rebuilds the head manifest within 256 MiB. It recreates every changed-range slice from the acquired bytes, and file identity, digest, line slice, slice digest, byte count and `SourceSliceBinding` must match the evidence artifact, including slices that later exceed the selection limits.

**Selection.** Repository text stays `repository_controlled` data, and only paths the memory scope allows can enter the packet. Changed-range evidence comes first. A handler built with `WithRepositoryContext` then asks its `IndexContextSource` for a plan of enclosing definitions, uses of changed definitions, related tests and repository map entries, binds each range against the head snapshot and fits them in priority order into the budget that remains. If the source gives no usable plan, the handler plans in process from the snapshots it already loaded (the head's Go files and the base versions of changed files, at most 4,096 files and 64 MiB). See [review context](local-model-review.md#review-context).

At most 128 candidates are considered and 32 sources selected. The source budget comes from `WithRepositoryContext` and the routes' context windows, or is 128 KiB without one. Past 32 omission records, records of each reason merge into one counted record. The packet records every analysis and semantic-coverage gap, every omission before selection (authorization, candidate limit, duplicate, size) and counted semantic omission summaries. Memory stays labeled `advisory_only`, and the packet carries the whole retrieval set. Every packet except an investigation context carries a `context_manifest` and, when the source read any, `repository_checks`.

**Non-Go text.** A changed hunk in a path that does not end in `.go` becomes a `changed_hunk` source if it is valid UTF-8 without NUL bytes and within the same limits. These files get no semantic analysis, and the packet keeps `semantic_unsupported_language` for them. Some paths are omitted:

| Rule | Omission reason |
| --- | --- |
| A `vendor` or `node_modules` path segment; basenames `go.sum`, `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`; suffixes `.lock`, `.min.js`, `.min.css`, `.map` | `excluded_path` |
| A hunk that is not valid UTF-8 or contains NUL | `non_text_content` |
| Binary or unsupported files rejected earlier by change evidence | `analysis_unsupported_content` |

The exclusion list applies only outside `.go`. A change in which every file is omitted for these reasons, or for `unsupported_language`, ends in an `unsupported_language` abstention: the review stops and says why.

**Repository instruction files.** The handler reads `AGENTS.md`, `CLAUDE.md`, `.github/copilot-instructions.md` and `.trestle/review-instructions.md` at the root of the base snapshot and adds each one present as a `repository_context` source. Subdirectory copies and working directories are not read. The head tree is not a source, because the pull request author controls it. An edit to an instruction file arrives as a `changed_hunk` source and is reviewed as code. A base file is used only when the head holds identical content, so the source stays slice-bound to the head file identity. A base file the head changed or deleted is omitted as `repository_instruction_changed`, and a change against an empty base has no instruction context.

The caps are 8 KiB per file and 16 KiB across the four. An oversized file is cut at the last whole line within its allowance, and the dropped tail is recorded as `repository_instruction_truncated` with its line range. The other omission reasons are `repository_instruction_size_limit` (the first line alone exceeds the allowance), `repository_instruction_unsupported_content`, `repository_instruction_path_not_authorized`, `repository_instruction_candidate_limit` and `repository_instruction_packet_budget`. Instruction sources are added after the abstention decisions, so they never make an all-omitted change reviewable, and only if they fit the selected-source count and byte budget left by the changed sources.

**Project intent documents.** The handler then reads the project intent documents at the fixed paths `.trestle/scope.md`, `.specify/memory/constitution.md`, `.kiro/steering/product.md`, `openspec/project.md`, `agent-os/product/mission.md`, `.taskmaster/docs/prd.txt`, `memory-bank/projectbrief.md`, `PRD.md`, `docs/PRD.md` and `docs/prd.md`, in that order, under the same rules and the same `repository_instruction_*` omission reasons. It uses the first three it can supply; a later document in the base is omitted as `repository_instruction_candidate_limit`. The caps are 8 KiB per document and 16 KiB across the three, separate from the instruction-file caps. Each one used is a `repository_context` source at its path; the model instructions name the four instruction file paths and describe every other `repository_context` source as a project intent document, untrusted data the change may be compared with.

These omissions stay in `source_coverage` and `source_omissions` but do not count as changed-source omissions: derived verification coverage, diagnostic sets, SARIF `trestleSourceOmittedCount` and the result's `incomplete` status exclude them. The direct local review reports them as `instruction_context_omitted` (SARIF `trestleInstructionContextOmittedCount`).

Instruction files are advisory. They carry the `repository_controlled` taint and the `evidence_data_not_instructions` label like every other source, and the model instructions say they are guidance about what to look for that cannot change the output contract or evidence rules. Candidate admission drops a candidate whose `source_range` names a `repository_context` source and keeps the rest of the batch, counted as `repository_context_anchor_omitted`. A candidate may still cite such a source as supporting evidence. The verifier receives the same sources, rebinds each instruction source to its head file only after checking the fixed path, the line-1 prefix and the byte-identical base copy, and refuses a finding located in an instruction file.

Every source carries `risk_flags`. A source whose path names repository AI material (these instruction files, `SKILL.md`, prompt files, agent configuration directories) gets `agent_configuration`, and instruction-like content such as chat-template tokens or fake system tags gets `instruction_like_text`. The flags mark material for attention and do not suppress review. See the [prompt-injection boundary](prompt-injection-boundary.md).

**Removed base lines.** Each `removed_lines` record from the evidence step becomes one `removed_lines` source with `repository_controlled` taint, holding the path, base `start_line` and `end_line`, the `head_line` when it has one, and `risk_flags`. The handler reloads the file from the base snapshot reference the record names, rebuilds the identity and slice binding from the bytes, and rejects any mismatch. Removed text on an excluded or unauthorized path, that is not valid UTF-8 or that is past the candidate limit is recorded as an omission at its base lines. Removed text at a deletion point is kept only when a selected changed hunk of its file holds its `head_line`, and otherwise it is a `packet_budget` omission. The removed text of an emptied or removed file needs no head neighbor, so a change that only removes files gets a packet of removed text alone, and it abstains with `all_sources_omitted` when none can be supplied. Removed sources are selected right after changed hunks. A finding on them is a base-side finding, see [deletion-only changes](local-model-review.md#deletion-only-changes).

**Pattern hygiene.** Every packet except an investigation context gets a `pattern_hygiene` object that records whether the change adds or spreads a curated anti-pattern, a lint or type suppression, a comment that justifies a workaround, a TODO without an issue reference, or an absolute rule in an agent instruction or skill file. It is built from the head contents already loaded and, for the directories of changed files, base files read from their artifacts: at most 32 directories, 128 files per side and 8 MiB of base text, and a directory past a bound is recorded as unread. The object holds counts and at most 16 items placed on selected `changed_hunk` sources, and no repository text. It changes neither selection nor abstention. The rules are in [local model review](local-model-review.md#pattern-hygiene).

**Stated intent.** A handler built with `WithChangeIntent` asks its `ChangeIntentSource` for the author-stated intent of the change's `base..head` revisions and attaches it as the packet's `stated_intent` object, fitted into the budget the selected sources left so changed code keeps priority (a cut is marked `truncated` or counted in `commits_omitted`). The direct review reads commit messages from its local object store, and the daemon binds no source. If the source fails the task fails (`invalid_input` or `canceled`). See [commit messages as stated intent](local-model-review.md#commit-messages-as-stated-intent) and the [prompt-injection boundary](prompt-injection-boundary.md#stated-intent).

**Check runs.** `WithCheckRuns` binds the outcomes of the repository's own tests and linters (`review.CheckRuns`, see [repository checks](repository-checks.md)). They are attached as `check_runs` only when the change has the same full base and head commit IDs, and otherwise the task fails with `invalid_input`. The object is bounded on its own (16 checks, 64 listed test IDs), does not count toward the source budget, and every name, reason and test ID is secret-scanned.

**Version.** New candidate-generation packets use review-context schema version 11, which requests `model-candidate-batch-v2` and binds its instructions through `instructions_identity`, their SHA-256. The instruction text is sent only in the system channel. The route-granting handler identity is `open-trestle/context-assembly-handler` version 11, and `WithChangeIntent`, `WithRepositoryContext` and `WithCheckRuns` bind the identities of their sources. A run planned under a different handler identity is not executed by this handler.

**Route authority.** The handler passes the canonical provider request to a configured policy authorizer, bound to the review scope, request identity, plan policy and decision time, and the returned authorization must match the scope and request. The built-in authorizer ranks the performance observations of eligible routes, keeps rejected-route accounting in the selection receipt, and records the route selection in the scoped audit ledger before it returns an authorization. If that write fails it returns none.

The handler writes two protected artifacts: a `context_packet` holding only canonical provider bytes, and a `task_input` that binds the context to its snapshot, the evidence, the memory-scope and retrieval-set identity and one `RouteAttemptAuthorization`. The task output is the `task_input`, which the generation handler consumes through its `context` dependency. Neither expires after any source or upstream dependency.

## Candidate generation

`handlers/model.GenerationHandler` asks a model for candidate problems. A candidate is a proposed problem that verification must still confirm. The handler sends the context packet to the gateway policy approved, makes one authorized provider attempt, accepts only candidates that cite source evidence, records route audit events and stores one protected candidate artifact.

**Authority.** The context task produces a `model-generation-input` artifact that binds the review scope and context artifact, the packet identity and required candidate schema, the review snapshot and its supported ranges, the host-issued evidence allowlist and one `RouteAttemptAuthorization`. At execution the handler reads both artifacts through the scoped store and repeats the checks, including `review.ValidateContextPacketRequest`. Repository source and recalled memory stay labeled as data, and only host-issued source evidence can support a candidate. The provider adapter sends the context bytes as the user message and `review.TrustedModelRequestInstructions` as the system channel. When a specialist is bound, the system channel also holds the skill text from the embedded profile catalog. See the [prompt-injection boundary](prompt-injection-boundary.md).

**Execution.** The handler identity includes the `RouteDispatcherCatalog` identity. Before releasing context bytes, the handler requires an existing route-selection audit event and records an idempotent attempt claim. After the call it records the dispatch outcome and the cost reconciliation, for success and failure. A model task must declare `max_attempts: 1`, and the GitHub planner applies this to generation and verification. The only provider retry is the same-route retry after a rate limit, which takes over the refused attempt's reservation. An ambiguous transport outcome stays visible as a claimed attempt, and a crash between dispatch and the terminal audit record is not replayed automatically.

**Acceptance.** A response is accepted only when it is one complete structured `review.v1` response that conforms to `model-candidate-batch-v2`, every cited source and evidence ID was in the packet, every claimed range is covered by the snapshot and cited evidence, there are no semantic duplicates, and the reconciled cost is within the authorized budget. A candidate anchored in a `repository_context` source is dropped and counted, not failed. A candidate located in a `removed_lines` source is a base-side finding: its lines are base lines inside that source, it records the source's `head_line` and `"side":"base"`, and only cited `removed_lines` evidence covers it. See [base-side findings](local-model-review.md#base-side-findings). Provider reasoning and invalid output are never stored as candidates.

**Category and fix.** Each candidate has a required `category` (`correctness`, `security`, `concurrency`, `performance`, `reliability`, `maintainability`, `style`, `documentation`, `testing`) and an optional `fix`, nonblank plain text of at most 256 characters. The parser rejects a missing, null or unknown category, an empty, blank, oversized, non-string or control-character fix, and any extra member. Both are model output and bound into the candidate and batch identities: the category is advisory and the fix is guidance for a person, not a patch or command.

**Failures.** A failed task carries a run failure and, where the provider's answer decides the cause, one content-free reason: a provider refusal named from its HTTP status (`provider_payment_required`, `provider_model_unavailable`, `provider_model_retired`, `provider_authentication_failed`, `provider_authorization_denied`, `provider_request_rejected`, `provider_rate_limited`), `provider_response_invalid` for a reply the adapter rejected, or `model_output_invalid` for a normally stopped reply that the review parser rejected. A host input check, or a reply that stopped at the output limit or a content filter, records no reason. The reason never includes the reply. See [failure details](failure-details.md).

**Output.** The `candidate_batch` artifact holds the accepted `CandidateBatch`, one successful `RouteExecutionRecord`, the route authorization, terminal outcome, token usage, cost settlement, normalized output receipt and the lineage of context and response. `ParseGenerationResultArtifact` revalidates scope, classification, protection, provenance, candidates, route records and encodings. The schemas are `route-attempt-authorization-v1`, `route-execution-record-v1`, `candidate-batch-v1` to `-v3`, `model-generation-input-v1`, `-v3` and `-v4` and `model-generation-result-v1` under `schemas/artifact/`, and `model-candidate-batch-v1` and `-v2` under `schemas/review/`.

## Verification

`handlers/model.VerificationHandler` has a second model check the candidates. Setup recommends a model from a different family, see [the rationale](rationale.md#the-checker-should-come-from-a-different-model-family). The handler builds a separate verifier request from the candidate artifact, selects a route that policy approves and that satisfies the separation policy relative to the generation route, records the second attempt, accepts a complete set of verdicts and writes a protected artifact of verified findings.

**Reconstruction.** The handler resolves the `candidates` dependency, the generation result and its exact input and context artifacts in the same scope, and revalidates the lineage. `review.NewVerificationRequestContext` rebuilds the verifier request from the generation context bytes and the accepted candidates, keeping source and advisory memory context and labeling candidates as unverified proposals. The request has its own identity and output schema. For a version 11 generation context the verifier request is verification-context version 10. The verifier receives every generation source, including removed base text at a deletion point, plus the `check_runs` object when present, but not `pattern_hygiene`, `context_manifest`, `repository_checks`, candidate categories, fix guidance or specialist guidance. The contract is sent in the system channel and bound by `instructions_identity`.

A regression listed in `check_runs` is strong evidence that the change broke that test and can support a candidate on the code that causes it. A test listed as stopped running is not, since a rename or removal does the same, and a check that could not run, no regression or a passing test is not evidence that the code is correct. When a change contradicts its stated intent, the verifier checks the claim against both the intent and the source evidence.

The handler checks source content, risk flags, evidence digests, snapshot ranges, labels, counted preselection omissions, coverage equations and candidate fields again. The `SourceCoverage` projection exposes only aggregate analyzed, selected and omitted counts, maps each omission reason to a content-free category and shows selection-stage omissions as `selection_limit`, with no paths, content or raw reason strings.

**Route authorization.** `PolicyVerificationAuthorizer` takes a route snapshot from `VerificationRouteInventory` and goes in this order:

1. Reject every route that does not satisfy the independence policy relative to candidate generation.
2. Apply the privacy zone and content-logging constraints.
3. Apply the capability, health, quota and budget checks.
4. Rank the remaining routes.
5. Create the route selection and the initial attempt authorization.
6. Record the selection in the scoped audit ledger before returning it.

The separation policies require a distinct full route reference, model or provider. A different registry revision, price or capability claim for the same route does not make it separate. The handler rechecks the authorization before dispatch and after the outcome. Inventory and audit-storage failures return the transient authorization-unavailable state, and no eligible route is a policy failure. Provider and inventory error text is not stored. Verification tasks require `max_attempts: 1`, the attempt claim is recorded before any context is released, and an overrun reconciled budget stops the task with an error. A verification failure records the same content-free reasons as generation.

**Verdicts.** The response must hold one verdict for every accepted candidate. A verified verdict needs supported source evidence and a final severity. Rejected and inconclusive verdicts cannot carry one. The handler rejects unknown candidates, omitted candidates, duplicate verdicts, unsupported evidence and incomplete sets. A verdict may cite a `removed_lines` source, but its base line numbers never cover the candidate's head lines. A verified verdict whose citations cover none of the candidate's lines also cites the candidate's `source_reference` when that source is on the candidate's side, is in the request and the list has room (at most four); otherwise it is refused with `evidence_mismatch`.

**Output.** A successful `verified_finding_set` artifact binds the canonical verification batch, the successful route execution, the route-independence proof from before and after dispatch, the verification receipt, the promoted finding set and the identities of the generation result, context, request, response, cost and provenance. Only verified candidates are promoted, and a promoted finding copies its candidate's category and fix unchanged. The fix is unverified model text: it is not part of `PublishableFinding`, so forge publication and its content scan do not render it, and the local JSON result labels it `unverified_model_guidance`. Rejected and inconclusive counts stay in the set. `ParseVerificationResultArtifact` rebuilds the context and all derived receipts, reruns the independence check and promotion and compares every identity before returning data. The schemas are `verification-batch-v1` and `-v2`, `verified-finding-set-v1` to `-v3` and `model-verification-result-v1` under `schemas/artifact/`.

## Publication readiness

The last task decides which verified findings are ready to report. The decision is advisory and nothing is written to a forge. See [publication readiness](publication-readiness-handler.md).

## Provider-free deterministic runs

A local deterministic catalog holds three handlers, `acquire_source`, `build_change` and `inspect_deterministic`. Preparation expands it to four tasks, because base and head acquisition are separate roots. The two `source-acquisition-input` version 2 inputs bind a source-root identity that the daemon retains, and model inventory and runtime-policy identities are not allowed in this request shape.

The analysis handler stores exact match locations in the deterministic evidence result and projects diagnostic set version 6, which has `analysis_result_identity`, `checks` and `observations` and no verified set, model-candidate coverage or verification context. The static rule detects the complete Go call span, and observation evidence never extends beyond the change model: a multiline call that only intersects a changed line is projected to that changed intersection. The observation count and canonical payload bytes are bounded before the artifact is committed, and exceeding the durable diagnostic budget is a `resource_limit` failure, not truncation.

The repository supervisor finalizes settled runs only when its local deterministic option is on. A daemon restart reopens the file journal, artifact store, audit ledger and diagnostic store, reads terminal runs back without running handlers again, and applies the usual lease, attempt and source-root checks to an interrupted active run.

## Transport boundary

The public `controlplane` package owns these contracts. The authenticated HTTP adapter, the Go client, the CLI and the daemon use the same canonical plan, lease, completion and receipt encodings. See [Daemon API and client](daemon-api.md).
