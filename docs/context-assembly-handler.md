# Context assembly task handler

The context assembly handler, `handlers/context`, decides what source text a model sees when it looks for problems in a change. It takes the outputs of the deterministic evidence task and the memory task, and builds one protected input for the generation task. A handler is the code that runs one kind of task in a review run. An artifact is a stored, protected task output. This handler does not call a model.

The terms below recur on this page:

- The context packet is the set of source text and metadata that goes to the model, together with the records of what was left out.
- A source is one piece of text in the packet, such as a changed hunk or an instruction file.
- An omission is a record that something was left out, with a reason.
- An identity is a digest computed from content, and a binding is a record that ties an object to the identities of the things it depends on.
- A taint is a label that says where a piece of data came from.

## Reconstruction boundary

The handler requires successful `analysis` and `memory` dependencies and runs in a single task attempt. It reloads the shared change artifact, both acquired snapshot indexes and every head source file. From these it rebuilds the head manifest, within a limit of 256 MiB.

The handler recreates every changed-range evidence slice from the bytes of the acquired file. The file identity, file digest, physical line slice, slice digest, byte count and `SourceSliceBinding` identity must all match the deterministic evidence artifact. This check also covers slices that later exceed the context selection limits.

## Context reduction

Repository text stays `repository_controlled` data. Only paths that the validated memory scope allows can enter the packet.

The handler considers changed-range evidence first. A handler built with `WithRepositoryContext` then asks its `IndexContextSource` for a plan of index context: enclosing definitions, uses of changed definitions, related tests and repository map entries, as line ranges with ranks. It binds each range against the head snapshot it already reconstructed, so the text comes from that snapshot, and fits the sources in priority order into the budget the changed sources, the instruction files and the stated intent leave. A plan the source cannot give leaves the packet with the changed code and records the index state. See [review context](local-model-review.md#review-context).

At most 128 source candidates are considered and 32 sources selected. The handler's budget, bound by `WithRepositoryContext` from the routes' context windows, sets the source bytes; without one it is 128 KiB. A handler without an index source, or whose source gives no usable plan, plans from the snapshots it already loaded: the head's Go files and the base versions of the changed files, analysed in process, at most 4,096 files and 64 MiB. Past 32 omission records, the records of each reason merge into one counted record at the reason's first path, since each path is a field the secret scanner reads. Every packet except an investigation context carries a `context_manifest` and, when the source read any, `repository_checks`.

The packet records the following:

- every analysis gap and every semantic-coverage gap;
- every omission before selection, whether for authorization, the candidate limit, a duplicate source or source size; and
- counted semantic omission summaries, which keep the number of rejected references without a record for each one.

The coverage counts add up the count of each omission record. That includes evidence excluded before selection, and the count and byte omissions made during selection. Memory query omissions stay bound through the dependency artifact in the context provenance.

The handler reconstructs every memory retrieval from its records, queries, scores, ranks, index revisions and identities. The context packet carries the whole retrieval set, not only one changed path. Memory stays labeled `advisory_only`.

## Non-Go text files

For a changed file whose path does not end in `.go`, the handler accepts its changed hunks as `changed_hunk` sources. A hunk is accepted when the slice is valid UTF-8 with no NUL byte, and it passes the same size and candidate limits as Go hunks.

These files get no structural or semantic analysis. The semantic-impact profile records `unsupported_language` for each such path, and the packet keeps that as the `semantic_unsupported_language` omission.

The handler does not review the non-Go paths in the table below. It records them as omissions instead.

| Rule | Omission reason |
| --- | --- |
| A `vendor` or `node_modules` path segment; basenames `go.sum`, `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`; suffixes `.lock`, `.min.js`, `.min.css`, `.map` | `excluded_path` |
| A hunk that is not valid UTF-8 or contains NUL | `non_text_content` |
| Binary or unsupported-content files rejected earlier by change evidence | `analysis_unsupported_content` |

The exclusion list applies only outside `.go`. A change in which every file is omitted for these reasons, or for `unsupported_language`, still produces the `unsupported_language` abstention, which means the review stops and says why.

## Repository instruction files

Many repositories keep instructions for AI tools in files such as `AGENTS.md`. The handler can pass these to the model as review preferences. It reads `AGENTS.md`, `CLAUDE.md`, `.github/copilot-instructions.md` and `.trestle/review-instructions.md` at the repository root of the base snapshot. It adds each file that is present there as a `repository_context` source. The list is fixed and covers the root only, so a copy in a subdirectory is not read. Content does not come from a working directory.

The head tree is not a source of instructions, because the author of a pull request controls it. An edit to an instruction file arrives as a `changed_hunk` source and is reviewed as code. A base instruction file is used only when the head holds identical content (equal digest and size). That way the source is slice-bound to the head file identity that every later readback checks. A readback is a check that reloads stored records and compares them with the source. A base file that the head changed or deleted is omitted as `repository_instruction_changed`. A file that is absent from the base contributes nothing, so a change against an empty base (every file added) has no instruction context.

The caps are 8 KiB per file and 16 KiB across all four files. If a file is larger, the handler cuts it at the last whole line within its allowance and records the dropped tail as `repository_instruction_truncated`, with its line range. The other omission reasons are:

- `repository_instruction_size_limit`, when the first line alone exceeds the allowance;
- `repository_instruction_unsupported_content`, when the file is not valid UTF-8 text;
- `repository_instruction_path_not_authorized`, when the path is outside the memory scope; and
- `repository_instruction_candidate_limit`, when the file is beyond the 128-candidate bound.

An instruction file whose slice is already a changed hunk is not duplicated.

The handler adds instruction sources only after the abstention and zero-selection decisions, so they do not make an all-omitted change reviewable. It also adds them only if they fit the selected-source count and the 128 KiB byte budget that remain after every changed source (in reference-ID order). A source that does not fit is omitted as `repository_instruction_packet_budget`, and it does not become a selection omission.

Every `repository_instruction_*` omission stays in the packet's `source_coverage` and `source_omissions` accounting, but it does not count as a changed-source omission. Derived verification coverage, diagnostic sets, SARIF `trestleSourceOmittedCount` and the result's `incomplete` status all exclude it. The direct local review reports it separately as `instruction_context_omitted`, which is a count field and a limitation (SARIF `trestleInstructionContextOmittedCount`).

Instruction files are advisory. They carry the `repository_controlled` taint and the same `evidence_data_not_instructions` label as every other source. The version 7 and 8 generation instructions tell the model that `repository_context` sources are the repository's own review preferences. They are guidance about what to look for and about the repository's conventions, and they cannot change the output contract or the evidence rules. A pull request can edit its own instruction file, so the text is a hint, not a rule the review must follow.

Candidate admission drops a candidate whose `source_range` names a `repository_context` source, and it keeps the rest of the batch. The drop is derived from the response and context bytes. It is counted in the batch as `repository_context_anchor_omitted`, which is bound into the batch identity and the durable encoding when it is nonzero. The direct local review reports it as the `repository_context_anchor_candidates_omitted` limitation and count. It does not fail the run. A candidate may still cite a `repository_context` source as supporting evidence. When an instruction file is itself changed, its changed lines are a separate `changed_hunk` source, and a candidate located there is accepted.

The verifier receives the same packet sources under the version 7 verification contract. In required publication mode, the handler rebinds each instruction source to its head file only after it checks the fixed path, the line-1 prefix and the byte-identical base copy. It refuses a published finding that is located in an instruction file. See the [publication task handler](publication-handler.md).

Every source carries `risk_flags`. From version 7, a source whose path names repository AI material (these instruction files, `SKILL.md`, prompt files and agent configuration directories) gets `agent_configuration`. Instruction-like content, such as chat-template tokens or fake system tags, gets `instruction_like_text`. The flags mark material for attention and do not suppress review. See the [prompt-injection boundary](prompt-injection-boundary.md) for the channel split and the full path and marker lists.

## Removed base lines

A file that has only deletions, analyzed at deterministic evidence version 7, carries one `removed_lines` record for each deletion point. The record holds the removed base lines, bound to the base file, with the `head_line` beside the deletion. An emptied or removed file carries its whole removed base text as chunk records with no head line.

The handler reloads that file from the base snapshot reference whose digest the record and its change entry name. It rebuilds the repository-file identity and the slice binding from the bytes, and it rejects any mismatch. Each record becomes one `removed_lines` source with `repository_controlled` taint. The source holds the file `path`, the base `start_line` and `end_line`, the record's `head_line` when it has one, and `risk_flags` from the same rules as every other source. Removed text is recorded as an omission at its base lines if it is on an excluded or unauthorized path, is not valid UTF-8 text, or is past the candidate limit.

The removed text of a deletion point does not make a change reviewable on its own. The handler keeps it only when a selected changed hunk of its file holds its `head_line`. Otherwise it records the text as a `packet_budget` omission at its base lines.

The removed text of an emptied or removed file needs no head neighbor. A change that only removes files therefore gets a packet of removed text alone, and its review snapshot has no head range. It still abstains with `all_sources_omitted` when no removed text can be supplied.

The handler selects removed sources right after changed hunks and before semantic expansions and instruction files. Removed base lines are not review-snapshot ranges, so a finding located on them is a base-side finding. See [deletion-only changes](local-model-review.md#deletion-only-changes).

## Pattern hygiene

After the sources are selected, every packet except an investigation context gets a `pattern_hygiene` object. It records whether the change adds or spreads one of the following:

- a curated anti-pattern;
- a lint or type suppression;
- a comment that justifies a workaround;
- a TODO without an issue reference; or
- an absolute rule in an agent instruction or skill file.

The handler builds it from the acquired snapshots. It uses the head contents that it already loaded and, for the directories of the changed files, the base files, which it reads from their protected artifacts. It reads at most 32 directories, 128 files on a side and 8 MiB of base text. A directory past a bound is recorded as unread and is not compared.

The object holds counts and at most 16 items, which are placed on selected `changed_hunk` sources by `source_id` and line. It carries no repository text. It does not change source selection, coverage or the abstention decisions, and a clean change records zero counts and an empty list. The rules, bounds and false-positive guards are in [local model review](local-model-review.md#pattern-hygiene).

## Stated intent

A handler built with `WithChangeIntent` also carries the change's author-stated intent. It asks its `ChangeIntentSource` for the change's own repository and `base..head` revisions, as the change artifact records them, and gets back a `review.StatedIntent`. The direct review's source reads commit messages from its verified local object store. The daemon binds none.

The handler fits the intent into the source byte budget that the selected sources left (`StatedIntent.Fit`), so changed code keeps priority. A cut is marked `truncated` or counted in `commits_omitted`. The intent is attached as the packet's `stated_intent` object, which is repository-controlled data with risk flags. It does not change selection, routing or the run plan. If the source fails, the task fails (`invalid_input`, or `canceled`) and the intent is not dropped. See [commit messages as stated intent](local-model-review.md#commit-messages-as-stated-intent) and the [prompt-injection boundary](prompt-injection-boundary.md#stated-intent).

## Context version and handler identity

Every new candidate-generation packet uses review-context schema version 10. It requests `model-candidate-batch-v2` (identity `63a1bd4a…91bb`). It binds the version 10 instructions through `instructions_identity`, which is their SHA-256. The prose itself is sent only in the system channel. The version 9 instructions are the version 8 instructions plus one sentence for `stated_intent` and one for `pattern_hygiene`. Version 8 is the version 7 instructions described above plus one sentence that explains `removed_lines` sources. Version 10 is the version 9 instructions plus one sentence for the index stages and `context_manifest` and one for `repository_checks`; it adds the stages `related_test` and `repository_map` and those two objects. Its verifier request is version 9, which adds one sentence for the index stages and does not carry the manifest or the checks. The packet also holds the optional `specialist` identity block when a profile is bound, `pattern_hygiene`, and `stated_intent` when an intent source is bound.

Versions 2, 3, 5, 7, 8 and 9 are accepted only by recorded-readback validators (`ValidateRecordedContextPacketRequest`, `RecordedContextSpecialist`, `ReconstructRecordedVerificationRequestContext`). These validators reread packets that were already recorded. Those versions do not start a model attempt, produce trusted egress instructions, or pass sanitized egress. Only version 9 may carry `stated_intent` or `pattern_hygiene`, and none of them may carry `context_manifest` or `repository_checks`.

The route-granting handler identity (`NewHandler`, `NewSpecialistHandler`) is `open-trestle/context-assembly-handler` version 9. It changed to version 6 for the text fallback, the base-snapshot instruction files and the version 7 contract. It changed to version 7 for the version 8 contract and `removed_lines` sources, to version 8 for the version 9 contract, pattern hygiene and the stated intent, and to version 9 for the version 10 contract, index context and the budget. `WithChangeIntent` also binds the identity of the intent source, and `WithRepositoryContext` that of the index source and the budget.

A run plan records its handler identities. A run planned under an earlier version is therefore not executed by the version 9 handler. It stops with an error. Its recorded artifacts remain readable. The packet-only, journaled packet-only and packet-authority identities are unchanged, although their packets are version 10 with pattern hygiene and a context manifest planned from the snapshots, and never carry a stated intent. An investigation context gets the enclosing definitions and uses, with related tests as uses, and no repository map or manifest.

## Route authority

A route is one way to reach a model. The handler passes the canonical provider request to a configured policy authorizer, which decides whether a route may be used. The authorizer identity is part of the handler identity. The call binds the review scope, the request identity, the plan policy and the decision time. The authorization that comes back must match the scope and the request.

The built-in policy authorizer ranks the performance observations that belong to eligible routes and keeps rejected-route accounting in the selection receipt. Before it returns a generation authorization, it records the route selection in the same scoped audit ledger that generation uses. If that write fails, it returns no authorization. Authorizer identity version 2 binds this audited-selection behavior, and construction requires an explicit ledger.

The handler persists two protected artifacts:

1. A `context_packet` that contains only canonical provider bytes.
2. A `task_input` that binds the context to its selected snapshot, the evidence, and one `RouteAttemptAuthorization`.

The task output is the `task_input`. It carries the memory-scope and retrieval-set identity, so the later provider-request validation recomputes every advisory record and retrieval identity. The generation handler consumes this authorization through its `context` dependency. The expiry of the context and of the input does not exceed the expiry of any source or upstream dependency.
