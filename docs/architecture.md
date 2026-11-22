# Public architecture

This page describes how Open Trestle is built and which rules its runtime enforces. It is written for contributors and for operators who want to know what the software will and will not do.

## Purpose

Open Trestle is a code-review runtime. It reports a review result only after it can tie that result to an immutable change, the repository's policy, the tool or model route that was used, and the records that support it.

Open Trestle performs an initial review sweep. It is not a final human approval. The goal is a review that stays useful when no human is watching in real time, and that finds the routine defects and relevant context a careful human reviewer would expect to see. This is a design target, not a claim of human-equivalent quality.

A failed required gate is meant to be a credible reason to stop approval until the finding is resolved or a human records an override. A passed run means that the checks shown in its coverage finished without a verified blocking result. Human review is still recommended after a pass.

## Canonical flow

```text
GitHub webhook, CLI daemon submission, MCP plan submission, or the CLI direct review
  -> verified webhook ingress, authenticated daemon API, or in-process direct session
  -> versioned review run plan
  -> immutable review snapshot
  -> repository index, change-impact data and, with consent, repository checks
  -> one built-in deterministic check and model review (the finder)
  -> verification (a different model)
  -> deterministic judgement: dedupe, rank, pre-existing class, advisory (direct path)
  -> result linked to its sources, with a walkthrough (direct path), or abstention
  -> surface-specific rendering
```

There are two ways to run this flow.

- The direct path is `trestle local-git model-review`, which `trestle review` and the first review in `trestle init` also run. It executes the review task graph inside the `trestle` process with process-private stores. It keeps the repository index on disk for later reviews, and the `review` and `init` wrappers also keep last-review metadata.
- The daemon path runs the same handlers inside `trestled` with durable runs. The GitHub webhook planner, `trestle local-git submit-review`, `trestle runs submit` and the MCP `open_trestle.submit_run` tool submit reviews to it.

The TUI, `trestle lsp` and the VS Code extension, and the web console observe one daemon run. They cannot start a review. On both paths the runtime, not the surface, owns authorization, policy, provider routing, execution safety, evidence retention and audit receipts.

A direct review prepares its context before any model call:

- It builds the [repository index](repository-index.md) of the base and head commits. The index holds the syntax analysis of each file (13 languages, see [syntax analysis](syntax-analysis.md)) and supplies the enclosing definitions, callers, tests and a ranked repository map.
- With your consent, it runs the repository's own tests in a sandbox (see [repository checks](repository-checks.md)).
- It runs the built-in rule `static_debug_output` and the Go semantic-impact profile, and computes pattern hygiene and style detection.

Analyzer adapters that policy approves, such as linters and static analysis, are planned (see the [roadmap](roadmap.md)).

After verification, a direct review runs a deterministic judge stage in the `localreview` package. No model takes part in it. The judge does three things:

- It classifies each verified finding as introduced, pre-existing or of unproven origin. A pre-existing finding is on unchanged lines, cites no evidence of the change, and the repository index shows that nothing outside the changed declarations reaches them. Any other finding on unchanged lines, such as a caller of a changed function, is of unproven origin and blocks like an introduced one.
- It merges duplicates of one defect within a run and across the members of a `--specialists` set.
- It ranks the distinct findings.

A review whose confirmed findings are all low severity or pre-existing is advisory: it keeps its findings but does not block CI. The result also carries a walkthrough built from the recorded artifacts. The daemon path does not run this stage yet. Its diagnostic sets carry the verified findings as the verifier produced them, without rank or class. See [ranked findings and the walkthrough](local-model-review.md#ranked-findings-and-the-walkthrough).

## Control boundaries

### Evidence

The review ledger records the immutable snapshot identity, source ranges, policy versions, adapter versions, route decisions, verifier results and final dispositions. Model output and retrieval results are derived inputs. They cannot create a blocking finding on their own, change a severity, suppress a finding or choose an external action.

### Semantic impact evidence

The runtime builds semantic impact profiles from approved language adapters, and each profile is tied to one snapshot. The Go adapter and the deterministic analysis handler record changed declarations and public API changes. They also record explicit gaps in parsing, language support, source and resources. A profile names the exact base and head snapshots, the change model, the digests of the input files, the adapter identity, the graph schema, the evidence grades and the declared coverage.

Each element carries an evidence grade. Two grades exist today:

- `structural` covers validated parse results such as declaration differences. It may support verification.
- `syntactic_candidate` covers the repository index's name-matched uses and related tests of changed definitions. It may only prioritize inspection.

Two further grades are planned design with no implementation. One is compiler or language-server facts from a type-aware adapter, which could support verification. The other is heuristics such as historical co-change, which would only point at review targets and could never create, raise or verify a finding on their own (see the [roadmap](roadmap.md)). Text or regex fallback may find candidates but cannot be presented as semantic analysis. Unsupported languages, generated content, incomplete resolution and adapter failure produce coverage gaps or abstentions.

The runtime assembles a compact review context packet, addressed by its content, from these inputs:

- the immutable snapshot;
- the normalized changed symbols and ranges;
- the relevant impact evidence;
- the applicable policy;
- the receipts from deterministic analyzers;
- the known coverage limits.

A direct review also adds the commit messages of the reviewed range as author-stated, unverified intent, along with deterministic pattern-hygiene observations. Neither can create, raise or suppress a finding (see the [prompt-injection boundary](prompt-injection-boundary.md#stated-intent)). A model receives only the packet that its approved route permits. The packet digest is kept with the candidate and verifier records, so the basis of a conclusion can be reproduced.

An acquired review snapshot records the exact repository, the base and head revisions, the verified acquisition receipts, the complete file manifests, the manifest delta and the requested changed ranges. Each source excerpt in a production model packet carries a content-addressed slice proof. The proof checks the full-file digest and confirms that the excerpt is the byte sequence for its declared physical lines. Before candidate generation, the runtime records the acquired snapshot, the source selection, the context packet and the slice binding. A context packet without this lineage can support local inspection, but it cannot reach the publication effect boundary.

### Model routing

Every model request has a policy envelope. The envelope holds the tenant and repository scope, the privacy classification, the permitted provider zones, the required capabilities, the time and cost budgets and the logging rules. A local-only request cannot silently fall back to a remote route.

Standard candidate-generation and verification requests may use an approved `private_remote` route only after the host sanitizes every typed text field. The sanitizer runs a pinned Betterleaks v1.8.1 profile and masks each reported zero-based half-open byte span. It then scans the result again in the same helper session. Dispatch requires the second (residual) scan to finish with no findings. Investigation requests and investigation tool results stay local-only.

The sanitized request and its egress receipt are immutable artifacts. The egress receipt records which request left the host and how it was scanned. It binds these values:

- the identities of the raw and the sanitized request;
- the review scope;
- the field roles and ordinals;
- the completion of the initial and residual scans;
- the scanner profile;
- the SHA-256 of the secret scan helper.

It carries content-free spans and rule IDs. It carries no field text, paths, snippets, matches, source digests or Betterleaks fingerprints. The generation or verification handler reloads both artifacts, validates them together and seals an opaque dispatch proof for the exact authorized request and scope. A non-local adapter cannot create that proof, and it cannot accept a raw request through the generic dispatch boundary.

The scan runs in the secret scan helper: Betterleaks v1.8.1 inside a WebAssembly (wasip1) guest that the helper executes with the wazero runtime, with regular expressions evaluated by RE2. The WebAssembly sandbox and a hard process kill on any deadline or fault are the containment. The program pins the SHA-256 of the helper at link time and checks the helper file and that digest before each start. A review run uses one helper process, and the daemon uses a helper session of its own for each sanitization.

The boundary accepts at most 256 UTF-8 fields and 2 MiB decoded in total. Any of the following blocks dispatch and leaves no partial result: a deadline, an incomplete scan, a resource limit, abnormal output, or a residual finding. This protects against unprivileged replacement of the helper. It does not protect against a compromised host root or kernel.

This is a narrow confidentiality control, not full secret detection, and the sanitized text still leaves the host for a remote route. For what the scanner misses, see [privacy](privacy.md) and the scanner section of [operations](operations.md).

### Route capacity authority

A route is eligible only when its approved capabilities satisfy both the policy minimums and the full authorized request envelope. `max_output_tokens` cannot exceed the route's output capacity, and `estimated_input_tokens + max_output_tokens` cannot exceed its context capacity. These checks run before ranking and are validated again on both the eligibility result and the content-free selection receipt. Selection candidate scores keep the approved context and output capacities, so receipt validation does not depend on a registry that may change.

### Execution

Repository files, issue text, CI definitions, logs, analyzer output and model output are treated as data, not instructions (see the [prompt-injection boundary](prompt-injection-boundary.md)). Commands come only from versioned adapters with a narrow argument grammar. Running repository code is off by default. The repository checks run a fixed set of test commands, only after you consent, in a sandbox with no network and with resource limits (see [repository checks](repository-checks.md)). Nothing else in the repository runs.

Read-only evidence work may share immutable, content-addressed artifacts across analyzers and review workers. Cache keys include the snapshot, adapter version, policy version and request parameters. Candidate generation and verification do not rely on another worker's conversational summary. Restartable execution records capture the state of intake, snapshot capture, evidence acquisition, analysis, candidate generation and verification.

All transports use one immutable review-run task graph. The graph fixes the exact inputs, the approved handlers, the dependencies, the attempt limits, the retry delays and the lease durations. The control plane keeps the following guarantees:

- Workers receive short-lived capabilities, and the secrets in them are never written to the journal.
- The control plane rebuilds state from canonical hash-chained events.
- It rejects stale workers through attempt fencing.
- It passes terminal dependency failures downstream without running the downstream work.
- It resumes expired leases after a restart.

Workers acquire task leases that the journal fences. Reconciliation rebuilds notices after a missed signal or a process restart. The same supervisor derives terminal success or failure from the replayed task state and appends one compare-and-append terminal event. A process stop therefore cannot leave a settled run permanently active.

### Results

Results are rendered from the canonical result, which is the system of record. Publication readiness is advisory and grants no external effect. The daemon does not publish reviews to a forge.

Results show a human-facing review disposition next to the coverage: verified blocking findings, verified non-blocking findings, cleared gates, incomplete checks and explicit abstentions. A rendered result must not imply that a clear or passing disposition replaces human approval.

### Guided setup

The setup core turns the deployment posture and readiness checks into a versioned, resumable plan that holds no secrets. The plan comes with an immutable checker catalog and a replayable receipt ledger.

The CLI initializes and inspects protected state, validates local storage and the posture of observer credentials, requires exact runtime policy identities and a named approval, and runs a bounded, provider-neutral dry run with no network authority. `trestle init` and `trestle setup bootstrap` are the setup surfaces. They use secure defaults, show the consequence of less-safe choices, keep recovery state and remain usable over SSH.

## Integration model

Open Trestle has three integration paths:

1. The event path uses authenticated GitHub webhooks. Webhooks and service hooks from other forges are planned.
2. The command path covers local terminals, CI jobs and scripts that use a declared Git state or a local fixture file. Git-hook integration is planned.
3. The protocol path covers web console, REST, LSP and MCP clients. A gRPC API is planned.

The [roadmap](roadmap.md) lists the planned items. None of them has code in the tree.

An integration counts as supported only after it passes common conformance checks for identity, immutable revision selection, cancellation, retry, deduplication, evidence parity, privacy behavior and safe degradation.

The current terminal interface is a foreground observer over authenticated daemon receipts and canonical review diagnostics. It tells apart two kinds of result. Finding contracts in versions 5 and 8 are verified findings. Version 6 holds unverified deterministic observations. Version 7 is the final full-review result and keeps the two as separate sections. The terminal interface has no worker, model, source, policy or publication authority. Its only change to state is a run cancellation, which you must confirm and which goes through the canonical API.

The embedded web console is a read-only, same-origin client. It reads exact run receipts, canonical review diagnostics and content-free runtime status for one repository. It shows versions 5 and 8 as verified-finding state. It shows version 6 as deterministic observations that need human review, not as verified findings. A run that ended successfully in the terminal sense stays secondary to the review disposition.

The console keeps bearer credentials only in page memory, rejects responses from another scope and malformed responses, and renders repository-controlled text without interpreting markup. It exposes no cancellation, worker, model, source, policy change or publication capability. Runtime inspection uses a separate capability. It exposes only configuration identities, storage posture, exact handler bindings, publication-fence verification and supervisor readiness.

## Deployment model

The first supported local-first v1 installation targets one trusted daemon that runs as the installing user. That daemon may own writable local Git, journal and artifact handles. Trusted in-process components are inside this boundary. Model-generated code, repository scripts and plug-ins are not trusted owner components. This profile does not isolate its stores from hostile code that runs with the installing user's privileges, does not authenticate individual function calls, and does not resist tampering by that code.

A separately privileged owner may be considered as an optional later installation profile. The first v1 does not require it, and the owner path is not yet implemented or accepted. This design choice does not authorize source-content scanning, model or provider calls, credential changes, push, deployment, publication or release.

Keep the historical-packet startup refusal and the prepared-to-success refusal until replacements prove all of the following:

- exact owner binding;
- audited route authorization;
- live lease and source checks;
- admission and write fencing;
- safe handling of uncertain partial effects;
- durable recovery, including an interruption after candidate persistence followed by a restart, with no duplicate dispatch and no unverified promotion.

The deployment architecture uses a trusted control plane with local state, content-free task notifications, policy evaluation and scoped remote workers. The trusted CLI, snapshot, receipt, daemon, control-plane and remote-worker boundaries are implemented in Go.

The following parts are planned design with no code, manifests or charts in the tree: OpenTelemetry observability, a Docker Compose profile for a single operator, and Helm charts or Kubernetes manifests for larger installations. None of this is a released deployment. The check sandbox for repository tests runs on Linux and Windows. Remote model providers work with any build that has its secret scan helper, and the packaged install is Linux amd64 only (see [platforms](platforms.md)).

## Non-goals

Open Trestle does not aim to provide:

- hidden provider fallback for restricted repositories;
- running repository commands other than the fixed test commands of the repository checks;
- source mutation, merge, deployment or external reporting by default;
- unrestricted third-party plugins;
- dynamic testing of public, third-party or unspecified targets.
