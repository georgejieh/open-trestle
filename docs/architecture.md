# Public architecture

This page describes how Open Trestle is built and which rules its runtime enforces. It is for contributors, and for operators who want to know what the software will and will not do.

## Purpose

Open Trestle is a code-review runtime. It reports a review result only when it can tie that result to an immutable change, the repository's policy, the tool or model route that was used, and the records that support it.

A review is an initial sweep, not a final human approval. The goal is a review that stays useful when no human is watching in real time and that finds the routine defects and relevant context a careful human reviewer would expect to see. This is a design target, not a claim of human-equivalent quality.

A failed required gate is meant to be a credible reason to withhold approval until the finding is resolved or a human records an override. A passed run means that the checks shown in its coverage finished without a verified blocking result. Human review is still recommended after a pass.

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

The flow runs in one of two ways.

- The direct path is `trestle local-git model-review`, which `trestle review`, the VS Code extension and the first review in `trestle init` also run. It executes the review task graph inside the `trestle` process with process-private stores. It keeps the repository index on disk for later reviews, and the `review` and `init` wrappers also keep last-review metadata.
- The daemon path runs the same handlers inside `trestled`, with durable runs. The GitHub webhook planner, `trestle local-git submit-review`, `trestle runs submit` and the MCP `open_trestle.submit_run` tool submit reviews to it.

`trestle lsp` and the web console observe one daemon run and cannot start a review. On both paths the runtime, not the surface, owns authorization, policy, provider routing, execution safety, evidence retention and audit receipts.

A direct review prepares its context before any model call:

- It builds the [repository index](repository-index.md) of the base and head commits. The index holds the syntax analysis of each file (13 languages, see [syntax analysis](syntax-analysis.md)) and supplies the enclosing definitions, callers, tests and a ranked repository map.
- With your consent, it runs the repository's own tests in a sandbox (see [repository checks](repository-checks.md)).
- It runs the built-in rule `static_debug_output` and the Go semantic-impact profile, and computes pattern hygiene and style detection.

Analyzer adapters that policy approves are planned and have no code. The repository's own linters and type checkers already run as part of the repository checks.

After verification, a direct review runs a deterministic judge stage in the `localreview` package, with no model involved. The judge:

- classifies each verified finding as introduced, pre-existing or of unproven origin. A pre-existing finding is on unchanged lines, cites no evidence of the change, and the repository index shows that nothing outside the changed declarations reaches those lines. Any other finding on unchanged lines, such as one in a caller of a changed function, is of unproven origin and blocks like an introduced one;
- merges duplicates of one defect within a run and across the members of a `--specialists` set; and
- ranks the distinct findings.

A review whose confirmed findings are all low severity or pre-existing is advisory: it keeps its findings but does not block CI. The result also carries a walkthrough built from the recorded artifacts. The daemon path does not run this stage yet, so its diagnostic sets carry the verified findings as the verifier produced them, without rank or class. See [ranked findings and the walkthrough](local-model-review.md#ranked-findings-and-the-walkthrough).

## Control boundaries

### Evidence

The review ledger records the immutable snapshot identity, source ranges, policy versions, adapter versions, route decisions, verifier results and final dispositions. Model output and retrieval results are derived inputs. On their own they cannot create a blocking finding, change a severity, suppress a finding or choose an external action.

### Semantic impact evidence

The runtime builds [semantic impact profiles](semantic-impact.md) from approved language adapters, each tied to one snapshot. The Go adapter and the deterministic analysis handler record changed declarations, public API changes, and explicit gaps in parsing, language support, source and resources. Besides the identities listed on that page, a profile names its evidence grades and declared coverage.

Each element carries an evidence grade. Two grades exist today:

- `structural` covers validated parse results such as declaration differences. It may support verification.
- `syntactic_candidate` covers the repository index's name-matched uses and related tests of changed definitions. It may only prioritize inspection.

Two further grades are planned and not implemented. One is compiler or language-server facts from a type-aware adapter, which could support verification. The other is heuristics such as historical co-change, which would only point at review targets and could never create, raise or verify a finding on their own. A text or regex fallback may find candidates but cannot be presented as semantic analysis. Unsupported languages, generated content, incomplete resolution and adapter failure produce coverage gaps or abstentions.

The runtime assembles a compact, content-addressed review context packet from:

- the immutable snapshot;
- the normalized changed symbols and ranges;
- the relevant impact evidence;
- the applicable policy;
- the receipts from deterministic analyzers;
- the known coverage limits.

A direct review also adds the commit messages of the reviewed range, as author-stated and unverified intent, and deterministic pattern-hygiene observations. Neither can create, raise or suppress a finding (see the [prompt-injection boundary](prompt-injection-boundary.md#stated-intent)). A model receives only the packet that its approved route permits. The packet digest is kept with the candidate and verifier records, so the basis of a conclusion can be reproduced.

An acquired review snapshot records the exact repository, the base and head revisions, the verified acquisition receipts, the complete file manifests, the manifest delta and the requested changed ranges. Each source excerpt in a production model packet carries a content-addressed slice proof, which checks the full-file digest and confirms that the excerpt is the byte sequence of its declared physical lines. Before candidate generation, the runtime records the acquired snapshot, the source selection, the context packet and the slice binding. A context packet without this lineage can support local inspection, but it cannot reach the publication effect boundary.

### Model routing

Every model request has a policy envelope. The envelope holds the tenant and repository scope, the privacy classification, the permitted provider zones, the required capabilities, the time and cost budgets and the logging rules. A local-only request cannot silently fall back to a remote route.

Standard candidate-generation and verification requests may use an approved `private_remote` route only after the host sanitizes every typed text field. The sanitizer runs a pinned Betterleaks v1.8.1 profile, masks each reported zero-based half-open byte span, and scans the result again in the same helper session. Dispatch requires this second (residual) scan to finish with no findings. Investigation requests and investigation tool results stay local-only.

The sanitized request and its egress receipt are immutable artifacts. The egress receipt records which request left the host and how it was scanned. It binds:

- the identities of the raw and the sanitized request;
- the review scope;
- the field roles and ordinals;
- the completion of the initial and residual scans;
- the scanner profile;
- the SHA-256 of the secret scan helper.

The receipt carries content-free spans and rule IDs, but no field text, paths, snippets, matches, source digests or Betterleaks fingerprints. The generation or verification handler reloads both artifacts, validates them together and seals an opaque dispatch proof for the exact authorized request and scope. A non-local adapter cannot create that proof, and it cannot accept a raw request through the generic dispatch boundary.

The scan runs in the secret scan helper, whose runtime, process model and limits are described in the scanner section of [operations](operations.md). Containment comes from the WebAssembly sandbox and a hard process kill on any deadline or fault. The program pins the SHA-256 of the helper at link time and checks the helper file against it before each start. This protects against unprivileged replacement of the helper, but not against a compromised host root or kernel. Any failure blocks dispatch and leaves no partial result.

This is a narrow confidentiality control, not full secret detection, and the sanitized text still leaves the host for a remote route. For what the scanner misses, see [privacy](privacy.md).

### Route capacity authority

A route is eligible only when its approved capabilities satisfy both the policy minimums and the full authorized request envelope: `max_output_tokens` cannot exceed the route's output capacity, and `estimated_input_tokens + max_output_tokens` cannot exceed its context capacity. These checks run before ranking and are validated again on both the eligibility result and the content-free selection receipt. Selection candidate scores keep the approved context and output capacities, so receipt validation does not depend on a registry that may change.

### Execution

Repository files, issue text, CI definitions, logs, analyzer output and model output are treated as data, not instructions (see the [prompt-injection boundary](prompt-injection-boundary.md)). Commands come only from versioned adapters with a narrow argument grammar. Running repository code is off by default. The repository checks run a fixed set of test commands, only after you consent, in a sandbox with no network and with resource limits (see [repository checks](repository-checks.md)). Nothing else in the repository runs.

Read-only evidence work may share immutable, content-addressed artifacts across analyzers and review workers. Cache keys include the snapshot, adapter version, policy version and request parameters. Candidate generation and verification do not rely on another worker's conversational summary. Restartable execution records capture the state of intake, snapshot capture, evidence acquisition, analysis, candidate generation and verification.

All transports use one immutable review-run task graph, which fixes the exact inputs, the approved handlers, the dependencies, the attempt limits, the retry delays and the lease durations. The control plane gives workers short-lived capabilities whose secrets are never written to the journal, rebuilds state from canonical hash-chained events, rejects stale workers through attempt fencing, and passes terminal dependency failures downstream without running the downstream work. Reconciliation rebuilds notices after a missed signal or a restart, and the supervisor resumes expired leases and finalizes settled runs, so a process stop cannot leave a settled run permanently active. See [review run runtime](runtime.md).

### Results

Results are rendered from the canonical result, which is the system of record. Publication readiness is advisory and grants no external effect, and the daemon does not publish reviews to a forge.

Results show a human-facing review disposition next to the coverage: verified blocking findings, verified non-blocking findings, cleared gates, incomplete checks and explicit abstentions. A rendered result must not imply that a clear or passing disposition replaces human approval.

### Guided setup

The setup core turns the deployment posture and readiness checks into a versioned, resumable plan that holds no secrets, together with an immutable checker catalog and a replayable receipt ledger.

The CLI initializes and inspects protected state, validates local storage and the posture of observer credentials, requires exact runtime policy identities and a named approval, and runs a bounded, provider-neutral dry run with no network authority. The setup surfaces are `trestle init` and `trestle setup bootstrap`. They use secure defaults, show the consequence of less safe choices, keep recovery state and remain usable over SSH.

## Integration model

Open Trestle has three integration paths:

1. The event path uses authenticated GitHub webhooks. Webhooks and service hooks from other forges are planned.
2. The command path covers local terminals, CI jobs and scripts that use a declared Git state or a local fixture file. Git-hook integration is planned.
3. The protocol path covers web console, REST, LSP and MCP clients. A gRPC API is planned.

None of these planned items has code in the tree, and none is on the [roadmap](roadmap.md).

An integration counts as supported only after it passes common conformance checks for identity, immutable revision selection, cancellation, retry, deduplication, evidence parity, privacy behavior and safe degradation.

The embedded web console is a read-only, same-origin client. It reads exact run receipts, canonical review diagnostics and content-free runtime status for one repository. It shows diagnostic set versions 5 and 8 as verified-finding state, and version 6 as deterministic observations that need human review, not as verified findings. Whether a run ended successfully in the terminal sense stays secondary to the review disposition.

The console keeps bearer credentials only in page memory, rejects malformed responses and responses from another scope, and renders repository-controlled text without interpreting markup. It offers no cancellation, worker, model, source, policy change or publication capability. Runtime inspection uses a separate capability, which exposes only configuration identities, storage posture, exact handler bindings, publication-fence verification and supervisor readiness.

## Deployment model

The first supported local-first v1 installation targets one trusted daemon that runs as the installing user and may own writable local Git, journal and artifact handles. Trusted in-process components are inside this boundary. Model-generated code, repository scripts and plug-ins are not trusted owner components. This profile does not isolate its stores from hostile code that runs with the installing user's privileges, does not authenticate individual function calls, and does not resist tampering by that code.

A separately privileged owner may be considered as an optional later installation profile. The first v1 does not require it, and the owner path is not implemented or accepted. This design choice does not authorize source-content scanning, model or provider calls, credential changes, push, deployment, publication or release.

The historical-packet startup refusal and the prepared-to-success refusal stay in place until replacements prove all of the following:

- exact owner binding;
- audited route authorization;
- live lease and source checks;
- admission and write fencing;
- safe handling of uncertain partial effects;
- durable recovery, including an interruption after candidate persistence followed by a restart, with no duplicate dispatch and no unverified promotion.

The deployment architecture uses a trusted control plane with local state, content-free task notifications, policy evaluation and scoped remote workers. The trusted CLI, snapshot, receipt, daemon, control-plane and remote-worker boundaries are implemented in Go.

OpenTelemetry observability, a Docker Compose profile for a single operator, and Helm charts or Kubernetes manifests for larger installations are planned, with no code, manifests or charts in the tree. None of this is a released deployment. The check sandbox for repository tests runs on Linux and Windows. Remote model providers work with any build that has its secret scan helper, and the packaged install is Linux amd64 only (see [platforms](platforms.md)).

## Non-goals

Open Trestle does not aim to provide:

- hidden provider fallback for restricted repositories;
- running repository commands other than the fixed test commands of the repository checks;
- source mutation, merge, deployment or external reporting by default;
- unrestricted third-party plugins;
- dynamic testing of public, third-party or unspecified targets.
