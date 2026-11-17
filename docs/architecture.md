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
  -> repository and change-impact data
  -> one built-in deterministic check and model review (the finder)
  -> verification (a different model)
  -> deterministic judgement: dedupe, rank, pre-existing class, advisory (direct path)
  -> result linked to its sources, with a walkthrough (direct path), or abstention
  -> surface-specific rendering or provider-native publication
```

There are two ways to run this flow.

- The direct path is `trestle local-git model-review`, which `trestle review` and the first review in `trestle init` also run. It executes the review task graph inside the `trestle` process with process-private stores and keeps nothing afterwards.
- The daemon path runs the same handlers inside `trestled` with durable runs. The GitHub webhook planner, `trestle local-git submit-review`, `trestle runs submit` and the MCP `open_trestle.submit_run` tool submit reviews to it.

The TUI, `trestle lsp` and the VS Code extension, the web console and ACP observe one daemon run. They cannot start a review. On both paths the runtime, not the surface, owns authorization, policy, provider routing, execution safety, evidence retention and audit receipts.

Today the deterministic analysis stage runs one built-in rule (`static_debug_output`) and the Go semantic-impact profile. Analyzer adapters that policy approves, such as linters and static analysis, are planned (see the [roadmap](roadmap.md)).

After verification, a direct review runs a deterministic judge stage in the `localreview` package. No model takes part in it. The judge does three things:

- It classifies each verified finding as introduced or pre-existing. A pre-existing finding is anchored only on unchanged lines and cites no evidence of the change.
- It merges duplicates of one defect within a run and across the members of a `--specialists` set.
- It ranks the distinct findings.

A review whose confirmed findings are all low severity or pre-existing is advisory: it keeps its findings but does not block CI. The result also carries a walkthrough built from the recorded artifacts. The daemon path does not run this stage yet. Its diagnostic sets carry the verified findings as the verifier produced them, without rank or class. See [ranked findings and the walkthrough](local-model-review.md#ranked-findings-and-the-walkthrough).

## Control boundaries

### Evidence

The review ledger records the immutable snapshot identity, source ranges, policy versions, adapter versions, route decisions, verifier results and final dispositions. Model output and retrieval results are derived inputs. They cannot create a blocking finding on their own, change a severity, suppress a finding or choose an external action.

### Semantic impact evidence

The runtime builds semantic impact profiles from approved language adapters, and each profile is tied to one snapshot. The Go adapter and the deterministic analysis handler record changed declarations, public API changes, name-based reference candidates and affected-test candidates. They also record explicit gaps in parsing, language support, source and resources. A profile names the exact base and head snapshots, the change model, the digests of the input files, the adapter identity, the graph schema, the evidence grades and the declared coverage.

Each element carries an evidence grade. Two grades exist today:

- `structural` covers validated parse results such as declaration differences. It may support verification.
- `syntactic_candidate` covers name-matched references and affected-test candidates. It may only prioritize inspection.

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

Standard candidate-generation and verification requests may use an approved `private_remote` route only after the host sanitizes every typed text field. The sanitizer runs a pinned Betterleaks v1.8.1 profile and masks each reported zero-based half-open byte span. It then scans the result again in a fresh child process. Dispatch requires the second (residual) scan to finish with no findings. Investigation requests and investigation tool results stay local-only.

The sanitized request and its egress receipt are immutable artifacts. The egress receipt records which request left the host and how it was scanned. It binds these values:

- the identities of the raw and the sanitized request;
- the review scope;
- the field roles and ordinals;
- the completion of the initial and residual scans;
- the scanner profile;
- the exact launcher and worker digests.

It carries content-free spans and rule IDs. It carries no field text, paths, snippets, matches, source digests or Betterleaks fingerprints. The generation or verification handler reloads both artifacts, validates them together and seals an opaque dispatch proof for the exact authorized request and scope. A non-local adapter cannot create that proof, and it cannot accept a raw request through the generic dispatch boundary.

Each scan uses one new child process at fixed root-owned paths, and the launcher replaces itself with the worker. A static, single-threaded launcher enters the Landlock domain before it runs the fixed Go worker. The worker then installs a process-wide TSYNC seccomp filter before it reads the request. The scan is invoked with fixed arguments, cwd `/`, an empty environment, anonymous pipes and compiled binary digests. The boundary denies network access, filesystem changes, further execution, namespaces, mounts and tracing.

The boundary accepts at most 256 UTF-8 fields and 2 MiB decoded in total. Any of the following blocks dispatch and leaves no partial result: a five-second worker deadline, a six-second parent watchdog, an incomplete scan, a resource limit, abnormal output, or a residual finding. This protects against unprivileged replacement and worker escape paths in the declared Linux boundary. It does not protect against a compromised host root or kernel. Each scan pays the cost of a new launcher and worker, because there is no process pool.

This is a narrow confidentiality control, not full secret detection, and the sanitized text still leaves the host for a remote route. For what the scanner misses, see [privacy](privacy.md) and the scanner section of [operations](operations.md).

### Execution

Repository files, issue text, CI definitions, logs, analyzer output and model output are treated as data, not instructions (see the [prompt-injection boundary](prompt-injection-boundary.md)). Commands come only from versioned adapters with a narrow argument grammar. Dynamic validation is off by default. It needs authorization, a permitted target, isolated execution, resource limits, default-deny networking and a durable receipt.

Read-only evidence work may share immutable, content-addressed artifacts across analyzers and review workers. Cache keys include the snapshot, adapter version, policy version and request parameters. Candidate generation, verification and publication do not rely on another worker's conversational summary. Restartable execution records capture the state of intake, snapshot capture, evidence acquisition, analysis, candidate generation, verification and publication.

All transports use one immutable review-run task graph. The graph fixes the exact inputs, the approved handlers, the dependencies, the attempt limits, the retry delays and the lease durations. The control plane keeps the following guarantees:

- Workers receive short-lived capabilities, and the secrets in them are never written to the journal.
- The control plane rebuilds state from canonical hash-chained events.
- It rejects stale workers through attempt fencing.
- It passes terminal dependency failures downstream without running the downstream work.
- It resumes expired leases after a restart.

External publication stays inside its stricter single-operation idempotency boundary rather than relying on generic task retry. The GitHub adapter adds a durable per-attempt dispatch guard, because the create-review endpoint has no documented native idempotency key.

PostgreSQL queue rows and wake-ups from `LISTEN`/`NOTIFY`, which carry no payload, reduce polling latency. Workers still acquire task leases that the journal fences. PostgreSQL metadata mode also replaces the process-local API guards with fixed windows based on the database clock. Existing authority keys serialize by row lock, and new-key cardinality serializes by namespace advisory lock. Only domain-separated key digests, the configuration identity, the count and the time bounds are stored. If the database fails, the request is denied as unavailable.

The Kubernetes HA setup probe can use two stores over the verified database. With them it proves shared plan visibility, idempotent notification scheduling, fenced task acquisition, cross-instance completion and one terminal event. It also proves retry-safe fixture cleanup. Reconciliation rebuilds notices after a missed signal or a process restart. The same supervisor derives terminal success or failure from the replayed task state and appends one compare-and-append terminal event. A process stop therefore cannot leave a settled run permanently active.

### Publication

A source-control comment or check is a rendering of the canonical result, not the system of record. Before an external write, the publisher validates the current head revision, the evidence links, the finding fingerprint, the policy outcome and the duplicate state.

Publication readiness is advisory and cannot grant an external effect. An external write requires all of the following:

- a live capability authorization;
- an acquired source and context binding;
- an exclusive operation claim;
- an attempt authorization;
- a fresh reconciliation against the current head;
- a publisher implementation that guarantees deduplication by the host-issued operation key.

Each successful and each failed attempt is recorded once. Automatic retry is limited to closed transient classifications. A retry keeps the same operation key, honors the bounded delay, reacquires the current head and stops at the configured attempt limit. A stale head always stops the operation and requires a new snapshot and plan.

Results show a human-facing review disposition next to the coverage: verified blocking findings, verified non-blocking findings, cleared gates, incomplete checks and explicit abstentions. A publication must not imply that a clear or passing disposition replaces human approval.

### Guided setup

The setup core turns the deployment posture and readiness checks into a versioned, resumable plan that holds no secrets. The plan comes with an immutable checker catalog and a replayable receipt ledger.

The CLI initializes and inspects protected state, validates local storage and the posture of observer credentials, requires exact runtime policy identities and a named approval, and runs a bounded, provider-neutral dry run with no network or publication authority. A loopback-only guided web service and a keyboard-first terminal workflow use the same plan and receipt contracts.

Air-gapped setup can stream one opaque local file and verify its exact SHA-256 digest, byte count and Ed25519 signature. It does this without extraction, import, execution or network access. The setup surfaces use secure defaults, show the consequence of less-safe choices, keep recovery state and remain usable over SSH and in air-gapped environments.

## Integration model

Open Trestle has three integration paths:

1. The event path uses authenticated GitHub webhooks. Webhooks and service hooks from other forges are planned.
2. The command path covers local terminals, CI jobs and scripts that use a declared Git state or a local fixture file. Git-hook integration is planned.
3. The protocol path covers web console, REST, LSP, MCP and ACP clients. A gRPC API is planned.

The [roadmap](roadmap.md) lists the planned items. None of them has code in the tree.

An integration counts as supported only after it passes common conformance checks for identity, immutable revision selection, cancellation, retry, deduplication, evidence parity, privacy behavior and safe degradation.

The current terminal interface is a foreground observer over authenticated daemon receipts and canonical review diagnostics. It tells apart two kinds of result. Finding contracts in versions 1 through 5 and 8 are verified findings. Version 6 holds unverified deterministic observations. Version 7 is the final full-review result and keeps the two as separate sections. The terminal interface has no worker, model, source, policy or publication authority. Its only change to state is a run cancellation, which you must confirm and which goes through the canonical API.

The embedded web console is a read-only, same-origin client. It reads exact run receipts, canonical review diagnostics and content-free runtime status for one repository. It shows versions 1 through 5 and 8 as verified-finding state. It shows version 6 as deterministic observations that need human review, not as verified findings. A run that ended successfully in the terminal sense stays secondary to the review disposition.

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

The broader deployment architecture uses a trusted control plane, PostgreSQL ledgers and content-free task notifications, S3-compatible artifact storage, a replaceable notification boundary, policy evaluation and scoped remote workers. The trusted CLI, snapshot, receipt, daemon, control-plane, PostgreSQL, S3-compatible storage and remote-worker boundaries are implemented in Go.

The following parts are planned design with no code, manifests or charts in the tree: OpenTelemetry observability, isolated sandbox runners, a Docker Compose profile for a single operator, and Helm charts or Kubernetes manifests for larger installations (see the [roadmap](roadmap.md)). The setup planner names a `kubernetes_ha` profile and can probe two stores over one verified PostgreSQL database. That is a setup check, not a Kubernetes deployment. None of this is a released deployment. Today only Linux amd64 has a tested path, and remote model providers work only with the packaged Linux amd64 install (see [platforms](platforms.md)). Support for macOS and Windows is planned for the first release.

The current storage foundation includes a conditional S3-compatible backend and a client-side envelope store. It requires versioned objects and a tenant-aware key provider that the operator supplies. It is not a complete deployed storage profile until it has a production KMS provider, a canonical metadata database, a bucket policy, recovery tooling and deployment conformance tests.

## Non-goals

Open Trestle does not aim to provide:

- hidden provider fallback for restricted repositories;
- arbitrary repository-command execution;
- source mutation, merge, deployment or external reporting by default;
- unrestricted third-party plugins;
- dynamic testing of public, third-party or unspecified targets.

### Route capacity authority

A route is eligible only when its approved capabilities satisfy both the policy minimums and the full authorized request envelope. `max_output_tokens` cannot exceed the route's output capacity, and `estimated_input_tokens + max_output_tokens` cannot exceed its context capacity. These checks run before ranking and are validated again on both the eligibility result and the content-free selection receipt. Selection candidate scores keep the approved context and output capacities, so receipt validation does not depend on a registry that may change.
