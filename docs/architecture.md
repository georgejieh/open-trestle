# Public architecture

## Purpose

Open Trestle is a review-evidence runtime. It produces review results only after it can bind a result to an immutable change, repository-scoped policy, tool or model route, and supporting evidence.

Open Trestle performs an initial review sweep, not final human approval. Its capability target is a comprehensive, evidence-led review that remains useful when a real-time human safeguard is unavailable; the runtime should be designed to identify the routine defects and relevant context a careful human reviewer would expect to encounter. That target is not a claim of human-equivalent review quality: any external quality claim requires versioned evaluation evidence. A failed required gate is intended to be a credible reason to stop approval until the finding is resolved or a human records an override. A passed run means only that the checks represented by its visible coverage completed without a verified blocking result. It does not prove correctness, security, maintainability, or fitness for the product. Human review remains recommended after a pass, where it can spend less time rediscovering routine evidence and more time exercising judgment.

## Canonical flow

```text
source-control event, CI job, local Git, IDE, or agent host
  -> authenticated transport adapter
  -> versioned review envelope
  -> immutable review snapshot
  -> repository and change-impact evidence
  -> policy-approved analyzers and bounded model review
  -> independent verification and deduplication
  -> evidence-linked result or explicit abstention
  -> surface-specific rendering or provider-native publication
```

Each integration submits the same canonical review request. The runtime, not the integration, owns authorization, policy, provider routing, execution safety, evidence retention, and audit receipts.

## Control boundaries

### Evidence

The canonical review ledger records immutable snapshot identity, source ranges, policy versions, adapter versions, route decisions, verifier results, and final dispositions. Model output and retrieval results are derived inputs. They cannot independently create a blocking finding, change severity, suppress a finding, or select an external action.

### Semantic impact evidence

The runtime derives snapshot-bound semantic impact profiles from approved language adapters. The bounded Go adapter and deterministic analysis handler record changed declarations, public API changes, name-based reference candidates, affected-test candidates, and explicit parser, language, source, and resource gaps. Profiles bind the exact base and head snapshots, change model, input file digests, adapter identity, graph schema, evidence grades, and declared coverage. Structural declaration differences may support verification. Syntactic reference candidates may only prioritize inspection.

Each element carries an evidence grade. Compiler or language-server facts and validated structural parse results may support verification. Heuristics such as historical co-change identify review targets only; they cannot independently create, raise, or verify a finding. Text or regex fallback may discover candidates but cannot be represented as semantic proof. Unsupported languages, generated content, incomplete resolution, and adapter failure produce explicit coverage gaps or abstentions rather than a silent downgrade in confidence.

The runtime assembles a compact, content-addressed review context packet from the immutable snapshot, normalized changed symbols and ranges, relevant impact evidence, applicable policy, deterministic analyzer receipts, and known coverage limits. A model receives only the packet its approved route permits. The packet digest is retained with the candidate and verifier records so the basis of a conclusion is reproducible.

An acquired review snapshot binds the exact repository, base and head revisions, verified acquisition receipts, complete file manifests, manifest delta, and requested changed ranges. Each source excerpt in a production model packet carries a content-addressed slice proof. The proof checks the full-file digest and confirms that the excerpt is the exact byte sequence for its declared physical lines. The runtime records the acquired snapshot, source selection, context packet, and slice binding before candidate generation. A context packet without this lineage can support local inspection, but it cannot reach the publication effect boundary.

### Model routing

Every model request has a policy envelope containing tenant and repository scope, privacy classification, permitted provider zones, required capabilities, time and cost budgets, and logging rules. A local-only request cannot silently fall back to a remote route.

### Execution

Repository files, issue text, CI definitions, logs, analyzer output, and model output are untrusted data. Commands come only from versioned adapters with a narrow argument grammar. Dynamic validation is disabled by default and requires explicit authorization, a permitted target, isolated execution, bounded resources, default-deny networking, and a durable receipt.

Read-only evidence work may share immutable, content-addressed artifacts across analyzers and review workers. Cache keys bind the snapshot, adapter version, policy version, and request parameters. Candidate generation, verification, and publication do not rely on another worker's conversational summary as authority. Restartable execution records capture intake, snapshot capture, evidence acquisition, analysis, candidate generation, verification, and publication state.

All transports use one immutable review-run task graph. The graph binds exact inputs, approved handlers, dependencies, attempt limits, retry delays, and lease durations. Workers receive short-lived capabilities whose secrets are never written to the journal. The control plane reconstructs state from canonical hash-chained events, rejects stale workers through attempt fencing, propagates terminal dependency failures without executing downstream work, and resumes expired leases after restart. External publication remains inside its stricter single-operation idempotency boundary rather than relying on generic task retry. The GitHub adapter adds a durable per-attempt dispatch guard because the create-review endpoint has no documented native idempotency key. PostgreSQL queue rows and empty-payload `LISTEN`/`NOTIFY` wake-ups reduce polling latency, but workers still acquire journal-fenced task leases. PostgreSQL metadata mode also replaces process-local API guards with database-clock fixed windows. Existing authority keys serialize by row lock; new-key cardinality serializes by namespace advisory lock. Only domain-separated key digests, configuration identity, count, and time bounds persist. Database failure denies the request as unavailable. The Kubernetes HA setup probe can use two independent stores over the verified database to prove shared plan visibility, idempotent notification scheduling, fenced task acquisition, cross-instance completion, one terminal event, and exact retry-safe fixture cleanup. Bounded reconciliation reconstructs notices after missed signals or process restart. The same supervisor derives terminal success or failure from replayed task state and appends one compare-and-append terminal event, so a process stop cannot leave a settled run permanently active.

### Publication

A source-control comment or check is a rendering of the canonical result, not the system of record. The publisher validates the current head revision, evidence links, finding fingerprint, policy outcome, and duplicate state before an external write.

Publication readiness is advisory and cannot grant an external effect. An external write requires a live capability authorization, an acquired source and context binding, an exclusive operation claim, a bounded attempt authorization, a fresh current-head reconciliation, and an exact publisher implementation that guarantees deduplication by the host-issued operation key. Successful and failed attempts are recorded once. Automatic retry is limited to closed transient classifications, preserves the same operation key, honors bounded delay, reacquires the current head, and stops at the configured attempt limit. A stale head always stops the operation and requires a new snapshot and plan.

Results render a human-facing review disposition alongside coverage: verified blocking findings, verified non-blocking findings, cleared gates, incomplete checks, and explicit abstentions. A publication must not imply that a clear or passing disposition replaces human approval.

### Guided setup

The setup core turns deployment posture and readiness checks into a versioned, resumable, secret-free plan with an immutable checker catalog and replayable receipt ledger. The CLI initializes and inspects protected state, validates local storage and observer credential posture, requires exact runtime policy identities and named approval, and executes a bounded provider-neutral dry run without network or publication authority. A loopback-only guided web service and keyboard-first terminal workflow use the same plan and receipt contracts. Air-gapped setup can stream one opaque local file and verify its exact SHA-256 digest, byte count, and Ed25519 signature without extraction, import, execution, or network access. The setup surfaces use secure defaults, show the consequence of less-safe choices, preserve recovery state, and remain usable over SSH and in air-gapped environments.

## Integration model

Open Trestle supports three integration paths:

1. **Event path:** authenticated provider webhooks and service hooks.
2. **Command path:** local terminals, Git hooks, CI jobs, and scripts using a declared Git state or frozen input bundle.
3. **Protocol path:** web, REST, gRPC, LSP, MCP, and ACP clients.

An integration is supported only after it passes common conformance checks for identity, immutable revision selection, cancellation, retry, deduplication, evidence parity, privacy behavior, and safe degradation.

The current terminal interface is a foreground observer over authenticated daemon receipts and verified diagnostics. It has no worker, model, source, policy, or publication authority. Its only mutation is an explicitly confirmed run cancellation through the canonical API.

The embedded web console is a read-only same-origin client of exact run receipts, verified diagnostics, and repository-scoped content-free runtime status. It keeps bearer credentials only in page memory, rejects cross-scope and malformed responses, renders repository-controlled text without markup interpretation, and exposes no cancellation, worker, model, source, policy mutation, or publication capability. Runtime inspection uses a separate capability and exposes only configuration identities, storage posture, exact handler bindings, publication-fence verification, and supervisor readiness.

## Deployment model

The deployment architecture uses a trusted control plane, PostgreSQL ledgers and content-free task notifications, S3-compatible artifact storage, a replaceable notification boundary, policy evaluation, OpenTelemetry observability, and isolated runners. The trusted CLI, snapshot, receipt, daemon, and control-plane boundaries are currently implemented in Go. Docker Compose supports a single operator. Helm and Kubernetes support larger installations. These are design decisions, not claims of a released deployment.

The current storage foundation includes a conditional S3-compatible backend and client-side envelope store. It requires versioned objects and an operator-supplied tenant-aware key provider. It is not a complete deployed storage profile without a production KMS provider, canonical metadata database, bucket policy, recovery tooling, and deployment conformance evidence.

## Non-goals

- hidden provider fallback for restricted repositories;
- arbitrary repository-command execution;
- default source mutation, merge, deployment, or external reporting;
- unrestricted third-party plugins;
- dynamic testing of public, third-party, or unspecified targets.

### Route capacity authority

A route is eligible only when its approved capabilities satisfy both policy minimums and the full authorized request envelope. `max_output_tokens` cannot exceed the route output capacity, and `estimated_input_tokens + max_output_tokens` cannot exceed its context capacity. These checks run before ranking and are revalidated on both the eligibility result and the content-free selection receipt. Selection candidate scores retain approved context and output capacities so receipt validation does not depend on mutable registry access.
