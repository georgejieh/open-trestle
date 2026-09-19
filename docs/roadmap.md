# Delivery roadmap

## Status language

This roadmap distinguishes **planned** work from released capability. Nothing in a planned workstream is available until the project publishes release evidence.

## Planned workstreams

### Foundation

Establish versioned public contracts, repository layout, contribution policy, release policy, and a local-first evidence model.

### Intake and evidence

Build immutable review snapshots, normalized changes, line mapping, repository profiles, source-control event handling, and durable receipts. Define the review outcome contract: the capability target is a comprehensive initial review that remains useful when a real-time human safeguard is unavailable, while external quality claims remain gated on versioned evaluation evidence. A failed required gate is a credible stop signal for human approval, while a pass is only visible coverage of the checks that ran and never a substitute for recommended human review.

The shared change model now admits nonempty, valid, within-budget added text against a canonical empty base, so added Go declarations and exact deterministic findings enter review; empty, binary, removed, and over-limit inputs remain explicit gaps. Expand the bounded semantic impact profile beyond the integrated Go AST adapter and direct-reference context selection. The profile records changed declarations, public API changes, syntactic reference and affected-test candidates, exact base/head and change identities, adapter and graph-schema versions, evidence grades, and coverage gaps. Structural facts may support a verifier; syntactic candidates may prioritize inspection but cannot establish a finding. Expand the approved adapter set deliberately, with explicit abstention for unsupported cases.

### Policy and analysis

Add repository-scoped policy packs, static-analysis adapters, deterministic CI planning, and a provider-neutral model gateway. Build content-addressed review context packets that bind the immutable snapshot, normalized changed symbols and ranges, semantic impact profile, applicable policy, deterministic receipts, and declared limits before model candidate generation. Route only the packet permitted by the request's privacy policy and retain its digest with every candidate and verification result.

Add explicit evidence grades and outcome semantics: verified structural evidence, candidate-only heuristic evidence, incomplete coverage, and abstention. A regex or text fallback may generate a lead but cannot silently claim semantic certainty or support a blocking disposition.

### Review and publication

Typed candidate findings, independent verification, route separation, and duplicate control precede review dispositions and idempotent source-control publication. Publication work must bind the acquired base and head, exact physical source slices, advisory readiness, explicit effect authorization, exclusive claim, fresh head observation, bounded attempt, and terminal result. Retry must retain one operation key, use closed failure classes and delay limits, reacquire the current head, and stop rather than publish against a stale change. Separate inexpensive read-only evidence scouts from bounded candidate generation and independent verification; workers exchange immutable evidence artifacts rather than conversational assertions. Add restartable execution records for intake, snapshot capture, evidence acquisition, analysis, candidate generation, verification, and publication.

Render review results as a human-review queue: verified blocking findings, verified non-blocking findings, cleared gates, incomplete checks, and explicit abstentions. Diagnostic-set version 2 preserves exact verified, rejected, and inconclusive candidate counts. Version 3 binds the validated verification context and carries bounded analyzed, selected, and omitted source counts. Version 4 adds sorted content-free aggregate omission reasons with exact accounting while versions 1 through 3 remain compatible. The retry-safe readiness step materializes that set from durable change and independent-verification lineage with the exact source head revision. Diagnostic-set version 5 now publishes the narrowly scoped static-debug check with exact source-check, analysis-result, change, state, coverage, and match bindings. Web and terminal review queues render its four states as a cleared gate, failed check, incomplete check, or explicit abstention. Only its fully covered zero-match `passed` state is presented as cleared, and never as approval or correctness. Web finding rows now expose their exact diagnostic, source-finding, fingerprint, and evidence-reference lineage through a read-only disclosure without fetching payloads. Gate policy may require a blocking finding to be resolved or explicitly overridden, but a clean run must state that it accelerates human review rather than approving a change.

### Runtime surfaces

The standalone daemon, authenticated HTTP API and client, CLI run operations, foreground terminal interface, headless CI JSON and SARIF, MCP, read-only ACP, and read-only LSP diagnostics share the canonical run and diagnostic contracts. Durable task notifications reduce remote-worker polling, and replay-based supervision closes settled runs automatically. The daemon now embeds an authenticated read-only web console for exact run, task, identity, verified-diagnostic, and content-free runtime inspection. A separate repository-scoped capability gates storage posture, non-secret configuration identities, handler authority, publication-fence state, and supervisor readiness. Repository onboarding, policy administration, provider administration, streaming subscriptions, and production distribution remain planned. The packaged VS Code extension now provides the existing read-only LSP diagnostics with machine-scoped process authority and SecretStorage credentials.

The shared secret-free setup plan defines safe deployment profiles, approved check receipts, and protected CLI initialization and inspection. Receipt-driven checks cover private local storage, PostgreSQL database authority, envelope-encrypted S3 conformance, KMS tenant-key authority, remote-provider authorization, GitHub integration-permission and local webhook-conformance validation, PostgreSQL shared API rate-limit validation, bounded two-instance replica reconciliation, opaque Ed25519-signed offline bundle validation, exact setup backup, local-administrator approval, distinct observer credentials, runtime policy, bounded local inference, and a non-publishing dry run. The local web setup service and keyboard-first terminal use the same protected plan, checker, receipt, and recovery contracts. Their explicit confirmations bind the current plan and keep credentials in request-time server capabilities. Requirements without a configured checker remain pending rather than appearing successful. The remaining guided roadmap covers additional forge adapters, external delivery reachability, broader replica and failover coordination, no-egress enforcement, and governed bundle import. The current signed-bundle check verifies only an opaque file and does not claim archive, SBOM, provenance, or installation validation.

### Governed execution

Add sandboxed, policy-approved verification runners. Dynamic validation remains separately authorized and disabled by default.

### Operations and release

Add installation profiles, backups, restore drills, upgrade and rollback support, signed release artifacts, SBOM and provenance, accessibility, observability, air-gapped distribution, and formal quality evaluation. The deterministic local release-evidence tool now inventories exact artifact bytes, embedded Go runtime modules, and non-development npm lockfile components as checksums and SPDX 2.3-formatted JSON. Its output is unsigned, uses a caller-declared revision and timestamp, and does not establish container-image identity, provenance, vulnerability status, a SLSA level, or production readiness. Signing, attestation publication and verification, vulnerability evidence, and complete release packaging remain planned. A first runnable versioned evaluation now covers only the exact static-debug changed-range rule over eight built-in cases. Its canonical content-free report is retained publicly and reproduced through the real CLI in CI; broader rule, model, calibration, cost, and latency evidence remains planned.

## Release gates

A release candidate must demonstrate:

- exact evidence for every published finding;
- authorization and tenant-isolation negative tests;
- no unapproved provider route, egress, command, or source mutation;
- no blocking finding derived only from model output, heuristic impact evidence, or undeclared/incomplete semantic coverage;
- visible human-review outcome, coverage, and abstention semantics for every supported surface;
- deployment, upgrade, backup, restore, and recovery verification for its supported profile;
- versioned quality evaluation, calibration, cost, latency, and false-positive evidence;
- signed artifacts, SBOM, provenance, vulnerability reporting, and release notes.

## How work becomes public

Public source contains original implementation, public contracts, tests, user documentation, and release evidence. Local research archives, development records, upstream inspection copies, and confidential configuration remain excluded from the public repository.
