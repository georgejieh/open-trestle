# Changelog

All notable changes to released versions of Open Trestle will be documented in this file.

## Unreleased

### Added

- Established the public repository boundary plus governance, contribution, support, and security documentation.
- Added the `trestled` review-run daemon, authenticated HTTP client and API, durable task journals and notifications, scoped remote workers, automatic settled-run finalization, and content-free runtime health and status inspection.
- Added local fixture and loose-object Git inspection, change evidence, and exact static-debug review with deterministic JSON and SARIF output. Nonempty valid added text is reviewed against a canonical empty base; unsupported coverage remains explicit.
- Added verified GitHub webhook intake, immutable source acquisition, integration-permission evidence, and separately authorized required-mode review publication with fresh-head and idempotency fences.
- Added deterministic source-slice evidence, a bounded Go semantic-impact profile, direct-reference context candidates, provider-neutral candidate generation, route-separated independent verification, and retry-safe publication readiness.
- Added human-review queues across the web console and terminal interface, including verified findings, cleared gates, incomplete checks, abstentions, bounded source coverage, omission reasons, and copyable finding lineage.
- Added MCP, read-only ACP, read-only LSP diagnostics, and a packaged VS Code extension that uses machine-scoped process authority and SecretStorage credentials.
- Added protected setup plans and local web and terminal setup flows, with named checks for storage, backup, PostgreSQL authority, envelope-encrypted S3, KMS, provider and GitHub authorization, webhook conformance, shared rate limits, two-instance reconciliation, opaque signed bundles, observer credentials, runtime policy, local inference, and non-publishing dry runs.
- Added exact backup creation and non-overwriting restore, PostgreSQL canonical stores, envelope-encrypted object storage, and configuration identity validation.
- Added a versioned static-debug quality evaluation over eight built-in cases, a canonical public report, and exact CLI reproduction in CI.
- Added deterministic unsigned local release evidence with exact artifact checksums, embedded Go runtime modules, non-development npm lockfile components in SPDX 2.3-formatted JSON, and candidate release notes preserved from a validated changelog section.
- Added a deterministic unsigned Linux amd64 candidate pyz with strict archive verification, no-overwrite staged installation, receipt-bound verification, bounded smoke evidence, rollback, and ownership-preserving uninstall for explicit local evaluation.
- Added a packaged local single-node journey over a real temporary Git repository, with candidate-to-source revision binding, durable daemon review state, CLI/TUI/console inspection, deterministic JSON and SARIF, before-and-after restart browser receipts, bounded process and network output, process-group cleanup, port-rebind proof, and source-state preservation.
- Added bounded same-target candidate upgrades and one-use immediate version rollback with protected old/new generation bindings, caught pre-commit failure restoration, and canonical content-free lifecycle evidence. Crash and power-loss recovery remains unproven.
- Added a planning-only specialist review-profile catalog (`agentprofile`) with nine embedded, content-identified profiles, strict versioned tier-to-route assignments, a deterministic router with explainable difficulty scoring, explicit tier escalation, verifier-independence marking, budget-cap omissions, and `trestle profiles list|plan`. Profiles are candidate-only; plans are not yet dispatched by review runs and never bypass gateway eligibility.

### Changed

- Expanded versioned artifact, diagnostic, readiness, local-Git, setup, and transport contracts with strict offline schema reference and documentation-inventory checks.
- Advanced diagnostic publication to version 5 while preserving earlier versions, binding the exact source check, analysis, change, verification context, coverage, omissions, and review state.
- Added diagnostic version 6 for deterministic observations, with analysis-result and changed-range lineage, schema-aware ACP/TUI/CLI/web semantics, and no independent-verification claim.
- Made web and VS Code distributions reproducible and freshness-checked in CI, with package-local npm policy that separates locked dependency retrieval from automatic audit requests and update checks.
- Sealed packaged alpha verification to a stable output-owned candidate copy and a no-follow working-tree snapshot bounded by entry count and regular-file bytes, including ignored and assume-unchanged files and recorded symlink targets outside `.git`.
- Independently validate phase-bound browser receipts and screenshot files, including strict JSON value types, exact review identities, fatal-zero browser metrics, viewport and PNG image dimensions, PNG structure and CRCs, and on-disk byte digests.

### Fixed

- Refused a signed GitHub webhook body replayed under a new delivery ID with `409 delivery_replayed` in the memory, file, and PostgreSQL inboxes; same-ID redelivery is unchanged. PostgreSQL upgrades refuse new-ID intake while legacy replay keys still require trusted backfill.
- Kept a run open while an optional task still has a retry pending, refused reads of artifacts with an interrupted authorized deletion, and stopped proven unchanged-head deterministic coordinator refusals from permanently quarantining a local scope. Cancellation, persistence, and changed-head refusals remain quarantined.
- Aligned the PostgreSQL run journal with the memory and file journals on owner context-input and prepared-packet guards.
- Classified provider response-body read failures as timeout, cancelled, or transport failures rather than invalid responses, and rejected invalid UTF-8 in OpenRouter and Responses output.
- Preserved historical diagnostic-set identities and exact readback for tied findings, and rejected memory expiry boundaries at or before the Unix epoch.
- Accepted version-5 deletion analysis in publication readiness without changing historical artifact contracts.
- Answered malformed MCP requests under their own id, negotiated newer ACP protocol versions down to version 1, accepted one trailing newline in `runs submit --plan` files, and sized both terminal interfaces to the terminal when `--width` is not given.
- Kept the console session and selected task through a transient refresh failure with a visible alert, opened the selected task from the overview, and fixed task-row overflow, misalignment, input-border contrast, and evidence typography.

### Security

- Updated the Go build toolchain to 1.26.10 and golang.org/x/text to v0.41.0, with the required x/sync v0.22.0 dependency, across both runtime modules and the isolated scanner profile. The product Go minimum remains 1.25.0.
- Added fail-closed validators for untrusted input, size and identity bounds, tenant and authorization scope, provider routes, source bindings, and publication effects.
- Added request-time credential boundaries and protected secret storage, emitted bounded content-free public failures, and disabled incidental npm audit and update-notifier requests during package installation. Vulnerability reporting remains a separate authorized release gate.
