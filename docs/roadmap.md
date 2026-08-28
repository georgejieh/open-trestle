# Delivery roadmap

## Status language

This roadmap distinguishes **planned** work from released capability. Nothing in a planned phase is available until the project publishes release evidence.

## Planned phases

### Foundation

Establish versioned public contracts, repository layout, contribution policy, release policy, and a local-first evidence model.

### Intake and evidence

Build immutable review snapshots, normalized changes, line mapping, repository profiles, change-impact profiles, source-control event handling, and durable receipts.

### Policy and analysis

Add repository-scoped policy packs, static-analysis adapters, deterministic CI planning, and a provider-neutral model gateway.

### Review and publication

Add typed candidate findings, independent verification, confidence and duplicate control, review dispositions, and idempotent source-control publication.

### Runtime surfaces

Add the standalone daemon, CLI, terminal interface, API, headless CI transport, web console, IDE bridges, MCP, ACP, and LSP transport layers.

The web console will include a first-class guided setup wizard for non-technical operators. It will use secure defaults and progressive disclosure to select a local, controlled-hybrid, Kubernetes/HA, or air-gapped profile; configure storage, recovery, identity, inference privacy, and least-privilege integrations; validate a dry-run before publication is possible; and explain blocked or unsafe choices plainly. Equivalent resumable setup is planned for the CLI and terminal interface.

### Governed execution

Add sandboxed, policy-approved verification runners. Dynamic validation remains separately authorized and disabled by default.

### Operations and release

Add installation profiles, backups, restore drills, upgrade and rollback support, signed release artifacts, SBOM and provenance, accessibility, observability, air-gapped distribution, and formal quality evaluation.

## Release gates

A release candidate must demonstrate:

- exact evidence for every published finding;
- authorization and tenant-isolation negative tests;
- no unapproved provider route, egress, command, or source mutation;
- deployment, upgrade, backup, restore, and recovery verification for its supported profile;
- versioned quality evaluation, calibration, cost, latency, and false-positive evidence;
- signed artifacts, SBOM, provenance, vulnerability reporting, and release notes.

## How work becomes public

Public source contains original implementation, public contracts, tests, user documentation, and release evidence. Local research archives, orchestration records, upstream inspection copies, prompt material, and agent fingerprints remain excluded from the public repository.
