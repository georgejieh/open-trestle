# Public architecture

## Purpose

Open Trestle is a review-evidence runtime. It produces review results only after it can bind a result to an immutable change, repository-scoped policy, tool or model route, and supporting evidence.

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

### Model routing

Every model request has a policy envelope containing tenant and repository scope, privacy classification, permitted provider zones, required capabilities, time and cost budgets, and logging rules. A local-only request cannot silently fall back to a remote route.

### Execution

Repository files, issue text, CI definitions, logs, analyzer output, and model output are untrusted data. Commands come only from versioned adapters with a narrow argument grammar. Dynamic validation is disabled by default and requires explicit authorization, a permitted target, isolated execution, bounded resources, default-deny networking, and a durable receipt.

### Publication

A source-control comment or check is a rendering of the canonical result, not the system of record. The publisher validates the current head revision, evidence links, finding fingerprint, policy outcome, and duplicate state before an external write.

## Integration model

Open Trestle supports three integration paths:

1. **Event path:** authenticated provider webhooks and service hooks.
2. **Command path:** local terminals, Git hooks, CI jobs, and scripts using a declared Git state or frozen input bundle.
3. **Protocol path:** web, REST, gRPC, LSP, MCP, and ACP clients.

An integration is supported only after it passes common conformance checks for identity, immutable revision selection, cancellation, retry, deduplication, evidence parity, privacy behavior, and safe degradation.

## Deployment model

The target architecture uses a Go control plane, PostgreSQL ledger, S3-compatible artifact storage, NATS JetStream jobs, OPA policy evaluation, OpenTelemetry observability, and isolated runners. Docker Compose supports a single operator. Helm and Kubernetes support larger installations. These are design decisions, not claims of a released deployment.

## Non-goals

- hidden provider fallback for restricted repositories;
- arbitrary repository-command execution;
- default source mutation, merge, deployment, or external reporting;
- unrestricted third-party plugins;
- dynamic testing of public, third-party, or unspecified targets.
