# Protocol contracts

Open Trestle publishes JSON Schema 2020-12 documents for transport implementers. Repository validation resolves every local fragment and internal Open Trestle URN reference offline; unknown targets, missing fragments, malformed JSON Pointers, and external schema references fail the test suite. Runtime parsers remain the enforcement authority. Setup-plan parsers replay the embedded checker catalog and receipt chain before accepting readiness. They additionally require canonical field order and encoding, content-addressed identity recomputation, sorted collections, graph safety, state-transition semantics, tenant lineage, and bounded byte size. Passing a schema alone never grants authority. Runtime-status schemas constrain years 1970 through 9999 and Gregorian leap days. Runtime-status parsers also enforce calendar-valid UTC millisecond timestamps, repository projection, unique sorted handler kinds and components, backend compatibility, and conditional review, route, worker, and publication rules that schemas cannot express completely. The canonical internal review-context packet and verification-context packet are schema version 2; counted source omissions are part of their request identities and coverage equations.

Routing, policy, provider, and review schemas:

- `schemas/gateway/review-routing-input-v1.schema.json`
- `schemas/policy/provider-data-constraints-v1.schema.json`
- `schemas/provider/model-requirements-v1.schema.json`
- `schemas/provider/model-capabilities-v1.schema.json`
- `schemas/provider/route-reference-v1.schema.json`
- `schemas/provider/route-capability-declaration-v1.schema.json`
- `schemas/review/model-candidate-batch-v1.schema.json`
- `schemas/review/model-investigation-output-v1.schema.json`
- `schemas/review/model-verification-batch-v1.schema.json`
- `schemas/review/local-git-inspect-result-v1.schema.json`
- `schemas/review/local-git-change-result-v1.schema.json`
- `schemas/review/local-git-change-result-v2.schema.json`
- `schemas/review/local-git-review-result-v1.schema.json`
- `schemas/review/local-git-review-result-v2.schema.json`

The investigation output schema uses a closed `oneOf`: a candidate batch or one host-defined snapshot tool call. A valid proposal is not permission to execute a tool. Runtime parsing, the retained model response, source bindings, and policy limits still govern admission.

Control-plane schemas:

- `schemas/controlplane/review-run-plan-v1.schema.json`
- `schemas/controlplane/review-run-event-v1.schema.json`
- `schemas/controlplane/review-run-receipt-v1.schema.json`
- `schemas/controlplane/review-task-lease-v1.schema.json`
- `schemas/controlplane/review-task-completion-v1.schema.json`
- `schemas/controlplane/task-claim-request-v1.schema.json`
- `schemas/controlplane/task-completion-request-v1.schema.json`
- `schemas/controlplane/task-notification-v1.schema.json`
- `schemas/controlplane/task-notification-lease-v1.schema.json`
- `schemas/controlplane/task-notification-claim-request-v1.schema.json`
- `schemas/controlplane/api-response-v1.schema.json`
- `schemas/controlplane/runtime-status-response-v1.schema.json`

Artifact schemas:

- `schemas/artifact/runtime-artifact-v1.schema.json`
- `schemas/artifact/artifact-deletion-authorization-v1.schema.json`
- `schemas/artifact/artifact-deletion-receipt-v1.schema.json`
- `schemas/artifact/source-acquisition-input-v1.schema.json`
- `schemas/artifact/source-file-v1.schema.json`
- `schemas/artifact/source-snapshot-v1.schema.json`
- `schemas/artifact/change-model-result-v1.schema.json`
- `schemas/artifact/deterministic-evidence-result-v1.schema.json`
- `schemas/artifact/deterministic-evidence-result-v2.schema.json`
- `schemas/artifact/deterministic-evidence-result-v3.schema.json`
- `schemas/artifact/semantic-impact-profile-v1.schema.json`
- `schemas/artifact/memory-retrieval-result-v1.schema.json`
- `schemas/artifact/publication-readiness-result-v1.schema.json`
- `schemas/artifact/publication-input-v1.schema.json`
- `schemas/artifact/publication-receipt-v1.schema.json`
- `schemas/artifact/route-attempt-authorization-v1.schema.json`
- `schemas/artifact/route-execution-record-v1.schema.json`
- `schemas/artifact/model-generation-input-v1.schema.json`
- `schemas/artifact/model-generation-result-v1.schema.json`
- `schemas/artifact/candidate-batch-v1.schema.json`
- `schemas/artifact/verification-batch-v1.schema.json`
- `schemas/artifact/verified-finding-set-v1.schema.json`
- `schemas/artifact/model-verification-result-v1.schema.json`

Evaluation schemas:

- `schemas/evaluation/static-debug-evaluation-result-v1.schema.json`

Runtime authority schemas:

- `schemas/runtime/runtime-route-inventory-v1.schema.json`
- `schemas/runtime/runtime-policy-v1.schema.json`
- `schemas/runtime/configuration-validation-result-v1.schema.json`
- `schemas/runtime/route-inventory-identity-result-v1.schema.json`
- `schemas/runtime/runtime-status-v1.schema.json`
- `schemas/runtime/postgres-admin-result-v1.schema.json`
- `schemas/runtime/postgres-rate-limit-admin-result-v1.schema.json`
- `schemas/runtime/postgres-replica-reconciliation-admin-result-v1.schema.json`
- `schemas/runtime/signed-bundle-admin-result-v1.schema.json`
- `schemas/runtime/signed-bundle-statement-admin-result-v1.schema.json`
- `schemas/runtime/kms-admin-result-v1.schema.json`
- `schemas/runtime/envelope-admin-result-v1.schema.json`
- `schemas/runtime/github-permission-admin-result-v1.schema.json`
- `schemas/runtime/github-permission-admin-result-v2.schema.json`
- `schemas/runtime/github-source-broker-v1.schema.json`
- `schemas/runtime/github-webhook-admin-result-v1.schema.json`

The inventory adds exactly three schemas (79 to 82): the source-broker descriptor v1, configuration-only permission-admin result v2, and integration-only check request v2. The descriptor retains its native 20 fields, `single_host_exclusive` ownership, and explicit token-creation and demand-renewal booleans. Its schema date pattern is structural; native source parsing validates dates and normalizes admitted trailing endpoint slashes. Setup/admin separately require API year >=2000. Schema validation never opens an owner or approves effects.

Setup schemas:

- `schemas/setup/setup-command-result-v1.schema.json`
- `schemas/setup/setup-plan-v1.schema.json`
- `schemas/setup/setup-check-receipt-v1.schema.json`
- `schemas/setup/setup-init-request-v1.schema.json`
- `schemas/setup/setup-check-request-v1.schema.json`
- `schemas/setup/setup-check-request-v2.schema.json`
- `schemas/setup/offline-bundle-signature-statement-v1.schema.json`
- `schemas/setup/setup-session-v1.schema.json`
- `schemas/setup/setup-check-result-v1.schema.json`
- `schemas/setup/setup-error-v1.schema.json`

Integration request v2 has exactly nine required fields: `contract`, `schema_version`, `plan_identity`, `key`, `confirmation`, `approve_integration_permission_authority_identity`, `approve_github_source_broker_authority_identity`, `allow_github_installation_token_creation`, and `approved_by`. Consent must be boolean true, and confirmation is exactly `create GitHub installation token and run integration_permissions_validated`. Credential creation is an explicitly approved effect, not bearer-only authority. The host cap and request approvals remain independent.

Historical integration request v1 remains published but is non-executable; unrelated v1 requests keep their semantics. Current plans, receipts, sessions, and results retain schema 1. Old Ready remains readable and historical, not auto-upcast authority. Migration requires fresh protected state and rerunning all nondeterministic checks, without importing old receipts. The admin v2 output has exactly seven fields: contract, schema version, `configuration_only` status, `identity` operation, and `broker_authority_identity`, `setup_issuance_authority_identity`, and `permission_authority_identity`. It grants no observed or executable authority. See [Setup planning](setup.md#github-integration-permissions) and [local setup API](daemon-api.md#local-setup-api).

Diagnostic schemas:

- `schemas/diagnostics/verified-diagnostic-set-v1.schema.json`
- `schemas/diagnostics/verified-diagnostic-set-v2.schema.json`
- `schemas/diagnostics/verified-diagnostic-set-v3.schema.json`
- `schemas/diagnostics/verified-diagnostic-set-v4.schema.json`
- `schemas/diagnostics/verified-diagnostic-set-v5.schema.json`

Webhook schemas:

- `schemas/webhook/verified-delivery-v1.schema.json`
- `schemas/webhook/response-v1.schema.json`

The daemon API response carries exactly one run receipt, immutable run plan, task lease, task-notification lease, verified diagnostic set, or sanitized error. Nested contracts are referenced by their schema URNs.

Every schema has a stable versioned `urn:open-trestle:schema:...` identity, rejects unknown object properties, and declares explicit bounds. The plan, receipt, event, lease, and completion encoders have repository tests that compare their canonical top-level record shape and constants with these documents.

A `review-task-lease` and a `task-notification-lease` contain bearer secrets. It is suitable only for the authorized worker transport. Do not place it in logs, diagnostics, URLs, model context, audit events, or public state. `review-run-receipt` and `review-run-event` are intentionally secret-free.

Consumers must treat all strings, tool descriptions, repository material, and webhook fields as untrusted data even after structural validation. They must not infer publication authority, provider access, or policy approval from a schema-valid document. Those decisions require the corresponding content-addressed policy and effect receipts.
