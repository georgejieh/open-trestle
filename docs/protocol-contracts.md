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
- `schemas/secret-scanner/secret-scan-request-v1.schema.json`
- `schemas/secret-scanner/secret-scan-response-v1.schema.json`

The investigation output schema uses a closed `oneOf`: a candidate batch or one host-defined snapshot tool call. A valid proposal is not permission to execute a tool. Runtime parsing, the retained model response, source bindings, and policy limits still govern admission.

Control-plane schemas:

- `schemas/controlplane/review-run-plan-v1.schema.json`
- `schemas/controlplane/local-deterministic-review-intent-v1.schema.json`
- `schemas/controlplane/local-full-review-intent-v1.schema.json`
- `schemas/controlplane/review-run-event-v1.schema.json`
- `schemas/controlplane/review-run-event-v2.schema.json`
- `schemas/controlplane/review-run-event-v3.schema.json`
- `schemas/controlplane/review-run-event-v4.schema.json`
- `schemas/controlplane/review-run-event-v5.schema.json`
- `schemas/controlplane/review-run-receipt-v1.schema.json`
- `schemas/controlplane/review-run-receipt-v2.schema.json`
- `schemas/controlplane/review-task-lease-v1.schema.json`
- `schemas/controlplane/review-task-completion-v1.schema.json`
- `schemas/controlplane/review-task-completion-v2.schema.json`
- `schemas/controlplane/task-claim-request-v1.schema.json`
- `schemas/controlplane/task-completion-request-v1.schema.json`
- `schemas/controlplane/task-notification-v1.schema.json`
- `schemas/controlplane/task-notification-lease-v1.schema.json`
- `schemas/controlplane/task-notification-claim-request-v1.schema.json`
- `schemas/controlplane/api-response-v1.schema.json`
- `schemas/controlplane/runtime-status-response-v1.schema.json`

The local file-backed full-review context worker emits a v3 `context_abstention_prepared` event before writing any abstention artifact. Its bounded canonical artifact envelope contains omission metadata only, not repository source bytes or a model claim. Recovery must verify the exact scope, plan, task, provenance, failure class, and artifact identity before a v2 failed-task event links the result. Old v1 no-output failures and v2 linked failures remain readable. The PostgreSQL journal's current 1 MiB event limit does not qualify v3; local full review rejects nonlocal stores.

A v4 `context_packet_prepared` event stores only packet artifact metadata, exact identity, creation/expiry, source root/snapshot, upstream dependencies, scope, task, attempt, exact lease identity, original lease event identity, and lease token identity. The file journal fsyncs this checkpoint before a caller may put packet bytes. This first checkpoint cannot settle success, renew or reclaim the lease, or authorize dispatch. Trusted recovery may terminally fail an expired packet-only preparation with a policy-class, no-output task failure. It cannot treat the preparatory packet as output. This does not implement the later sanitized-input checkpoint or verify packet bytes against immutable upstream sources. v1/v2/v3 event bytes remain unchanged.

Artifact schemas:

- `schemas/artifact/runtime-artifact-v1.schema.json`
- `schemas/artifact/context-abstention-v1.schema.json`
- `schemas/artifact/sanitized-model-request-v1.schema.json`
- `schemas/artifact/sanitized-egress-receipt-v1.schema.json`
- `schemas/artifact/artifact-deletion-authorization-v1.schema.json`
- `schemas/artifact/artifact-deletion-receipt-v1.schema.json`
- `schemas/artifact/source-acquisition-input-v1.schema.json`
- `schemas/artifact/source-acquisition-input-v2.schema.json`
- `schemas/artifact/source-file-v1.schema.json`
- `schemas/artifact/source-snapshot-v1.schema.json`
- `schemas/artifact/change-model-result-v1.schema.json`
- `schemas/artifact/deterministic-evidence-result-v1.schema.json`
- `schemas/artifact/deterministic-evidence-result-v2.schema.json`
- `schemas/artifact/deterministic-evidence-result-v3.schema.json`
- `schemas/artifact/deterministic-evidence-result-v4.schema.json`
- `schemas/artifact/semantic-impact-profile-v1.schema.json`
- `schemas/artifact/memory-retrieval-result-v1.schema.json`
- `schemas/artifact/publication-readiness-result-v1.schema.json`
- `schemas/artifact/publication-readiness-result-v2.schema.json`
- `schemas/artifact/publication-content-scan-receipt-v1.schema.json`
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
- `schemas/evaluation/deterministic-corpus-candidate-result-v1.schema.json`
- `schemas/evaluation/deterministic-corpus-performance-observation-v1.schema.json`

Runtime authority schemas:

- `schemas/runtime/runtime-route-inventory-v1.schema.json`
- `schemas/runtime/runtime-policy-v1.schema.json`
- `schemas/runtime/runtime-policy-v2.schema.json`
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

Runtime policy v1 keeps its original wire and identity contract. Its `preferred_route_record_identities` are ordered ranking hints, not a verifier-route grant. Runtime policy v2 requires `verification_route_record_identity`, an exact nonzero record identity in the bound route inventory. It binds that grant and version into a distinct policy identity. The local route-pair resolver accepts only the v2 explicit grant, plus a generation pin, and checks local eligibility and independence before producing a preliminary pair. It never derives verifier authority from the preferred-route list. This startup pair is not authorization for an actual sanitized request, does not permit fallback, and does not enable dispatch by itself. Previously persisted v1 plans and policy identities remain readable. New full-local admission requires an explicit v2 verifier grant; an unbound or ineligible pair fails startup before a run is admitted. This is operator-configuration refusal, not the explicit durable abstention required for verifier loss or coverage gaps after admission. That later per-run outcome and the actual-request verifier gate are not implemented by startup validation.

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
- `schemas/diagnostics/deterministic-diagnostic-set-v6.schema.json`

Webhook schemas:

- `schemas/webhook/verified-delivery-v1.schema.json`
- `schemas/webhook/response-v1.schema.json`

The daemon API response carries exactly one run receipt, immutable run plan, task lease, task-notification lease, diagnostic set, or sanitized error. Diagnostic versions 1 through 5 contain independently verified finding contracts. Version 6 contains deterministic observations and does not represent them as verified findings. Nested contracts are referenced by their schema URNs.

Every schema has a stable versioned `urn:open-trestle:schema:...` identity, rejects unknown object properties, and declares explicit bounds. The plan, receipt, event, lease, and completion encoders have repository tests that compare their canonical top-level record shape and constants with these documents.

A `review-task-lease` and a `task-notification-lease` contain bearer secrets. It is suitable only for the authorized worker transport. Do not place it in logs, diagnostics, URLs, model context, audit events, or public state. `review-run-receipt` and `review-run-event` are intentionally secret-free.

The v5 `context_input_prepared` event advances the exact v4 packet checkpoint under the same task, attempt, lease and worker. Its bounded public descriptor is untrusted claims about artifact envelopes and route/scanner identities. It is not proof of an actual scanner run, route selection, audit join, stored sanitized request, receipt, generation input or authorization. It contains no recoverable request, receipt, input, authorization, or repository bytes. Neither this event nor a route-audit subject grants task success or model authority. Ordinary completion, lease renewal and expiry reclaim remain blocked. Trusted recovery can append a no-output policy failure after lease expiry; there is no v5 success settlement API until independent exact-byte and selection proof is specified and verified. Existing v1-v4 encodings and v3 abstention behavior remain unchanged.

Consumers must treat all strings, tool descriptions, repository material, and webhook fields as untrusted data even after structural validation. They must not infer publication authority, provider access, or policy approval from a schema-valid document. Those decisions require the corresponding content-addressed policy and effect receipts.
