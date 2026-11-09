# Model candidate generation

`handlers/model.GenerationHandler` connects a durable context packet to the policy-approved provider gateway. It performs one authorized provider attempt, admits only evidence-bound candidates, records route audit events, and stores one protected candidate artifact.

## Durable authority

The context-assembly dependency produces a `model-generation-input` artifact. The candidate-generation task receives that exact successful dependency output through `TaskExecutionRequest`; its static plan input remains a content-addressed recipe identity.

A `model-generation-input` binds:

- the exact review scope and context artifact
- the context packet identity and required candidate schema
- the immutable review snapshot and its supported ranges
- the host-issued evidence allowlist
- one complete `RouteAttemptAuthorization`

`NewGenerationInput` accepts an already validated `review.ContextPacket`. It verifies that the context artifact contains the exact provider request bytes, that those bytes hash to the context identity, and that the authorization binds the same request and review scope. `NewGenerationInputArtifact` preserves the context artifact's classification, protection, and expiry.

At execution time, the handler reads both artifacts through the scoped store and repeats these checks with `review.ValidateContextPacketRequest`. Repository source and recalled memory remain labeled data. Only host-issued source evidence can support candidate claims.

The provider adapter sends the context bytes as the user message and `review.TrustedModelRequestInstructions` as the system channel. For a version 8 context that is the pinned host contract plus, when a specialist is bound, the catalog-exact skill text from the embedded profile catalog. The context itself carries no instruction prose: it binds the contract by `instructions_identity` and the profile by identity fields only. See the [prompt-injection boundary](prompt-injection-boundary.md).

## Provider execution

The handler identity includes the immutable `RouteDispatcherCatalog` identity. Dispatch resolves only the adapter ID in the authorization. Before releasing context bytes, the handler requires an existing route-selection audit event and records an idempotent route-attempt claim. It then records the typed dispatch outcome and pessimistic cost reconciliation for both success and failure.

A model task must declare `max_attempts: 1`. Generic control-plane retries cannot mint a new route authorization, reserve another budget, or prove replay safety. The GitHub planner applies this rule to candidate-generation and verification tasks. Provider retries and fallback require a separately authorized route continuation, not a repeated task lease.

Ambiguous transport outcomes therefore remain visible as claimed attempts with closed audit lineage. A process crash between provider dispatch and terminal audit recording does not cause an automatic replay.

A successful response is admitted only when:

- it is one complete structured `review.v1` response
- it conforms to the candidate schema its context requests: `model-candidate-batch-v2` for a version 8 context (and a recorded version 7 context), `model-candidate-batch-v1` for a recorded earlier context (`review.ParseContextCandidateBatch`)
- every cited source and evidence ID was in the context packet
- every claimed range is covered by the immutable snapshot and cited evidence
- semantic duplicate findings are absent
- reconciled cost does not exceed the authorized budget

A candidate whose `source_range` names a `repository_context` source is dropped from the admitted batch, not treated as a failure: the remaining candidates are admitted with contiguous ordinals, and the drop count is bound into the batch identity and durable encoding (`repository_context_anchor_omitted`, absent when zero). From context version 8 a candidate located in a `removed_lines` source is a base-side finding: its lines are base lines inside that source, it records the source's `head_line`, and only cited `removed_lines` evidence covers it. Base-line evidence never covers a head location. The durable candidate-batch encoding records `"side":"base"` and `head_line` on such a candidate and on each cited removed_lines binding; see [base-side findings](local-model-review.md#base-side-findings).

Provider reasoning and invalid model output are not persisted as candidates.

## Category and fix guidance

Version 7 and 8 generation ask for `model-candidate-batch-v2`. Each candidate adds a required `category` from a closed set (`correctness`, `security`, `concurrency`, `performance`, `reliability`, `maintainability`, `style`, `documentation`, `testing`) and an optional `fix`: nonblank plain text of at most 256 characters, which always fits the parser's 1024-byte UTF-8 wire bound. Parsing stays strict: a v1 document, a missing, null, or unknown category, an empty, blank, oversized, non-string, or control-character fix, and any extra member are rejected. Category and fix are bound into the candidate identity (preimage version 2) and the batch identity, and the durable `open-trestle/candidate-batch` encoding uses schema version 2 for such batches. Both remain untrusted model output: category is advisory, and the fix is guidance for a person, never a patch, command, or automatic edit.

The generation input records the context's `output_schema_identity` (v1 for recorded contexts before version 7, v2 for versions 7 and 8), and both execution and `ParseGenerationResultArtifact` require it to match the context bytes. Readback also requires the admitted batch's schema to match its context version.

## Candidate artifact

The `candidate_batch` artifact contains:

- the canonical admitted `CandidateBatch`
- one successful `RouteExecutionRecord`
- the route authorization, terminal outcome, token usage, cost settlement, and normalized output receipt
- exact context and response lineage

Its provenance includes the task input, context, candidates, authorization, outcome, reconciliation, output receipt, and route execution. `ParseGenerationResultArtifact` requires the exact input and context artifacts and revalidates scope, classification, protection, provenance, candidates, route records, and canonical encodings.

The handler can be wrapped in `artifactvalidation.ValidatedTaskHandler` with `task_input` and `candidate_batch` kinds.

## Published schemas

- `schemas/artifact/route-attempt-authorization-v1.schema.json`
- `schemas/artifact/route-execution-record-v1.schema.json`
- `schemas/artifact/candidate-batch-v1.schema.json`, `schemas/artifact/candidate-batch-v2.schema.json` (categorized) and `schemas/artifact/candidate-batch-v3.schema.json` (uncategorized, recording removed base lines)
- `schemas/artifact/model-generation-input-v1.schema.json` (candidate schema v1 or v2), `schemas/artifact/model-generation-input-v3.schema.json` (sanitized) and `schemas/artifact/model-generation-input-v4.schema.json` (unsanitized, with `removed_lines` evidence)
- `schemas/review/model-candidate-batch-v1.schema.json` (recorded contexts before version 7)
- `schemas/review/model-candidate-batch-v2.schema.json` (version 7 and 8 contexts)
- `schemas/artifact/model-generation-result-v1.schema.json`
