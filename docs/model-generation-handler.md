# Model candidate generation

The generation handler, `handlers/model.GenerationHandler`, is the step of a review run that asks a model for candidate problems. A handler is the code that runs one kind of task, and a candidate is a proposed problem that a later verification step must still confirm. The handler takes the durable context packet (the bounded source text and metadata for the review, built by the [context assembly handler](context-assembly-handler.md)) and sends it to the provider gateway that policy approved. It makes one authorized provider attempt, accepts only candidates that cite evidence, records route audit events, and stores one protected candidate artifact. An artifact is a stored task output, and a route is one way to reach a model.

## Durable authority

The context assembly task produces a `model-generation-input` artifact. The candidate-generation task receives that exact successful dependency output through `TaskExecutionRequest`. Its static plan input remains a content-addressed recipe identity. An identity in general is a digest computed from content, and a binding is a record that ties an object to the identities of the things it depends on.

A `model-generation-input` binds:

- the exact review scope and context artifact;
- the context packet identity and the required candidate schema;
- the immutable review snapshot and its supported ranges;
- the evidence allowlist that the host issued; and
- one complete `RouteAttemptAuthorization`.

`NewGenerationInput` accepts a `review.ContextPacket` that has already been validated. It verifies that the context artifact contains the exact provider request bytes, that those bytes hash to the context identity, and that the authorization binds the same request and review scope. `NewGenerationInputArtifact` preserves the classification, protection and expiry of the context artifact.

At execution time, the handler reads both artifacts through the scoped store and repeats these checks with `review.ValidateContextPacketRequest`. Repository source and recalled memory stay labeled as data. Only source evidence that the host issued can support a candidate's claims.

The provider adapter sends the context bytes as the user message and `review.TrustedModelRequestInstructions` as the system channel. For a version 9 context, the system channel holds the pinned host contract. When a specialist is bound, it also holds the skill text from the embedded profile catalog, exactly as the catalog has it. The context itself carries no instruction prose. It binds the contract by `instructions_identity` and the profile by identity fields only. See the [prompt-injection boundary](prompt-injection-boundary.md).

## Provider execution

The handler identity includes the identity of the immutable `RouteDispatcherCatalog`. Dispatch resolves only the adapter ID in the authorization. Before the handler releases any context bytes, it requires an existing route-selection audit event and records an idempotent route-attempt claim. After the call, it records the typed dispatch outcome and the pessimistic cost reconciliation, for both success and failure.

A model task must declare `max_attempts: 1`. Generic control-plane retries cannot issue a new route authorization, reserve another budget, or prove that a replay is safe. The GitHub planner applies this rule to candidate-generation and verification tasks. Provider retries and fallback need a separately authorized route continuation, not a repeated task lease.

As a result, an ambiguous transport outcome stays visible as a claimed attempt with closed audit lineage. If a process crashes between the provider dispatch and the terminal audit record, the handler does not replay the attempt automatically.

The handler admits a successful response only when all of these hold:

- it is one complete structured `review.v1` response;
- it conforms to the candidate schema that its context requests: `model-candidate-batch-v2` for a version 9 context (and a recorded version 7 or 8 context), or `model-candidate-batch-v1` for a recorded earlier context (`review.ParseContextCandidateBatch`);
- every cited source and evidence ID was in the context packet;
- every claimed range is covered by the immutable snapshot and the cited evidence;
- there are no semantic duplicate findings; and
- the reconciled cost does not exceed the authorized budget.

If a candidate's `source_range` names a `repository_context` source, the handler drops that candidate from the admitted batch and does not treat it as a failure. The remaining candidates are admitted with contiguous ordinals. The drop count is bound into the batch identity and the durable encoding as `repository_context_anchor_omitted`, which is absent when it is zero.

From context version 8, a candidate that is located in a `removed_lines` source is a base-side finding. Its lines are base lines inside that source, and it records the source's `head_line`. Only cited `removed_lines` evidence covers it, and base-line evidence never covers a head location. The durable candidate-batch encoding records `"side":"base"` and `head_line` on such a candidate and on each cited `removed_lines` binding. See [base-side findings](local-model-review.md#base-side-findings).

The handler does not persist provider reasoning or invalid model output as candidates.

## Failures

A failed task carries a closed run failure. Where the provider's answer decides the cause, it also carries one content-free reason. See [failure details](failure-details.md) and the [protocol contracts](protocol-contracts.md). The reasons are:

- a provider refusal named from its HTTP status alone (`provider_payment_required`, `provider_model_unavailable`, `provider_model_retired`, `provider_authentication_failed`, `provider_authorization_denied`, `provider_request_rejected`, `provider_rate_limited`);
- `provider_response_invalid`, when the adapter refused a reply that the provider sent (for example a malformed or truncated 200);
- `model_output_invalid`, when a reply that stopped normally held an answer that the review parser refused. A host input check, or a reply that stopped at the output limit or a content filter, records no reason.

The reason names neither the reply nor its fields. The verification handler records the same reasons.

## Category and fix guidance

Generation at versions 7, 8 and 9 asks for `model-candidate-batch-v2`. Each candidate adds two fields:

- a required `category` from a closed set (`correctness`, `security`, `concurrency`, `performance`, `reliability`, `maintainability`, `style`, `documentation`, `testing`); and
- an optional `fix`, which is nonblank plain text of at most 256 characters. That length always fits the parser's 1024-byte UTF-8 wire bound.

Parsing stays strict. It rejects a v1 document, a category that is missing, null or unknown, a fix that is empty, blank, oversized, not a string or contains control characters, and any extra member. Category and fix are bound into the candidate identity (preimage version 2) and the batch identity, and the durable `open-trestle/candidate-batch` encoding uses schema version 2 for such batches. Both fields remain untrusted model output. The category is advisory, and the fix is guidance for a person, never a patch, command or automatic edit.

The generation input records the context's `output_schema_identity` (v1 for recorded contexts before version 7, v2 for versions 7, 8 and 9). Both execution and `ParseGenerationResultArtifact` require it to match the context bytes. Readback, which reloads a stored result and checks it, also requires the schema of the admitted batch to match its context version.

## Candidate artifact

The `candidate_batch` artifact contains:

- the canonical admitted `CandidateBatch`;
- one successful `RouteExecutionRecord`;
- the route authorization, the terminal outcome, the token usage, the cost settlement and the normalized output receipt; and
- the exact lineage of the context and the response.

Its provenance includes the task input, context, candidates, authorization, outcome, reconciliation, output receipt and route execution. `ParseGenerationResultArtifact` requires the exact input and context artifacts. It revalidates the scope, classification, protection, provenance, candidates, route records and canonical encodings.

You can wrap the handler in `artifactvalidation.ValidatedTaskHandler` with the `task_input` and `candidate_batch` kinds.

## Published schemas

- `schemas/artifact/route-attempt-authorization-v1.schema.json`
- `schemas/artifact/route-execution-record-v1.schema.json`
- `schemas/artifact/candidate-batch-v1.schema.json`, `schemas/artifact/candidate-batch-v2.schema.json` (categorized) and `schemas/artifact/candidate-batch-v3.schema.json` (uncategorized, recording removed base lines)
- `schemas/artifact/model-generation-input-v1.schema.json` (candidate schema v1 or v2), `schemas/artifact/model-generation-input-v3.schema.json` (sanitized) and `schemas/artifact/model-generation-input-v4.schema.json` (unsanitized, with `removed_lines` evidence)
- `schemas/review/model-candidate-batch-v1.schema.json` (recorded contexts before version 7)
- `schemas/review/model-candidate-batch-v2.schema.json` (version 7, 8 and 9 contexts)
- `schemas/artifact/model-generation-result-v1.schema.json`
