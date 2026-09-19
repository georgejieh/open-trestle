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

## Provider execution

The handler identity includes the immutable `RouteDispatcherCatalog` identity. Dispatch resolves only the adapter ID in the authorization. Before releasing context bytes, the handler requires an existing route-selection audit event and records an idempotent route-attempt claim. It then records the typed dispatch outcome and pessimistic cost reconciliation for both success and failure.

A model task must declare `max_attempts: 1`. Generic control-plane retries cannot mint a new route authorization, reserve another budget, or prove replay safety. The GitHub planner applies this rule to candidate-generation and verification tasks. Provider retries and fallback require a separately authorized route continuation, not a repeated task lease.

Ambiguous transport outcomes therefore remain visible as claimed attempts with closed audit lineage. A process crash between provider dispatch and terminal audit recording does not cause an automatic replay.

A successful response is admitted only when:

- it is one complete structured `review.v1` response
- it conforms to the published model candidate schema
- every cited source and evidence ID was in the context packet
- every claimed range is covered by the immutable snapshot and cited evidence
- semantic duplicate findings are absent
- reconciled cost does not exceed the authorized budget

Provider reasoning and invalid model output are not persisted as candidates.

## Candidate artifact

The `candidate_batch` artifact contains:

- the canonical admitted `CandidateBatch`
- one successful `RouteExecutionRecord`
- the route authorization, terminal outcome, token usage, cost settlement, and normalized output receipt
- exact context and response lineage

Its provenance includes the task input, context, candidates, authorization, outcome, reconciliation, output receipt, and route execution. `ParseGenerationResultArtifact` requires the exact input and context artifacts and revalidates scope, classification, protection, provenance, candidates, route records, and canonical encodings.

The handler can be wrapped in `artifact.ValidatedTaskHandler` with `task_input` and `candidate_batch` kinds.

## Published schemas

- `schemas/artifact/route-attempt-authorization-v1.schema.json`
- `schemas/artifact/route-execution-record-v1.schema.json`
- `schemas/artifact/candidate-batch-v1.schema.json`
- `schemas/artifact/model-generation-input-v1.schema.json`
- `schemas/artifact/model-generation-result-v1.schema.json`
