# Independent model verification

`handlers/model.VerificationHandler` consumes the exact candidate artifact produced by candidate generation. It creates a distinct verifier request, selects a policy-approved independent route, records the second route attempt, admits a complete verdict set, and emits a protected verified-finding artifact.

## Dependency and context reconstruction

The handler receives the successful `candidates` dependency through `TaskExecutionRequest`. It resolves the generation result and its exact generation-input and context artifacts in the same review scope. All generation lineage is revalidated before a verifier request exists.

`review.NewVerificationRequestContext` rebuilds the verifier request directly from the canonical generation-context bytes and admitted candidates. It preserves the exact source and advisory memory context but labels candidates as unverified proposals. The resulting request has a different identity and output schema from candidate generation. Source content, risk flags, evidence digests, snapshot ranges, authority labels, counted preselection omissions, coverage equations, and candidate fields are checked again. Verification-context schema v2 preserves the exact counted source coverage from generation rather than rebuilding it from omission-record length. The immutable `SourceCoverage` projection binds its verification context, review scope, snapshot, and candidate batch and exposes analyzed, selected, and omitted aggregate counts for diagnostic materialization. It also maps every canonical internal omission reason into a closed content-free category and represents selection-stage omissions only as `selection_limit`; it does not expose paths, source content, raw reason strings, or repository-wide coverage.

## Independent route authorization

`PolicyVerificationAuthorizer` obtains a bounded route snapshot from `VerificationRouteInventory`. Each snapshot binds exact registry and performance revisions, resolved approved routes, operational state, and performance observations.

Authorization follows this order:

1. Reject every route that does not satisfy the configured independence policy relative to candidate generation.
2. Apply privacy zone and content-logging constraints.
3. Apply capability, health, quota, and pessimistic budget checks.
4. Rank the remaining exact records deterministically.
5. Create the route selection and initial attempt authorization.
6. Record the selection in the scoped audit ledger before returning authority.

Supported separation policies require a distinct full route reference, model, or provider. A different registry revision, price, capability claim, or evidence record for the same route does not establish route independence. The selected authorization is checked again before provider dispatch and after the verifier outcome. A shared route that fails policy is never called.

Inventory failures and audit-storage failures return the closed transient authorization-unavailable state. No eligible independent route is a policy failure. Provider or inventory error text is not stored in task results.

## Verification execution

Verification tasks require `max_attempts: 1`. The handler records the attempt claim before releasing context, then records the typed provider outcome and cost reconciliation. Generic task retries cannot reuse verification authority or budget. A reconciled budget overrun fails closed.

A version 9 generation context yields a verification-context schema version 8 request, a recorded version 8 generation context a version 7 one, and a recorded version 7 generation context a version 6 one. Version 7 is version 6 plus one sentence that explains `removed_lines` sources. Version 8 is version 7 plus the optional `stated_intent` object and one sentence that explains it; the verifier checks a claim that a change contradicts its stated intent against both the intent and the evidence. Version 6 keeps the version 5 verdict rules, opens with the instruction-hierarchy paragraph of the [prompt-injection boundary](prompt-injection-boundary.md), and sends that contract only in the trusted system channel; the payload binds it by `instructions_identity`. It does not receive candidate categories, fix guidance or specialist guidance; categories and fixes are bound only through `candidate_batch_identity` and each `candidate_id`. The verifier checks the defect claim against evidence. The verifier receives every generation source, so it sees the removed base text at a deletion point; a verified verdict may cite a `removed_lines` source, but its base line numbers never count as covering the candidate's head lines (`review.ParseContextVerificationBatch`). A categorized batch is refused against a pre-version-7 generation context. New verifier requests are built only from an executable version 9 generation context. Recorded verification contexts of versions 2, 3, 5, 6 and 7, and recorded generation contexts of versions 5, 7 and 8, are reconstructed for readback but grant no new verification.

The verifier response must contain exactly one verdict for every admitted candidate. Verified verdicts require supported source evidence and a final severity. Rejected and inconclusive verdicts remain explicit and cannot carry a final severity. Unknown candidates, omitted candidates, duplicate verdicts, unsupported evidence, or incomplete responses are rejected.

## Protected output

A successful `verified_finding_set` artifact contains and binds:

- the canonical verification batch
- the successful verification route execution
- the pre-dispatch and post-dispatch route-independence proof
- the independent verification receipt
- the promoted verified finding set
- the generation result, context, request, response, cost, and provenance identities

Only independently verified candidates are promoted. A promoted finding copies its candidate's category and fix unchanged; the verified-finding identity binds them (preimage version 2), and the verified-finding-set encoding uses schema version 2 when any finding carries a category. The fix stays unverified model text: it is not part of `PublishableFinding`, so forge publication and its content scan do not render it, and the local JSON result labels it `unverified_model_guidance`. Rejected and inconclusive counts remain in the finding set. `ParseVerificationResultArtifact` reconstructs the verification context and all derived receipts, reruns independence and promotion, and compares every identity before returning data.

`artifactvalidation.ValidatedTaskHandler` can wrap the handler with `candidate_batch` as input and `verified_finding_set` as output.

## Published schemas

- `schemas/artifact/verification-batch-v1.schema.json` and `schemas/artifact/verification-batch-v2.schema.json` (verdicts that record removed base lines)
- `schemas/artifact/verified-finding-set-v1.schema.json`, `schemas/artifact/verified-finding-set-v2.schema.json` (categorized) and `schemas/artifact/verified-finding-set-v3.schema.json` (uncategorized, recording removed base lines)
- `schemas/artifact/model-verification-result-v1.schema.json`
