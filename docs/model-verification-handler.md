# Independent model verification

The verification handler, `handlers/model.VerificationHandler`, is the step of a review run in which a second, independent model checks the candidate problems that the first model proposed. A handler is the code that runs one kind of task, and an artifact is a stored task output. A route is one way to reach a model, and an identity is a digest computed from content.

The handler takes the exact candidate artifact that candidate generation produced. It builds a separate verifier request, selects a route that policy approves and that is independent of the generation route, and records the second route attempt. It then accepts a complete set of verdicts and writes a protected artifact of verified findings.

## Dependency and context reconstruction

The handler receives the successful `candidates` dependency through `TaskExecutionRequest`. It resolves the generation result and its exact generation-input and context artifacts in the same review scope. Before a verifier request exists, it revalidates all the generation lineage.

`review.NewVerificationRequestContext` rebuilds the verifier request directly from the canonical generation-context bytes and the accepted candidates. It keeps the exact source and advisory memory context, but it labels the candidates as unverified proposals. The resulting request has a different identity and output schema from candidate generation. The
handler then checks the source content, risk flags, evidence digests, snapshot
ranges, authority labels, counted preselection omissions, coverage equations and
candidate fields again.

Verification-context schema v2 keeps the exact counted source coverage from generation. It does not rebuild that coverage from the length of the omission records.

The immutable `SourceCoverage` projection binds its verification context, review scope, snapshot and candidate batch. It exposes analyzed, selected and omitted aggregate counts for diagnostic materialization. It maps every canonical internal omission reason to a closed category that carries no content, and it represents selection-stage omissions only as `selection_limit`. It does not expose paths, source content, raw reason strings or repository-wide coverage.

## Independent route authorization

`PolicyVerificationAuthorizer` obtains a bounded route snapshot from `VerificationRouteInventory`. Each snapshot binds exact registry and performance revisions, the resolved approved routes, their operational state and their performance observations.

Authorization follows this order:

1. Reject every route that does not satisfy the configured independence policy relative to candidate generation.
2. Apply the privacy zone and content-logging constraints.
3. Apply the capability, health, quota and pessimistic budget checks.
4. Rank the remaining exact records deterministically.
5. Create the route selection and the initial attempt authorization.
6. Record the selection in the scoped audit ledger before returning authority.

The supported separation policies require a distinct full route reference, model or provider. A different registry revision, price, capability claim or evidence record for the same route does not establish route independence. The handler checks the selected authorization again before provider dispatch and after the verifier outcome. It never calls a shared route that fails policy.

Inventory failures and audit-storage failures return the closed transient authorization-unavailable state. When no eligible independent route exists, that is a policy failure. Provider or inventory error text is not stored in task results.

## Verification execution

Verification tasks require `max_attempts: 1`. The handler records the attempt claim before it releases any context, and then records the typed provider outcome and the cost reconciliation. Generic task retries cannot reuse verification authority or budget. If the reconciled budget is overrun, the task fails closed, which means it stops with an error.

The verification-context schema version follows the generation context version:

| Generation context | Verification-context schema |
| --- | --- |
| Version 9 | Version 8 |
| Recorded version 8 | Version 7 |
| Recorded version 7 | Version 6 |

Version 7 is version 6 plus one sentence that explains `removed_lines` sources. Version 8 is version 7 plus the optional `stated_intent` object and one sentence that explains it. When a change contradicts its stated intent, the verifier checks that claim against both the intent and the evidence.

Version 6 keeps the version 5 verdict rules and opens with the instruction-hierarchy paragraph of the [prompt-injection boundary](prompt-injection-boundary.md). It sends that contract only in the trusted system channel, and the payload binds it by `instructions_identity`. The verifier does not receive candidate categories, fix guidance or specialist guidance. Categories and fixes are bound only through `candidate_batch_identity` and each `candidate_id`. The verifier checks the defect claim against the evidence.

The verifier receives every generation source, so it sees the removed base text at a deletion point. A verified verdict may cite a `removed_lines` source, but its base line numbers never count as covering the candidate's head lines (`review.ParseContextVerificationBatch`). The handler refuses a categorized batch against a generation context from before version 7.

New verifier requests are built only from an executable version 9 generation context. Recorded verification contexts of versions 2, 3, 5, 6 and 7, and recorded generation contexts of versions 5, 7 and 8, are reconstructed for readback but grant no new verification. Readback means reloading a stored result and checking it against its sources.

The verifier response must contain exactly one verdict for every accepted candidate. A verified verdict requires supported source evidence and a final severity. Rejected and inconclusive verdicts remain explicit and cannot carry a final severity. The handler rejects a response with unknown candidates, omitted candidates, duplicate verdicts, unsupported evidence or an incomplete set of verdicts.

## Protected output

A successful `verified_finding_set` artifact contains and binds:

- the canonical verification batch;
- the successful verification route execution;
- the route-independence proof from before and after dispatch;
- the independent verification receipt;
- the promoted verified finding set; and
- the identities of the generation result, context, request, response, cost and provenance.

Only independently verified candidates are promoted. A promoted finding copies its candidate's category and fix unchanged. The verified-finding identity binds them (preimage version 2), and the verified-finding-set encoding uses schema version 2 when any finding carries a category.

The fix stays unverified model text. It is not part of `PublishableFinding`, so forge publication and its content scan do not render it, and the local JSON result labels it `unverified_model_guidance`.

Rejected and inconclusive counts remain in the finding set. `ParseVerificationResultArtifact` reconstructs the verification context and all derived receipts, reruns independence and promotion, and compares every identity before it returns data.

`artifactvalidation.ValidatedTaskHandler` can wrap the handler with `candidate_batch` as input and `verified_finding_set` as output.

## Published schemas

- `schemas/artifact/verification-batch-v1.schema.json` and `schemas/artifact/verification-batch-v2.schema.json` (verdicts that record removed base lines)
- `schemas/artifact/verified-finding-set-v1.schema.json`, `schemas/artifact/verified-finding-set-v2.schema.json` (categorized) and `schemas/artifact/verified-finding-set-v3.schema.json` (uncategorized, recording removed base lines)
- `schemas/artifact/model-verification-result-v1.schema.json`
