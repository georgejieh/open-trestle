# Model verification

The verification handler, `handlers/model.VerificationHandler`, is the step of a review run in which a second model checks the candidate problems that the first model proposed. Setup recommends a second model from a different family; see [the rationale](rationale.md#the-checker-should-come-from-a-different-model-family). A handler is the code that runs one kind of task, and an artifact is a stored task output. A route is one way to reach a model, and an identity is a digest computed from content.

The handler takes the candidate artifact that candidate generation produced. It builds a separate verifier request, selects a route that policy approves and that satisfies the separation policy relative to the generation route, and records the second route attempt. It then accepts a complete set of verdicts and writes a protected artifact of verified findings.

## Dependency and context reconstruction

The handler receives the successful `candidates` dependency through `TaskExecutionRequest`. It resolves the generation result and its exact generation-input and context artifacts in the same review scope. Before a verifier request exists, it revalidates the generation lineage.

`review.NewVerificationRequestContext` rebuilds the verifier request from the canonical generation-context bytes and the accepted candidates. It keeps the source and advisory memory context and labels the candidates as unverified proposals. The resulting request has a different identity and output schema from candidate generation. The handler then checks the source content, risk flags, evidence digests, snapshot ranges, labels, counted preselection omissions, coverage equations and candidate fields again.

Verification-context schema v2 keeps the counted source coverage from generation and does not rebuild it from the length of the omission records.

The `SourceCoverage` projection binds its verification context, review scope, snapshot and candidate batch. It exposes analyzed, selected and omitted aggregate counts for diagnostic materialization. It maps every internal omission reason to a category that carries no content, and it represents selection-stage omissions as `selection_limit`. It exposes no paths, source content or raw reason strings.

## Route authorization

`PolicyVerificationAuthorizer` obtains a route snapshot from `VerificationRouteInventory`. Each snapshot binds registry and performance revisions, the resolved approved routes, their operational state and their performance observations.

Authorization follows this order:

1. Reject every route that does not satisfy the configured independence policy relative to candidate generation.
2. Apply the privacy zone and content-logging constraints.
3. Apply the capability, health, quota and budget checks.
4. Rank the remaining routes.
5. Create the route selection and the initial attempt authorization.
6. Record the selection in the scoped audit ledger before returning the authorization.

The supported separation policies require a distinct full route reference, model or provider. A different registry revision, price or capability claim for the same route does not make it a separate route. The handler checks the selected authorization again before provider dispatch and after the verifier outcome.

Inventory failures and audit-storage failures return the transient authorization-unavailable state. When no eligible route exists, that is a policy failure. Provider or inventory error text is not stored in task results.

## Verification execution

Verification tasks require `max_attempts: 1`. The handler records the attempt claim before it releases any context, and then records the provider outcome and the cost reconciliation. Task retries cannot reuse the authorization or budget. If the reconciled budget is overrun, the task stops with an error.

The verification-context schema version follows the generation context version:

| Generation context | Verification-context schema |
| --- | --- |
| Version 11 | Version 10 |
| Recorded version 10 | Version 9 |
| Recorded version 9 | Version 8 |
| Recorded version 8 | Version 7 |
| Recorded version 7 | Version 6 |

Version 7 is version 6 plus one sentence that explains `removed_lines` sources. Version 8 is version 7 plus the optional `stated_intent` object and one sentence that explains it. When a change contradicts its stated intent, the verifier checks that claim against both the intent and the source evidence. Version 9 is version 8 plus the index stages and one sentence for them. Version 10 is version 9 plus the generation context's `check_runs` object, copied unchanged, and one sentence for it: a regression listed there is strong evidence that the change broke that test and can support a candidate located on the code that causes it; a test listed as stopped running is not, since a rename or removal does the same; and a check that could not run, the absence of a regression, or a passing test is not evidence that the code is correct, since the code under test writes its own results (see [repository checks](repository-checks.md)). The verifier does not receive `pattern_hygiene`, `context_manifest` or `repository_checks`.

Version 6 keeps the version 5 verdict rules and opens with the instruction-hierarchy paragraph of the [prompt-injection boundary](prompt-injection-boundary.md). It sends that contract in the system channel, and the payload binds it by `instructions_identity`. The verifier does not receive candidate categories, fix guidance or specialist guidance. Categories and fixes are bound through `candidate_batch_identity` and each `candidate_id`.

The verifier receives every generation source, so it sees the removed base text at a deletion point. A verified verdict may cite a `removed_lines` source, but its base line numbers do not count as covering the candidate's head lines (`review.ParseContextVerificationBatch`). The handler rejects a categorized batch against a generation context from before version 7.

New verifier requests are built from a version 11 generation context only. Recorded verification contexts of versions 2, 3, 5, 6, 7, 8 and 9, and recorded generation contexts of versions 5, 7, 8, 9 and 10, are reconstructed for readback but grant no new verification. Readback means reloading a stored result and checking it against its sources.

The verifier response must contain one verdict for every accepted candidate. A verified verdict requires supported source evidence and a final severity. Rejected and inconclusive verdicts cannot carry a final severity. The handler rejects a response with unknown candidates, omitted candidates, duplicate verdicts, unsupported evidence or an incomplete set of verdicts.

## Protected output

A successful `verified_finding_set` artifact contains and binds:

- the canonical verification batch;
- the successful verification route execution;
- the route-independence proof from before and after dispatch;
- the verification receipt;
- the promoted verified finding set; and
- the identities of the generation result, context, request, response, cost and provenance.

Only verified candidates are promoted. A promoted finding copies its candidate's category and fix unchanged. The verified-finding identity binds them (preimage version 2), and the verified-finding-set encoding uses schema version 2 when any finding carries a category.

The fix is unverified model text. It is not part of `PublishableFinding`, so forge publication and its content scan do not render it, and the local JSON result labels it `unverified_model_guidance`.

Rejected and inconclusive counts remain in the finding set. `ParseVerificationResultArtifact` reconstructs the verification context and all derived receipts, reruns the independence check and promotion, and compares every identity before it returns data.

## Published schemas

- `schemas/artifact/verification-batch-v1.schema.json` and `schemas/artifact/verification-batch-v2.schema.json` (verdicts that record removed base lines)
- `schemas/artifact/verified-finding-set-v1.schema.json`, `schemas/artifact/verified-finding-set-v2.schema.json` (categorized) and `schemas/artifact/verified-finding-set-v3.schema.json` (uncategorized, recording removed base lines)
- `schemas/artifact/model-verification-result-v1.schema.json`
