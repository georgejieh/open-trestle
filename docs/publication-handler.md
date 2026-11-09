# Publication task handler

`handlers/publication.Handler` is the only review task that can release verified findings to a configured source-control publisher. It requires a single task attempt and the exact protected `readiness` dependency.

## Immutable target

Forge planning creates a protected `publication-input` artifact for required-mode runs. The input binds the configured publisher implementation ID, repository identity, pull-request or change ID, and immutable reviewed head revision. Prepared processing validates it against the plan before opening the run. It is never inferred later from mutable forge state.

Before requesting effect authority, the handler reconstructs the verification result, generation input, context packet, deterministic evidence, change model, and acquired source snapshots. It creates a `ProtectedSourceBinding` over the review scope, repository, reviewed head, head manifest, change, evidence, context, selected evidence bindings, and pipeline snapshot. A publication plan is valid only when this binding matches readiness and the exact target.

Every generation evidence item is rebound from protected bytes and must match one deterministic authority, or the task fails with `invalid_input`:

- a changed analysis item, bound to its head file and checked against the recorded range, digest, binding, and file identities;
- a `removed_lines` record, bound to the exact base file it names;
- a semantic reference range, bound to its head file with the item's binding identity; or
- a repository instruction prefix: one of the fixed root files `AGENTS.md`, `CLAUDE.md`, `.github/copilot-instructions.md`, and `.trestle/review-instructions.md`, starting at line 1, whose base snapshot copy has the head file's digest and size. It is bound to the head file with the item's binding identity, exactly as context assembly bound it.

Instruction context is advisory evidence only. A finding selected for publication, inline or summary-only, that is located in a file bound as instruction context refuses the binding. Candidate admission already drops such candidates; this check does not rely on it.

## Effect boundary

Readiness is not write authority. The handler separately:

1. asks the configured effect authorizer for the exact publication plan;
2. records an exclusive publication claim in the audit ledger;
3. creates one initial publication-attempt authorization;
4. reacquires the moving change head through the exact resolver catalog;
5. reconciles and audits the observed head;
6. dispatches only when the fresh-head gate is current; and
7. selects the publisher only from the immutable publisher catalog.

The publisher must provide exact-operation-key idempotency. The GitHub adapter adds its durable `PublicationAttemptGuard` before the HTTP write. Ambiguous or failed writes are not retried by the task because publication tasks require `max_attempts=1`.

No verified findings or all findings below threshold produce a protected `publication_receipt` with `not_required` and no external call. Insufficient independence or blocked inconclusive results fail with the policy class. A successful external write produces a content-free receipt that stores only identities, including the hashed external reference.

`review.RepositoryPublicationAuthorizer` is the built-in explicit repository-policy authority. Its identity binds tenant, repository, policy, principal, and authorization lifetime. Every returned effect decision is short-lived and bound to the exact review scope. Enabling this authority does not bypass publication readiness, immutable target checks, fresh-head reconciliation, operation-key fencing, or completion audit.

Publisher and current-head resolver catalogs bind each implementation's non-secret `ConfigurationIdentity()`, not only its public ID. The GitHub adapter identity covers repository authority, endpoint, API version, credential authority, durable attempt guard, HTTP client authority and timeout, and clock authority. Custom HTTP clients and clocks require explicit non-secret authority identities. Changing any of these values changes the publication handler identity and therefore cannot execute under an unchanged review plan.
