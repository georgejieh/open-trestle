# Publication task handler

The publication handler, `handlers/publication.Handler`, is the one review task that can release verified findings to a configured source-control publisher, such as the pull request on a forge. A handler is the code that runs one kind of task in a review run. This one runs in a single task attempt, and it requires the exact protected `readiness` dependency, which is the output of the [publication readiness handler](publication-readiness-handler.md).

## Immutable target

For runs in required publication mode, forge planning creates a protected `publication-input` artifact, which is a stored task output. The input binds the following:

- the configured publisher implementation ID;
- the repository identity;
- the pull-request or change ID; and
- the immutable reviewed head revision.

Prepared processing validates the input against the plan before it opens the run. The handler never infers the target later from mutable forge state.

Before it requests effect authority, the handler reconstructs the verification result, generation input, context packet, deterministic evidence, change model and acquired source snapshots. Effect authority is permission to perform an external effect, here the publication. The handler then creates a `ProtectedSourceBinding`, a record that ties together the review scope, repository, reviewed head, head manifest, change, evidence, context, selected evidence bindings and pipeline snapshot. A publication plan is valid only when this binding matches both the readiness result and the exact target.

The handler rebinds every generation evidence item from protected bytes. Each item must match exactly one deterministic authority, or the task fails with `invalid_input`. The possible authorities are:

- a changed analysis item, bound to its head file and checked against the recorded range, digest, binding and file identities;
- a `removed_lines` record, bound to the exact base file it names;
- a semantic reference range, bound to its head file with the item's binding identity; or
- a repository instruction prefix, which is one of the fixed root files `AGENTS.md`, `CLAUDE.md`, `.github/copilot-instructions.md` and `.trestle/review-instructions.md`, starting at line 1, whose base snapshot copy has the head file's digest and size. It is bound to the head file with the item's binding identity, exactly as context assembly bound it.

Instruction context is advisory evidence only. If a finding selected for publication, inline or summary-only, is located in a file that is bound as instruction context, the handler refuses the binding. Candidate admission already drops such candidates, but this check does not rely on that.

## Effect boundary

Readiness is not write authority. The handler separately takes these steps:

1. It asks the configured effect authorizer for the exact publication plan.
2. It records an exclusive publication claim in the audit ledger.
3. It creates one initial publication-attempt authorization.
4. It reacquires the moving change head through the exact resolver catalog.
5. It reconciles and audits the observed head.
6. It dispatches only when the fresh-head gate is current.
7. It selects the publisher only from the immutable publisher catalog.

The publisher must provide idempotency by exact operation key, which means that repeating the same operation key does not repeat the write. The GitHub adapter adds its durable `PublicationAttemptGuard` before the HTTP write. The task does not retry an ambiguous or failed write, because publication tasks require `max_attempts=1`.

If there are no verified findings, or all findings are below the threshold, the handler produces a protected `publication_receipt` with `not_required` and makes no external call. A receipt is the stored record of what the handler did. Insufficient independence or blocked inconclusive results fail with the policy class. A successful external write produces a receipt that has no repository content and stores only identities, including the hashed external reference.

`review.RepositoryPublicationAuthorizer` is the built-in authority that grants effects according to an explicit repository policy. Its identity binds the tenant, repository, policy, principal and authorization lifetime. Every effect decision it returns is short-lived and bound to the exact review scope. Enabling this authority does not bypass publication readiness, the immutable target checks, fresh-head reconciliation, operation-key fencing or the completion audit.

Publisher and current-head resolver catalogs bind each implementation's non-secret `ConfigurationIdentity()`, not only its public ID. The GitHub adapter identity covers the repository authority, endpoint, API version, credential authority, durable attempt guard, HTTP client authority and timeout, and clock authority. Custom HTTP clients and clocks require explicit non-secret authority identities. Changing any of these values changes the publication handler identity, so a run cannot execute under an unchanged review plan.
