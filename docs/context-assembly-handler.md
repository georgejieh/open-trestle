# Context assembly task handler

`handlers/context` turns the exact deterministic evidence and memory task outputs into one protected generation authority. It does not call a model.

## Reconstruction boundary

The handler requires successful `analysis` and `memory` dependencies and a single task attempt. It reloads the shared change artifact, both acquired snapshot indexes, and every head source file. It rebuilds the complete head manifest within a 256 MiB bound.

Every changed-range evidence slice is independently recreated from the acquired file bytes. The file identity, file digest, physical line slice, slice digest, byte count, and `SourceSliceBinding` identity must all match the deterministic evidence artifact. This check includes slices that later exceed context selection limits.

## Context reduction

Repository text remains `repository_controlled` data. Only evidence paths allowed by the already validated memory scope can enter the packet. Changed-range evidence is considered first. Bounded one-line sources named by the semantic profile are then admitted as `direct_reference` candidates after their source file and slice identities are independently reconstructed. Affected-test links retain their syntactic-candidate status. At most 128 source candidates are considered. Deterministic selection keeps at most 32 sources and 128 KiB of source text. The packet records every analysis and semantic-coverage gap and every pre-selection authorization, candidate-limit, duplicate-source, or source-size omission. Counted semantic omission summaries retain the exact number of rejected references without emitting an unbounded record per reference. Its coverage counts sum each omission record's bounded count, including validated evidence excluded before selection as well as count and byte omissions made during selection. Memory query omissions also remain bound through the exact dependency artifact in context provenance.

All memory retrievals are reconstructed from their records, queries, scores, ranks, index revisions, and identities. The context packet carries the bounded retrieval set rather than silently retaining only one changed path. Memory remains labeled `advisory_only`.

## Route authority

The handler passes the canonical provider request to a configured policy authorizer. The authorizer identity is part of the handler identity. The call binds the exact review scope, request identity, plan policy, and decision time. Returned authority must match the scope and request.

The built-in policy authorizer ranks only the performance observations belonging to eligible routes and retains rejected-route accounting in the selection receipt. Before returning usable generation authority, it durably records the complete route selection in the same scoped audit ledger used by generation. Selection persistence failure returns no authorization. Authorizer identity version 2 binds this audited-selection behavior; construction requires an explicit ledger.

The handler persists two protected artifacts:

1. A `context_packet` containing only canonical provider bytes.
2. A `task_input` binding that context to its selected snapshot, evidence, and one exact `RouteAttemptAuthorization`.

The task output is the `task_input`. It carries the exact memory-scope and retrieval-set identity, so later provider-request validation recomputes every advisory record and retrieval identity. The generation handler therefore consumes dynamically created authority through its exact `context` dependency. Context and input expiry cannot exceed any source or upstream dependency expiry.
