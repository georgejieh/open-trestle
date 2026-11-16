# Change model task handler

`handlers/change` converts the exact `source-base` and `source-head` dependency artifacts into one bounded, source-linked `change_model` artifact. It performs no repository or network access.

## Input reconstruction

The handler requires exactly two successful source dependencies. For each dependency it resolves:

- the source task's immutable root input artifact
- the protected source snapshot index
- every source file named by that index

It rechecks scope, classification, protection, repository identity, full revision identity, source adapter identity, acquisition lineage, file size, file digest, and reconstructed manifest identity. Base and head must refer to the same repository and adapter. A `source-base` merge-base input (source input v3) must have a version 2 snapshot whose recorded derivation names that input's requested base and head and whose revision is the recorded merge base, and the head it was resolved for must be the revision the `source-head` task acquired; the change then runs from that merge base, so the result's base revision is the merge base, not the requested base. A plain input must have a plain snapshot of exactly its revision, and the head input cannot be a merge-base input. Aggregate loaded source is limited to 256 MiB and cleared after execution.

## Deterministic delta

The handler builds `RepositoryManifestDelta` from both reconstructed manifests. Each changed path receives an exact `RepositoryFileDeltaExecution`:

- modified supported text records a normalized file-change identity, line-map identity, and canonical head-side changed ranges
- nonempty, valid, within-budget added text records full-file change evidence and its complete head range
- removed files remain explicit without inventing a head range
- empty, invalid-UTF-8 or binary, excessive, and removed cases retain a closed unsupported reason

At most 4,096 changed paths enter one result. Unsupported evidence is never silently presented as a verified text change.

## Output

The canonical result binds both source artifact and snapshot identities, repository coordinates, full base and head revisions, adapter, reconstructed manifests, manifest delta, per-path file identities and digests, execution status, omission reason, and changed ranges. Its protected artifact uses deterministic-tool origin and cites both dependency outputs, both root inputs, and the delta in provenance.

`ParseResultArtifact` checks canonical encoding and cross-binds the result to both source snapshots. `artifactvalidation.ValidatedTaskHandler` can enforce `source_snapshot` dependencies and a `change_model` output.

Published schema: `schemas/artifact/change-model-result-v1.schema.json`. The handler identity is the SHA-256 of the canonical record of contract `open-trestle/change-model-handler` and schema version 3, which is `af559535868494caf3a8e78d0df23ebda6f7c186caa06c57b3a9dac7ee78b276`. A run plan records it, so a run planned under an earlier identity fails closed instead of being executed by this handler.
