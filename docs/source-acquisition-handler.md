# Source acquisition task handler

`handlers/source` connects an approved `scm.SourceAdapter` to the durable control-plane task contract and protected artifact storage. It implements `controlplane.TaskAcquireSource` and can be registered by its content-derived handler identity in `controlplane.TaskHandlerCatalog`.

## Input authority

A caller creates a canonical `source-acquisition-input` with:

- one exact repository identity
- one full Git commit identity
- one exact source-adapter descriptor with manifest and content capabilities
- the fixed `manifest_and_content` artifact request
- the fixed `read_only` effect

`NewInputArtifact` stores that authority as a scoped `task_input` artifact with host origin. The task definition's input identity must be the resulting artifact identity. The handler rejects missing, expired, repository-originated, noncanonical, cross-scope, and cross-adapter inputs before source access.

Webhook, API, CI, and local planners use the same input contract. A planner must persist the input artifact before making its task available. The input artifact, not forge text or conversational state, is the authority released to the handler. Webhook-prepared plans create separate `source-base` and `source-head` root inputs, so the same handler acquires both immutable sides without reading a moving branch.

## Merge-base inputs

Schema version 3 of `source-acquisition-input` (`NewMergeBaseInput`) names a requested base in its revision fields and a head in `merge_base_head_revision_digest`, with `base_derivation: merge_base`. It authorizes acquisition of the merge base of the two, which is how a pull request diff presents a change. Both commits use one object algorithm. Versions 1 and 2 are unchanged and still name the exact revision to acquire.

For such an input the handler asks its adapter, which must implement `scm.MergeBaseResolver`, for the forge's merge base and then acquires that commit like any other. A refusal is a failed completion with a recorded, content-free reason and no acquisition:

| Condition | Run failure | Reason |
|---|---|---|
| the requested base equals the head, or the merge base is the head (the head is already contained in the base) | `policy` | `nothing_to_review` |
| the adapter reports that both commits exist and share no history (the GitHub adapter never does; see [merge base](github-source-acquisition.md#merge-base)) | `policy` | `no_merge_base` |
| the merge base could not be read | the acquisition mapping below (for example `transient` for a rate limit or server error, `policy` for missing authorization) | `merge_base_unavailable` |
| the adapter cannot resolve merge bases, or returned a malformed result | `policy`, or `internal` for a malformed result | `merge_base_unavailable` |

There is no fallback to the requested base. The resulting snapshot is `source-snapshot` schema version 2: its `revision_identity` is the merge base, and `revision_derivation` records `method: forge_merge_base`, the requested-base and head revision identities, and the merge-base revision. Version 1 snapshots keep their bytes and identities.

## Output layout

A successful acquisition creates:

1. One protected `source_file` artifact for every manifest entry. The payload records the path, SHA-256 digest, byte count, exact bytes, and acquisition execution identity. Empty files are supported. A file is limited to 10 MiB.
2. One protected `source_snapshot` index. It binds the request, receipt, acquisition execution, repository, revision, adapter, manifest, and ordered file-artifact references.

All output artifacts retain the input's scope, classification, protection mode, and expiry. Their provenance includes both the exact task input and acquisition execution. The snapshot index is written only after all file artifacts are durable. Immutable file artifacts left by an interrupted attempt are safe orphans and remain subject to the normal retention policy.

`ParseSnapshotArtifact` verifies the scoped index. `ParseFileArtifact` then requires that verified snapshot and one exact listed reference. It checks scope, classification, protection, identity, canonical encoding, repository origin, provenance, content digest, byte count, and acquisition lineage before returning a defensive content copy. Downstream change-building handlers should resolve only file identities listed by the verified snapshot index.

The handler can be wrapped in `artifactvalidation.ValidatedTaskHandler` with `task_input` as its input kind and `source_snapshot` as its output kind for an additional catalog boundary.

## Terminal behavior

Source-adapter outcomes map to closed run failures:

| Acquisition reason | Run failure |
|---|---|
| authorization, policy, or capability blocked | `policy` |
| adapter unavailable | `transient` |
| bounded resource exceeded | `resource_limit` |
| malformed or inconsistent source evidence | `internal` |
| canceled execution | `canceled` |

Provider error strings and repository content never enter task completions. The remote worker's execution context remains the cancellation and renewed-lease signal after dispatch; the handler does not treat the original lease expiry as final once execution has started.

Schemas are published as:

- `schemas/artifact/source-acquisition-input-v1.schema.json`
- `schemas/artifact/source-file-v1.schema.json`
- `schemas/artifact/source-snapshot-v1.schema.json`
