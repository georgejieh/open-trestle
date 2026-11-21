# Source acquisition task handler

The source acquisition handler, `handlers/source`, fetches the source code that a review run needs and stores it as protected artifacts. A handler is the code that runs one kind of task in a review run, and an artifact is a stored task output. This handler connects an approved `scm.SourceAdapter`, the code that talks to the source-control system, to the durable control-plane task contract and to artifact storage. It implements `controlplane.TaskAcquireSource`. You can register it in `controlplane.TaskHandlerCatalog` under its handler identity, which is derived from its content.

## Input authority

A caller creates a canonical `source-acquisition-input` that contains:

- one repository identity;
- one full Git commit identity;
- one source-adapter descriptor with manifest and content capabilities;
- the fixed `manifest_and_content` artifact request; and
- the fixed `read_only` effect.

`NewInputArtifact` stores this authority as a scoped `task_input` artifact with host origin. The input identity in the task definition must be the identity of that artifact. Before it touches any source, the handler rejects inputs that are missing, expired, repository-originated, noncanonical, from another scope or for another adapter.

Webhook, API, CI and local planners all use the same input contract. A planner must persist the input artifact before it makes its task available. Plans that the webhook path prepares create separate `source-base` and `source-head` root inputs, so the same handler acquires both sides at fixed commits and never reads a moving branch.

## Merge-base inputs

A merge base is the most recent commit that two branches share. A pull request diff shows changes relative to the merge base, so some inputs ask for it. Schema version 3 of `source-acquisition-input` (`NewMergeBaseInput`) names a requested base in its revision fields and a head in `merge_base_head_revision_digest`, with `base_derivation: merge_base`. It authorizes acquisition of the merge base of the two. Both commits use one object algorithm. Versions 1 and 2 are unchanged and still name the exact revision to acquire.

For such an input, the handler asks its adapter for the forge's merge base, and the adapter must implement `scm.MergeBaseResolver`. The handler then acquires that commit like any other. If it refuses, the task completes as failed with a recorded reason that has no repository content, and nothing is acquired. The table shows each case:

| Condition | Run failure | Reason |
|---|---|---|
| the requested base equals the head, or the merge base is the head (the head is already contained in the base) | `policy` | `nothing_to_review` |
| the adapter reports that both commits exist and share no history (the GitHub adapter never does; see [merge base](github-source-acquisition.md#merge-base)) | `policy` | `no_merge_base` |
| the merge base could not be read | the acquisition mapping below (for example `transient` for a rate limit or server error, `policy` for missing authorization) | `merge_base_unavailable` |
| the adapter cannot resolve merge bases, or returned a malformed result | `policy`, or `internal` for a malformed result | `merge_base_unavailable` |

The handler does not fall back to the requested base. The resulting snapshot is `source-snapshot` schema version 2. Its `revision_identity` is the merge base, and its `revision_derivation` records `method: forge_merge_base`, the identities of the requested base and head revisions, and the merge-base revision. Version 1 snapshots keep their bytes and identities.

## Output layout

A successful acquisition creates two kinds of artifact:

1. One protected `source_file` artifact for every manifest entry. Its payload records the path, SHA-256 digest, byte count, bytes and acquisition execution identity. Empty files are supported. A file is limited to 10 MiB.
2. One protected `source_snapshot` index. It binds the request, receipt, acquisition execution, repository, revision, adapter, manifest and the ordered references to the file artifacts.

All output artifacts keep the scope, classification, protection mode and expiry of the input. Their provenance includes both the task input and the acquisition execution. The handler writes the snapshot index only after all file artifacts are durable. If an attempt is interrupted, the file artifacts it leaves behind stay subject to the normal retention policy.

`ParseSnapshotArtifact` verifies the scoped index. `ParseFileArtifact` then requires that verified snapshot and one listed reference. It checks scope, classification, protection, identity, canonical encoding, repository origin, provenance, content digest, byte count and acquisition lineage before it returns a copy of the content. Downstream change-building handlers should resolve only the file identities that the verified snapshot index lists.

## Terminal behavior

Source-adapter outcomes map to these run failures:

| Acquisition reason | Run failure |
|---|---|
| authorization, policy, or capability blocked | `policy` |
| adapter unavailable | `transient` |
| resource limit exceeded | `resource_limit` |
| malformed or inconsistent source data | `internal` |
| canceled execution | `canceled` |

Provider error strings and repository content do not enter task completions. After dispatch, the remote worker's execution context signals cancellation and a renewed lease. The handler does not treat the original lease expiry as final once execution has started.

The schemas are published as:

- `schemas/artifact/source-acquisition-input-v1.schema.json`, `schemas/artifact/source-acquisition-input-v2.schema.json` (binds a daemon-retained source-root identity) and `schemas/artifact/source-acquisition-input-v3.schema.json` (merge base)
- `schemas/artifact/source-file-v1.schema.json`
- `schemas/artifact/source-snapshot-v1.schema.json` and `schemas/artifact/source-snapshot-v2.schema.json` (merge-base derivation)
