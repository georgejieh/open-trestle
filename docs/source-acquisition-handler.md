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

## Output layout

A successful acquisition creates:

1. One protected `source_file` artifact for every manifest entry. The payload records the path, SHA-256 digest, byte count, exact bytes, and acquisition execution identity. Empty files are supported. A file is limited to 10 MiB.
2. One protected `source_snapshot` index. It binds the request, receipt, acquisition execution, repository, revision, adapter, manifest, and ordered file-artifact references.

All output artifacts retain the input's scope, classification, protection mode, and expiry. Their provenance includes both the exact task input and acquisition execution. The snapshot index is written only after all file artifacts are durable. Immutable file artifacts left by an interrupted attempt are safe orphans and remain subject to the normal retention policy.

`ParseSnapshotArtifact` verifies the scoped index. `ParseFileArtifact` then requires that verified snapshot and one exact listed reference. It checks scope, classification, protection, identity, canonical encoding, repository origin, provenance, content digest, byte count, and acquisition lineage before returning a defensive content copy. Downstream change-building handlers should resolve only file identities listed by the verified snapshot index.

The handler can be wrapped in `artifact.ValidatedTaskHandler` with `task_input` as its input kind and `source_snapshot` as its output kind for an additional catalog boundary.

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
