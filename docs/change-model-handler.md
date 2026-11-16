# Change model task handler

The change model handler turns the output of the two source acquisition tasks, `source-base` and `source-head`, into one `change_model` artifact. That artifact lists the files that changed between the two revisions, with ranges linked back to the source. A handler is the code that runs one kind of task in a review run, and an artifact is a stored task output. The handler lives in `handlers/change`, and it is the step that comes after [source acquisition](source-acquisition-handler.md). It makes no repository or network access, and the artifact is bounded in size.

## Input reconstruction

The handler requires exactly two successful source dependencies. For each one, it resolves:

- the source task's root input artifact, which cannot change after it is written;
- the protected source snapshot index; and
- every source file that the index names.

The handler then rechecks the following:

- scope, classification and protection;
- repository identity and full revision identity;
- source adapter identity and acquisition lineage;
- file size and file digest; and
- the reconstructed manifest identity.

Base and head must refer to the same repository and adapter.

The two source tasks can be planned in two ways, and the handler checks each case:

- A `source-base` merge-base input (source input v3) must have a version 2 snapshot. That snapshot's recorded derivation must name the input's requested base and head, and its revision must be the recorded merge base. The head it was resolved for must be the revision that the `source-head` task acquired. The change then runs from that merge base, so the result's base revision is the merge base, not the requested base. See [source acquisition](source-acquisition-handler.md#merge-base-inputs).
- A plain input must have a plain snapshot of exactly its revision. The head input cannot be a merge-base input.

The handler loads at most 256 MiB of source in total, and it clears that source after execution.

## Deterministic delta

The handler builds a `RepositoryManifestDelta` from the two reconstructed manifests. Each changed path gets an exact `RepositoryFileDeltaExecution`, which records how the handler treated that path:

- For modified supported text, it records a normalized file-change identity, a line-map identity, and the canonical changed ranges on the head side.
- For added text that is nonempty, valid and within budget, it records full-file change evidence and the complete head range.
- Removed files stay in the result explicitly, and the handler does not invent a head range for them.
- Empty files, files that are invalid UTF-8 or binary, files over budget, and removed files keep a closed unsupported reason, which is one value from a fixed list of reasons.

One result holds at most 4,096 changed paths. The handler never presents unsupported evidence as a verified text change.

## Output

The canonical result binds the following:

- the identities of both source artifacts and snapshots;
- the repository coordinates;
- the full base and head revisions and the adapter;
- the reconstructed manifests and the manifest delta;
- the file identities and digests for each path;
- the execution status, the omission reason and the changed ranges.

Its protected artifact has deterministic-tool origin, which marks the output as produced by fixed code and not by a model. Its provenance cites both dependency outputs, both root inputs and the delta.

`ParseResultArtifact` checks the canonical encoding and cross-binds the result to both source snapshots. `artifactvalidation.ValidatedTaskHandler` can require `source_snapshot` dependencies and a `change_model` output.

The published schema is `schemas/artifact/change-model-result-v1.schema.json`. The handler identity is the SHA-256 digest of the canonical record of the contract `open-trestle/change-model-handler` at schema version 3, which is `af559535868494caf3a8e78d0df23ebda6f7c186caa06c57b3a9dac7ee78b276`. A run plan records this identity. A run that was planned under an earlier identity fails closed and is not executed by this handler.
