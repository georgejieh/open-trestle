# Deterministic evidence task handler

`handlers/analysis` turns the exact protected `change_model` dependency into source-slice evidence, a bounded semantic impact profile, and one narrow deterministic check. It does not make network calls or infer defects beyond the check's exact rule.

## Source reconstruction

The handler resolves the base and head snapshot artifacts named by the change result. It validates the complete change-to-snapshot boundary, locates each changed head file in the head snapshot, reloads its protected artifact, and reconstructs its repository-file identity from the bytes.

Only exact physical lines named by the change model become evidence. Each item records a `SourceSliceBinding` identity, file identity and digest, range, slice digest, and slice size. A later context handler can reload the same file and independently rebind the slice before giving it to a model.

## Semantic impact

The handler also loads changed Go files from the base snapshot and bounded Go source from the head snapshot. It derives structural declaration changes, public API changes, syntactic reference candidates, affected-test candidates, and explicit coverage gaps. The embedded profile binds both snapshots, the change model, every loaded file digest, the Go adapter identity, and graph schema. Syntactic candidates can guide context selection but cannot establish a finding.

## Deterministic check

Analysis-result version 3 records one `static_debug_output` check. It reuses the existing Go AST and type-aware scanner for exact `fmt.Println("debug")` calls that overlap changed Go ranges. The result binds rule version 1, the change identity, applicable and checked file/range counts, exact match count, state, and its own content identity.

- `passed` means every applicable changed Go range parsed and had zero exact matches.
- `failed` means at least one exact match. Coverage can still be incomplete and remains visible in the counts.
- `incomplete` means an applicable range could not be checked and no exact match was established.
- `not_applicable` means there was no changed Go range.

This gate says nothing about other logging calls, debug variables, non-Go files, unchanged source, repository-wide quality, correctness, or approval. Only `passed` is a cleared instance of this one exact rule.
Publication readiness validates the same analysis result and change before mapping this content-free check into diagnostic-set version 5. The public check repeats the source-check, analysis-result, and change identities so consumers can distinguish deterministic evidence from model findings.

## Bounds and coverage

- At most 8,192 evidence or gap records are emitted.
- At most 64 MiB of changed head source is read in one execution.
- Each source slice is limited to 1 MiB.
- Every changed range is represented exactly once by evidence or a typed gap.
- Removed, binary or unsupported, empty-added, source-limit, slice-limit, and aggregate evidence-limit cases remain explicit.

If the number of required coverage records exceeds the limit, one `evidence_limit` gap covers each changed entry. The output never silently truncates ranges.

## Output

The protected `deterministic_evidence` artifact binds the change artifact, change result, repository, head revision, head snapshot, manifest, exact slice proofs, and complete coverage accounting. Its origin is `deterministic_tool` and its expiry never exceeds any source artifact used.

Published schemas: `schemas/artifact/deterministic-evidence-result-v2.schema.json`, `schemas/artifact/deterministic-evidence-result-v3.schema.json`, and `schemas/artifact/semantic-impact-profile-v1.schema.json`. Version 3 adds the deterministic check. Version 2 remains readable without inventing check evidence, and version 1 remains published for contract history.
