# Deterministic evidence task handler

The deterministic evidence handler, `handlers/analysis`, collects the facts about a change that do not depend on a model. A handler is the code that runs one kind of task in a review run. This one takes the protected `change_model` dependency and produces three things: source slices, a semantic impact profile, and one check. It makes no network calls, and it infers no defects beyond the rule of that check.

## Source reconstruction

The handler resolves the base and head snapshot artifacts that the change result names. It validates the boundary between the change and the snapshots, locates each changed head file in the head snapshot, and reloads that file's protected artifact. It then reconstructs the repository-file identity (a digest of the file's content) from the bytes.

Only the lines that the change model names become slices. Each item records a `SourceSliceBinding` identity, the file identity and digest, the range, the slice digest and the slice size. A binding is a record that ties the slice to the file it came from. A later context handler can reload the same file and rebind the slice before it gives the slice to a model.

## Semantic impact

The handler also loads the changed Go files from the base and head snapshots. From these it derives structural declaration changes, public API changes and explicit coverage gaps. The embedded profile binds both snapshots, the change model, the digest of every loaded file, the Go adapter identity and the graph schema. See [semantic impact profiles](semantic-impact.md).

## Deterministic check

Each analysis result records one `static_debug_output` check. The check reuses the existing Go AST and type-aware scanner to find `fmt.Println("debug")` calls that overlap changed Go ranges. The result binds rule version 1, the change identity, the counts of applicable and checked file ranges, the match count, the state, and its own content identity.

The check has four states:

- `passed` means that every applicable changed Go range parsed and had zero matches.
- `failed` means that there was at least one match. Coverage can still be incomplete, and the counts show that.
- `incomplete` means that an applicable range could not be checked and no match was found.
- `not_applicable` means that there was no changed Go range.

The check covers only that one call pattern in changed Go ranges.

Publication readiness validates the same analysis result and change before it maps this check into diagnostic-set version 5. The check contains no repository content. The public check repeats the source-check, analysis-result and change identities, so that consumers can tell it apart from model findings.

## Bounds and coverage

- The handler writes at most 8,192 evidence or gap records.
- It reads at most 64 MiB of changed head source in one execution. The removed text of emptied and removed files is charged to that bound only by its bytes, after every changed file. The handler reads those files from a separate 64 MiB bound.
- Each source slice is limited to 1 MiB.
- Evidence or a typed gap represents every changed range once.
- Removed files, binary or unsupported files, added files that are empty, and the source limit, slice limit and aggregate evidence limit all appear in the output.
- From version 4, an added file without a reviewable range is labeled with the reason it has none. `empty_added_file` is used only when the file has zero bytes. `unsupported_content` is used for content that the change model cannot diff (for example binary). `resource_limit` is used past the size bound. Readback, which is the check that reloads a stored result and compares it with the source, accepts `empty_added_file` from version 4 only for an added file with zero bytes. Versions 1 to 3, as published, read back unchanged.
- From version 4, a file that the change model could not diff because of its size (over 1 MiB) becomes one whole-entry `resource_limit` gap, whatever its kind. The handler never reads such a file if it was removed or emptied. Its removed text becomes one whole-entry `removed_lines_limit` gap. An added file that still gets no range was recorded as `empty_added_file` before, and from version 4 readback refuses that label for it.

If the number of required coverage records exceeds the limit, one `evidence_limit` gap covers each changed entry. The output does not truncate ranges.

## Output

The protected `deterministic_evidence` artifact binds the change artifact, the change result, the repository, the head revision, the head snapshot, the manifest, the slice proofs and the coverage accounting. Its origin is `deterministic_tool`. Its expiry does not exceed that of any source artifact it used.

The published schemas are `schemas/artifact/deterministic-evidence-result-v4.schema.json` through `schemas/artifact/deterministic-evidence-result-v7.schema.json`, and `schemas/artifact/semantic-impact-profile-v2.schema.json`. Every result carries the check and its observations and embeds a version 2 profile.

### Deletion-only files across versions

Version 5 records a deletion-only file (`no_changed_head_lines`) as one whole-entry gap with no range. Version 6 instead binds up to 8 unchanged head lines on each side of each deletion point as items of that entry. It adds one `deleted_lines` gap for each deletion point, which covers the head lines on either side of the removed lines. Version 6 carries no removed base text. A result is version 6 only when it carries such items. The version 5 and 6 schemas differ from version 4 only in their version constant and the added gap reasons: `no_changed_head_lines` from version 5 and `deleted_lines` from version 6.

Version 7 is what the handler now writes for deletion-point context. It adds the removed base text of each deletion point. The handler takes the base file from the base snapshot reference whose digest matches the change entry, and it rebuilds the repository-file identity from the bytes. It then binds the removed base lines of each point as one `removed_lines` record. The record is a source-slice binding to the base file, with base line numbers, and is not a changed head range. Each deletion point's record names its `head_line`, which is the head line beside which the lines were removed. That line is also the start of the point's `deleted_lines` gap.

An emptied file and a removed file keep their whole-entry gap. They also bind their whole removed base text as chunk records with no head line. The chunks are consecutive line-aligned pieces of at most 64 lines and 8 KiB, up to 32 KiB per file, and they cover the base file from line 1. The rest of the file becomes one trailing `removed_lines_limit` gap.

The handler binds this text after every other entry, from the evidence budget they left, and it charges only the bytes it binds. It therefore takes no budget from a changed file. The removed files are read from a separate bound of 64 MiB. A file that would pass that bound, or that finds no budget left, is not read, and it records one whole-entry `removed_lines_limit` gap (lines 0). A file whose base content is not text (not UTF-8, or holding a NUL byte) binds no records and is charged nothing.

A point whose removed text exceeds 64 lines or 8 KiB, or would take the entry past 32 KiB of removed text, gets no record. The handler records it whole as a `removed_lines_limit` gap at its base range. Unlike every other ranged gap, the lines of a `removed_lines_limit` gap are base lines.

Every entry with deletion-point context accounts for its removed text through records, limit gaps, or both, and the removed base ranges of an entry never overlap. Deletions before and after the only line of a one-line head file share one `deleted_lines` marker, which is recorded once. Each removed range is still bound separately.

The version 7 schema adds the required `removed_lines` array, with the same record shape as `items`, and the `removed_lines_limit` gap reason. Versions 5 and 6 remain readable from recorded bytes and never carry `removed_lines`. The handler identity moved to version 7, so a run planned before the upgrade stops with an error and is not executed. See [deletion-only changes](local-model-review.md#deletion-only-changes).
