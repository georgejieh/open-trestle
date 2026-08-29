# Local Git debug-output review

`trestle local-git review` runs the maintained debug-output rule over one exact loose-object base/head comparison and emits compact findings and coverage.

```text
trestle local-git review \
  --objects-root PATH \
  --repository-authority AUTHORITY \
  --repository-namespace SEGMENT[/SEGMENT...] \
  --repository-name NAME \
  --revision-algorithm sha1|sha256 \
  --base-revision-digest FULL_LOWERCASE_HEX \
  --head-revision-digest FULL_LOWERCASE_HEX
```

All seven flags are required exactly once. `PATH` is the exact loose-object directory. Base and head are ordered caller selections. The command does not infer a merge base, resolve refs or `HEAD`, inspect an index or working tree, discover `.git`, run Git, use credentials, or access a network. Packs and alternates are unsupported.

Repository authority, namespace, and name are caller-supplied scope labels. They do not establish repository origin, ownership, or authorization.

## Review scope and limits

The command uses the existing `static-debug-output` rule only. It does not run a model or add other static rules. The fixed local limits are:

- at most 64 changed entries;
- at most 1 MiB of authenticated head content per supported file;
- at most 64 MiB total authenticated head content;
- at most 1,024 findings.

Limits are validated before acquisition. Every supported file in the canonical `Change` receives analyzed, unsupported-language, or no-positive-head-range coverage. Added, removed, binary, NUL-bearing, or diff-over-budget entries remain explicit in the nested change execution and are not silently reviewed as modified text.

## Output

Success or an inconclusive result writes one `open-trestle/local-git-review-result` JSON object followed by one newline. The object contains:

- the complete nested `open-trestle/local-git-change-result` record;
- the identity-bound debug-output review execution and result identities;
- fixed limits and per-file coverage;
- finding IDs, titles, severities, repository-relative ranges, and evidence IDs;
- evidence IDs, kinds, exact selected-byte digests, and repository-relative ranges.

It does not contain source content, excerpts, unified patches, the object-root path, repository label text, raw commit digests, environment data, credentials, or parser token text. Repository-relative paths, whole-file head digests, and selected-byte evidence digests are intentionally emitted and can be sensitive. Digests can support content-membership guesses. Callers must govern storage and forwarding.

Status values are:

- `findings`: at least one finding and no unsupported delta entries;
- `inconclusive`: review ran but the rule found nothing;
- `partial`: review findings or coverage exist alongside unsupported delta entries;
- `no_change`: base and head produced the same accepted manifest;
- `unsupported`: changed entries exist but none produced a supported `Change`.

## Exit codes

- `0`: a findings record was fully written;
- `1`: root, acquisition, graph, resource, review, encoding, close, or output failure;
- `2`: command grammar or canonical input failure;
- `3`: an inconclusive, partial, no-change, or unsupported record was fully written.

Operational and usage failures emit no success JSON. Output is buffered and written once after the object root closes, but a low-level write failure can still truncate the stream.

## Evidence boundary

The command proves only the identities and bounded rule behavior represented by the emitted acquisition, change, opaque entry, coverage, finding, and evidence contracts. It does not prove repository origin, ownership, authorization, ref reachability, ancestry, merge-base correctness, atomic snapshot stability, working-tree state, semantic review completeness, model quality, policy approval, tenant isolation, or publication readiness. It performs no autofix and retains no source bytes after the synchronous review scope.
