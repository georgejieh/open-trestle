# Local Git change evidence

`trestle local-git change` compares two caller-selected loose Git commits and emits compact change evidence.

```text
trestle local-git change \
  --objects-root PATH \
  --repository-authority AUTHORITY \
  --repository-namespace SEGMENT[/SEGMENT...] \
  --repository-name NAME \
  --revision-algorithm sha1|sha256 \
  --base-revision-digest FULL_LOWERCASE_HEX \
  --head-revision-digest FULL_LOWERCASE_HEX
```

All seven flags are required exactly once. `PATH` is the exact loose-object directory, normally `.git/objects`. Base and head are ordered caller selections. The command does not infer a merge base, resolve refs or `HEAD`, inspect an index or working tree, discover `.git`, append path components, run Git, read Git configuration, use credentials, or access a network. Packs and alternates are not supported.

Repository authority, namespace, and name are caller-supplied scope labels. They do not establish the origin, owner, or authorization of the object directory.

## Output

The command buffers one `open-trestle/local-git-change-result` JSON object and writes it followed by one newline after the object root closes successfully. The object contains only compact identities, counts, documented repository-relative changed paths, change kinds, supported or unsupported states, unsupported reasons, and optional file-change and line-map identities. It does not contain the object-root path, repository label text, raw commit digest, source content, unified patch, timestamps, host data, environment data, credentials, or command output.

Entry order is the canonical manifest-delta path order. Added and removed paths are explicit unsupported outcomes under the current modified-file `Change` contract. NUL-bearing or diff-over-budget modified files also remain explicit unsupported outcomes. A supported entry carries authenticated `FileChange` and `LineMap` identities. The aggregate `change` identity includes supported entries only; counts and the complete entry array make partial coverage explicit.

The status is one of:

- `complete`: every changed path produced supported modified-file evidence;
- `no_change`: the two accepted manifests are equal;
- `partial`: at least one path is supported and at least one is unsupported;
- `unsupported`: changed paths exist, but none produced supported evidence.

Repository-relative paths can be sensitive. The command intentionally emits them so a local caller can identify accounted changes. Callers must govern storage and forwarding of the JSON record.

## Exit codes

- `0`: a complete or no-change record was fully written;
- `1`: root, acquisition, graph, resource, encoding, close, or output failure;
- `2`: command grammar or canonical input failure;
- `3`: a partial or unsupported record was fully written.

Operational and usage failures emit no success JSON. The output is prepared in memory and written once, but a low-level output failure can still produce a truncated stream.

## Evidence boundary

The command confines reads beneath one exact opened directory handle. Each distinct requested revision is acquired once through the same local adapter; equal requests are acquired once. Accepted object graphs produce structural bindings and profiles. At most 64 changed paths are processed. Every accepted delta entry produces one opaque supported or unsupported execution, and source maps are discarded before return.

This does not prove that the directory belongs to the repository label. It does not prove ownership, authorization, ref reachability, ancestry, merge-base correctness, temporal order, atomic snapshot stability, working-tree or index state, adapter provenance, tenant isolation, or sandboxing. It does not infer renames or copies, report mode-only changes, retain source, produce Go impact analysis, perform review, or publish findings.
