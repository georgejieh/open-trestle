# Local Git inspection

`trestle local-git inspect` reads one exact loose Git commit beneath a caller-supplied object directory and emits a compact evidence record.

```text
trestle local-git inspect \
  --objects-root PATH \
  --repository-authority AUTHORITY \
  --repository-namespace SEGMENT[/SEGMENT...] \
  --repository-name NAME \
  --revision-algorithm sha1|sha256 \
  --revision-digest FULL_LOWERCASE_HEX
```

All flags are required exactly once. The path is the exact object directory, normally `.git/objects`. The command does not discover repositories, append path components, resolve refs or `HEAD`, inspect an index or working tree, run Git, read Git configuration, use credentials, or access a network. Packed objects and alternates are not supported.

Repository authority, namespace, and name are caller-supplied scope labels. They do not establish the origin, owner, or authorization of the object directory.

## Output

Success writes one compact JSON object followed by a newline. The contract is `open-trestle/local-git-inspect-result`, schema version 1, with strict public shape `schemas/review/local-git-inspect-result-v1.schema.json`. It contains only the structural status, content coverage, and identities for the envelope, repository label, revision, adapter, request, receipt, acquisition execution, profiled acquisition execution, evidence binding, manifest, verified commit, verified tree graph, manifest correspondence, and profile bundle.

The command does not print the object-root path, repository labels, raw revision digest, file paths, repository content, profile internals, timestamps, host data, or environment data. The status `supplied_evidence_bound` means structural agreement only.

## Exit codes

- `0`: the envelope was built, encoded, the object root closed, and the full record written.
- `1`: object-root, confinement, loose-object, envelope, profile, close, encoding, or output failure.
- `2`: command grammar or canonical input failure.

Nonzero results do not emit a success record.

## Evidence boundary

The command confines reads beneath the exact opened directory handle. It verifies the supplied loose commit, tree, and blob bytes using the selected hash algorithm, verifies the complete supported tree graph and its manifest correspondence, and derives structural binding and deterministic repository profiling from one acquisition.

This does not prove that the directory belongs to the repository label. It does not prove ownership, authorization, ref reachability, branch state, working-tree or index state, snapshot authority, adapter provenance, tenant isolation, or sandboxing. It performs no review, change calculation, publication, command execution, source mutation, or content output.
