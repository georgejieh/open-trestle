# Manual review feedback

`trestle local-git retained-memory-input` lets you record your own notes about a
past review so that a later review can take them into account. It writes a
protected advisory snapshot from a protected, completed foreground model-review
JSON result. The snapshot does not change findings.

To author a snapshot, use `--review-input PATH` instead of `--revision-algorithm`
and `--head-revision-digest`. Keep the other arguments from the existing authoring
command: the repository labels, tenant, logical repository, route inventory,
runtime policy, local-only egress, timeout, validity, feedback input and new
output. The review result must meet all of these conditions:

- it has schema version 1, 4, 5 or 6;
- its terminal status is succeeded;
- it contains a canonical verified diagnostic set whose scope, repository, head
  and runtime policy match.

The file is supplied by the operator. Open Trestle does not authenticate who
wrote it.

The protected convenience feedback file can contain:

```json
[{"path":"a.go","start_line":4,"decision":"dismiss","text":"The caller rejects zero before this path."},
 {"path":"caller.go","text":"Prefer actionable defects over style suggestions."}]
```

`confirm`, `dismiss` and `advisory` each select exactly one verified finding, by
its repository-relative path and start line. A missing or ambiguous match
is refused. A deterministic observation is not a verified finding.

Legacy path-and-text entries remain scoped review preferences, and they do not
change policy. The current bound is one record per path, so select a different
path for each entry. Open Trestle refuses unknown keys, duplicate keys and paths,
malformed selectors, and text that is over budget. The decision and the derived
review, set and finding identities count toward the existing 1024-byte text limit.
The seven-day lifetime and the other retained-input bounds apply.

The output records remain `human_feedback` with `user_controlled` taint. They are
advice. Dismissing a finding does not suppress it, approve a change, change
severity or publish a review.

A later local model review uses the file only when you pass the explicit `--retained-memory-input PATH` flag. Both roles can receive advice
selected through the existing bounded changed-path retrieval, but loading the file
does not guarantee that any advice is selected. A review with another head or
policy refuses the file. Open Trestle does not relabel or extend a file
automatically.

## Remove future local input

To remove an input file, use the same repository, scope and configuration
arguments, `--review-input`, `--egress local-only` and `--timeout`. Add
`--remove-input PATH` instead of `--valid-for`, `--feedback-input` and `--output`.

The command validates the retained declaration against that scope and
policy, including record identities, before it removes the captured entry. It can
remove expired matching input, but expired input cannot be reused. It refuses
missing or mismatched input. The target must be a protected regular mode-0600
file. On success, the command prints `open-trestle/retained-memory-removal-result`
v1 with the removed input, scope, repository, head and policy identities.

Removal samples and rechecks the identities, bytes and metadata of the file and
its parent. It then removes the file relative to the opened parent and synchronizes
that directory. It does not make the compare-and-unlink atomic against other code
that runs with the same user's privileges. If Open Trestle detects a replacement before removal, it
refuses. If an I/O failure happens after removal, the command reports an
incomplete operation. A failed command does not tell you whether the file remains.

A saved command that names the removed path refuses before any model call. If you
omit the input flag on a later review, the review uses empty memory. Removal
affects only that local path. It cannot revoke copies, undo an in-flight request,
erase acquired context, or change historical findings and results.

To remove part of a snapshot, author a narrower new snapshot explicitly, and then
remove the old input using the review for the same head and policy as that old
input. Keep that matching review for cleanup after a head change, because a review
at the new head cannot remove it. No background learning, cleanup, discovery or
cross-head change occurs.
