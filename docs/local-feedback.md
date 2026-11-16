# Manual review feedback

`trestle local-git retained-memory-input` can author a protected advisory snapshot
from a protected completed foreground model-review JSON result. It does not
change findings or establish human adjudication.

Use `--review-input PATH` instead of `--revision-algorithm` and
`--head-revision-digest`. Keep the repository labels, tenant, logical repository,
route inventory, runtime policy, local-only egress, timeout, validity, feedback
input and new output arguments from the existing authoring command. The result
must be schema version 1, 4, 5 or 6, terminal succeeded, and contain a canonical verified
diagnostic set with matching scope, repository, head and runtime policy. The
file is operator-supplied evidence, not authenticated authorship or source custody.

The protected convenience feedback file can contain:

```json
[{"path":"a.go","start_line":4,"decision":"dismiss","text":"The caller rejects zero before this path."},
 {"path":"caller.go","text":"Prefer actionable defects over style suggestions."}]
```

`confirm`, `dismiss` and `advisory` select exactly one verified finding by exact
repository-relative path and start line. Missing and ambiguous matches refuse.
A deterministic observation is not a verified finding. Legacy path/text entries
remain scoped review preferences; they do not change policy. The current bound
remains one record per path, so select a different path for each entry. Unknown
keys, duplicate keys and paths, malformed selectors and over-budget text refuse.
The decision and derived review/set/finding identities count toward the existing
1024-byte text limit. The seven-day lifetime and all other retained-input bounds
remain unchanged.

The output records remain `human_feedback` with `user_controlled` taint. They are
advice, not truth or authority. Dismissal does not suppress a finding, approve a
change, bypass independent verification, change severity or publish a review.
Only the explicit `--retained-memory-input PATH` flag on a later ordinary local
model review admits the file. Both roles can receive advice selected through the
existing bounded changed-path retrieval. Loading does not guarantee selection.
Another head or policy refuses; no file is automatically relabeled or extended.

## Remove future local input

To remove the exact input file, use the same repository/scope/configuration,
`--review-input`, `--egress local-only` and `--timeout` arguments, with
`--remove-input PATH` instead of `--valid-for`, `--feedback-input` and `--output`.
The command validates the retained declaration against that exact scope and
policy, including record identities, before removing its captured entry. Expired
matching input can be removed but cannot be reused. Missing or mismatched input
refuses. The target must be a protected regular mode-0600 file. Success emits
`open-trestle/retained-memory-removal-result` v1 with removed input/scope/repository/
head/policy identities and no advice, path, expired-validity or record-count claim.

Removal samples and rechecks file and parent identities, bytes and metadata,
then removes relative to the opened parent and synchronizes that directory.
It does not claim an atomic compare-and-unlink against concurrent hostile code
with the same user's privileges. The supported installation trusts that user.
Replacement detected before removal refuses. I/O failure after removal reports
an incomplete operation; do not infer that the file remains or was removed
merely from a failed command.

A saved command naming the removed path refuses before model calls. Omitting
the input flag on a later review uses empty memory. Removal affects only that
local path. It cannot revoke copies, undo an in-flight request, erase acquired
context or mutate historical findings/results. To remove part of a snapshot,
author a narrower new snapshot explicitly, then remove the old input using the
review for the same head and policy as that old input. Keep that matching review
for cleanup after a head change; a review at the new head cannot remove it. No
background learning, cleanup, discovery or cross-head mutation occurs.
