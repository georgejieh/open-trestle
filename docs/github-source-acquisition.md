# GitHub source acquisition

`adapters/scm/github` implements the provider-neutral `scm.SourceAdapter` contract for GitHub repositories. Given a commit ID, it fetches that one full commit and returns a canonical manifest of its files, with file content if requested. It does not clone a worktree, run Git, execute repository files or write source to disk.

## How the adapter checks integrity

Acquisition makes three checks:

1. The GitHub commit-object endpoint must return the requested commit ID and one root tree ID.
2. The recursive tree response must be complete. The adapter rebuilds every Git tree object from its modes, names, child object IDs and Git's ordering rules. Every rebuilt subtree ID and the root tree ID must match GitHub's response.
3. The adapter reads the temporary tar archive without extracting it to the filesystem. Every file in the archive must have a tree entry with the same path, size, type and Git blob object ID, and the archive and the tree must contain the same set of files.

The HTTPS GitHub commit endpoint ties the requested commit ID to its root tree, and from there the tree and blob contents are checked in the repository's SHA-1 or SHA-256 Git object format. The Open Trestle manifest also records a SHA-256 hash of each file as supplied.

The adapter rejects a recursive tree marked `truncated`. GitHub documents a recursive limit of 100,000 entries and 7 MB, but Open Trestle applies its smaller manifest limit of 65,536 tree entries. It also limits metadata, compressed bytes, individual files and total extracted content. Individual files are capped at 10 MiB so that the protected source-file artifact contract can represent them. The adapter rejects Git submodules, because a gitlink is not file content, and it keeps symbolic links as the bytes of their link target without following them.

## Scope and authorization

An adapter instance is bound to one canonical repository authority, one API endpoint, one API version and an allowlist of archive hosts. Every request must carry all of these:

- The configured repository authority.
- One lowercase GitHub owner and repository name.
- A full immutable Git commit ID.
- Read-only effect authority.
- The adapter identity.
- The capability to read a manifest, or a manifest and content.

A request that does not match is blocked before any network access. `TokenProvider` retrieves a token separately for every GitHub API request. A nil provider allows documented anonymous access to public resources, but a typed-nil provider is rejected so that it cannot select anonymous access by accident.

The default API endpoint is `https://api.github.com`, and the default pinned API version is `2026-03-10`. For GitHub Enterprise compatibility, an operator can select another exact `YYYY-MM-DD` version. Plain HTTP is accepted only for an IP-literal loopback endpoint.

## Archive redirects

GitHub's archive endpoint answers with a temporary redirect, which the adapter does not follow automatically. Instead, it checks the new scheme, authority, repository path and commit suffix against the configured allowlist, then issues a second request without the GitHub authorization header. It rejects any further redirect. Signed query values on an approved temporary URL are not logged and do not appear when the adapter is formatted.

The adapter rejects path traversal, mixed archive roots, duplicate files, hard links, devices and other special archive entries, and the archive root must be a zero-size directory. Every tar entry counts toward a limit of 65,537 entries, including skipped directories. All decompressed bytes, including tar metadata, padding, skipped content and trailing gzip data, count toward a separate 384 MiB stream limit. Retained file content is still capped at 256 MiB. Reads check for cancellation in chunks. The adapter parses tar data as an input stream and does not create an archive path on the host filesystem.

## Merge base

The adapter also implements `scm.MergeBaseResolver`, which reports the merge base that GitHub uses for a pull request diff (`merge-base...head`). It sends one `GET /repos/{owner}/{repo}/compare/{base}...{head}?per_page=1`, which gets the same repository, endpoint, version, credential and request-shape checks as acquisition.

The adapter handles the response as follows:

- It bounds the response to the 16 MiB metadata limit.
- It rejects duplicate or non-lowercase members anywhere in the response.
- It reads only `merge_base_commit.sha`, which must be a full object ID of the requested algorithm.
- It ignores commit lists, file lists, status and counts.
- GitHub's compare response schema requires `merge_base_commit`, so a response without a valid one counts as unavailable (`artifact_incomplete`).

If GitHub reports that the compare was not found, the result is unavailable whatever the body says (`adapter_failure`, retried like any failed read). The adapter does not report `MergeBaseNone`, so commits with no common ancestor show up as `merge_base_unavailable`. Other failures use the classification in the next section.

Besides the commit, tree and archive reads, the brokered source transport allows only this compare shape: two full object IDs of the same length, three dots and `per_page=1`. Resolving the merge base writes nothing and is not acquisition; Open Trestle then acquires the resolved commit like any other.

## Terminal outcomes

Authentication failures and unsafe scope changes become typed blocked results. Rate limits, timeouts and server failures become typed adapter-unavailable results. A truncated tree or a size limit becomes a resource-limit result. A mismatch in a tree, archive, blob or schema becomes an artifact-incomplete result. Provider response bodies and token-provider errors are not copied into receipts.

The endpoint behavior follows GitHub's official documentation for [commit objects](https://docs.github.com/en/rest/git/commits#get-a-commit-object), [recursive trees](https://docs.github.com/en/rest/git/trees#get-a-tree), [repository tar archives](https://docs.github.com/en/rest/repos/contents#download-a-repository-archive-tar) and [commit comparison](https://docs.github.com/en/rest/commits/commits#compare-two-commits). The lowercase-member rule for compare responses is unverified against live GitHub.
