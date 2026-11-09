# GitHub immutable source acquisition

`adapters/scm/github` implements the provider-neutral `scm.SourceAdapter` contract for GitHub repositories. It retrieves one full commit by object ID and returns a canonical manifest with optional exact file content. It does not clone a worktree, run Git, execute repository files, or write source to disk.

## Trust and integrity model

Acquisition uses three independent checks:

1. The GitHub commit-object endpoint must return the exact requested commit ID and one root tree ID.
2. The recursive tree response must be complete. The adapter reconstructs every Git tree object from its modes, names, child object IDs, and Git ordering rules. Every reconstructed subtree ID and the root tree ID must match GitHub's response.
3. The temporary tar archive is read without filesystem extraction. Every archive file must have an exact tree entry, size, type, and Git blob object ID. The archive and tree must contain the same file set.

The HTTPS GitHub commit endpoint remains the authority that binds the requested commit ID to its root tree. Tree and blob correspondence after that binding is cryptographically checked with the repository's SHA-1 or SHA-256 Git object format. The resulting Open Trestle manifest additionally records SHA-256 over each exact supplied file.

A recursive tree marked `truncated` is rejected. GitHub documents a recursive limit of 100,000 entries and 7 MB. Open Trestle applies the smaller manifest limit of 65,536 tree entries and also bounds metadata, compressed bytes, individual files, and total extracted content. Individual files are capped at 10 MiB so they can be represented by the protected source-file artifact contract. Git submodules are rejected because a gitlink is not file content. Symbolic links are preserved as link-target bytes and are never followed.

## Scope and authorization

An adapter instance binds one canonical repository authority, API endpoint, API version, and bounded archive-authority allowlist. Requests must use:

- the exact configured repository authority
- one lowercase GitHub owner and repository name
- a full immutable Git commit ID
- read-only effect authority
- the exact adapter identity
- manifest or manifest-and-content capability

A mismatch is blocked before network access. `TokenProvider` retrieves a token separately for every GitHub API request. A nil provider enables documented anonymous access for public resources. Typed-nil providers are rejected rather than silently selecting anonymous access.

Setup permission validation is separate from source acquisition. `trestle setup check integration` uses a dedicated GitHub App user access token to inspect one exact installation and the separate runtime installation token to inspect selected repository scope, admits only metadata, contents, and pull-request read permission, and grants no acquisition or publication authority.

The default API endpoint is `https://api.github.com`. The default pinned API version is `2026-03-10`; an operator can select another exact `YYYY-MM-DD` version for GitHub Enterprise compatibility. Plain HTTP is accepted only for an IP-literal loopback endpoint.

## Archive redirects

GitHub's archive endpoint returns a temporary redirect. The adapter never follows it automatically. It validates the new scheme, exact authority, repository path, and commit suffix against the configured allowlist, then issues a second request without the GitHub authorization header. Further redirects are rejected. Signed query values on an approved temporary URL are not logged or included in adapter formatting.

The adapter rejects path traversal, mixed archive roots, duplicate files, hard links, devices, and other special archive entries. The archive root must be a zero-size directory. Every tar entry, including skipped directories, counts toward a 65,537-entry limit. All decompressed bytes, including tar metadata, padding, skipped content, and trailing gzip data, count toward a separate 384 MiB stream limit; retained file content remains capped at 256 MiB. Reads check cancellation in bounded chunks. It parses tar data as an input stream and never materializes an archive path on the host filesystem.

## Merge base

The adapter also implements `scm.MergeBaseResolver`, which reports the merge base GitHub uses for a pull request diff (`merge-base...head`). It sends one `GET /repos/{owner}/{repo}/compare/{base}...{head}?per_page=1` with the same repository, endpoint, version, credential, and request-shape checks as acquisition, bounds the response to the 16 MiB metadata limit, rejects duplicate or non-lowercase members anywhere in it, and reads only `merge_base_commit.sha`, which must be a full object ID of the requested algorithm. Commit lists, file lists, status, and counts are ignored. `merge_base_commit` is required by GitHub's compare response schema; a response without a valid one is unavailable (`artifact_incomplete`). A compare that GitHub reports as not found is unavailable whatever its body (`adapter_failure`, retried like any failed read): GitHub's message for commits with no common ancestor is not sourced in this repository, so the adapter never reports `MergeBaseNone` and unrelated histories surface as `merge_base_unavailable`. Other failures use the acquisition classification below. The brokered source transport admits exactly this compare shape (two full object IDs of one length, three dots, `per_page=1`) beside the commit, tree, and archive reads. Resolution writes nothing and is not acquisition: the resolved commit is then acquired like any other.

## Terminal outcomes

Authentication failures and unsafe scope changes become typed blocked results. Rate limits, timeouts, and server failures become typed adapter-unavailable results. Truncated trees and size limits become resource-limit results. Tree, archive, blob, or schema mismatches become artifact-incomplete results. Provider response bodies and token-provider errors are not copied into receipts.

The endpoint behavior follows GitHub's official documentation for [commit objects](https://docs.github.com/en/rest/git/commits#get-a-commit-object), [recursive trees](https://docs.github.com/en/rest/git/trees#get-a-tree), [repository tar archives](https://docs.github.com/en/rest/repos/contents#download-a-repository-archive-tar), and [commit comparison](https://docs.github.com/en/rest/commits/commits#compare-two-commits). The lowercase-member rule for compare responses is unverified against live GitHub.
