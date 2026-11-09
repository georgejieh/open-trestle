# GitHub pull-request review

There are two ways to get Open Trestle results onto a GitHub pull request. They
are different products with different trust and maturity.

| | GitHub Actions path | Daemon and GitHub App path |
| --- | --- | --- |
| What runs | `trestle local-git model-review` inside a workflow job | `trestled` with webhook ingress, source acquisition and the publication gate |
| Who posts | existing tools: `github/codeql-action/upload-sarif` and `reviewdog`, using the job's own `GITHUB_TOKEN` | the Open Trestle publication adapter, as a GitHub App |
| State | none; one foreground, ephemeral run per job | durable runs, journals, idempotent publication |
| Setup | a workflow file, a provider secret and a packaged `trestle` binary | a GitHub App, webhook endpoint, storage and operator approvals |
| Output | SARIF (code scanning alerts), inline review comments, job summary | a `COMMENT` review pinned to the reviewed head |
| Fork pull requests | not supported (no secrets, read-only token) | depends on the App installation |

Use the Actions path to try Open Trestle on a repository you control with no
server. Use the daemon path when you need durable runs, a fresh-head fence and
idempotent publication. See [GitHub publication](github-publication.md),
[webhook ingress](webhook-ingress.md), [source acquisition](github-source-acquisition.md)
and [integration permissions](github-integration-permissions.md) for that path.

Both paths review a pull request the way GitHub presents it: from the merge base
of `pull_request.base.sha` and `pull_request.head.sha` to the head. The Actions
path computes it with `git merge-base` in the checkout. The daemon path plans a
`source-base` task that reads GitHub's merge base with one compare request and
acquires that commit, so commits merged into the base branch after the branch
point are never reported as reverse changes. When the two commits share no
history, or the head equals the base or is already contained in it, the daemon
run fails with policy and the recorded reason `no_merge_base` or
`nothing_to_review`; when GitHub does not report a merge base it fails with
`merge_base_unavailable`. It never falls back to reviewing `base.sha` directly.

## How the Actions path fits together

1. `actions/checkout` with `fetch-depth: 0` so the head, the base branch tip and
   the history between them exist.
2. A packaged `trestle` binary. Remote model egress is refused by a plain
   `go build`; see [remote model review](remote-model-review.md).
3. `trestle setup bootstrap init --provider ...` and `check` write and verify the
   protected configuration and print the review command. The provider key is passed
   through an environment variable whose name starts `OPEN_TRESTLE_PROVIDER_`.
4. `trestle local-git model-review ... --format sarif --exit-code-policy findings`
   with the merge base `git merge-base "$BASE_SHA" "$HEAD_SHA"` as the base and
   `head.sha` as the head. `BASE_SHA` is `github.event.pull_request.base.sha`, the
   base branch tip when the event fired; reviewing against it directly would treat
   commits merged into the base branch since the branch point as part of the
   change. Both SHAs are passed through `env`, never interpolated into `run:`.
5. Upload the SARIF only when the run succeeded (`trestleRunStatus` is
   `succeeded`), because uploading an empty refused or failed run for the same
   category could close open alerts. The upload sets `sha` to the pull request
   head and `ref` to `refs/pull/<number>/head`; `upload-sarif` otherwise uses
   `github.sha`, the temporary merge commit. These inputs follow the
   `upload-sarif` documentation and are unverified live. Then post inline
   comments with reviewdog, write a job summary, and fail the job from the
   recorded exit status.

The step-by-step workflow, with its placeholders and caveats, is
[`examples/github-actions/open-trestle-review.yml`](../examples/github-actions/open-trestle-review.yml)
and its [README](../examples/github-actions/README.md). The SARIF mapping and exit
policy are specified in [local model review](local-model-review.md#headless-ci-use).

## What a green job does and does not mean

`--exit-code-policy findings` exits 0 when the review ran to completion and no
verified high or critical finding exists. It does not mean the change is clear:
the review is bounded, abstentions and omitted source are listed as limitations
in the SARIF, and `comprehensive_clearance` is always false. A job that could not
run the review (refused, unreadable change, missing secret, provider failure) fails.

## Status

Honest status of the Actions path:

- Verified offline: the SARIF projection, fingerprints, exit policy, shallow and
  partial checkout diagnostics, and that the example workflow parses as YAML. These
  run against synthetic model transports in the repository tests.
- Not verified: any run on GitHub. The workflow has not executed on a hosted
  runner. The `upload-sarif`, `reviewdog`, `setup-go` and checkout steps, the
  source build of the packaged binary on a runner, the `jq` extraction of the
  review command, and live provider behavior are written from documentation and
  unrun. The example pins action major versions only and tells you to pin commit
  SHAs. No Open Trestle release exists, so the release-artifact install is a
  placeholder.
- Fork pull requests do not receive repository secrets and get a read-only
  `GITHUB_TOKEN`, so the example skips them. Do not switch to `pull_request_target`
  to work around this: it would run with secrets against code from the fork.
- Source and findings are sent to the model provider you configure. Review that
  provider's terms before enabling the workflow on private code.
