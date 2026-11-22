# GitHub pull-request review

There are two ways to run Open Trestle on a GitHub pull request. They differ in setup, state and who posts. Only the Actions path posts results to the pull request.

| | GitHub Actions path | Daemon and GitHub App path |
| --- | --- | --- |
| What runs | `trestle local-git model-review` inside a workflow job | `trestled` with webhook ingress, source acquisition and local workers |
| Who posts | Existing tools: `github/codeql-action/upload-sarif` and `reviewdog`, using the job's own `GITHUB_TOKEN` | Nobody. The daemon does not publish reviews to GitHub. Read results through the daemon API, the TUI, the console, MCP or LSP |
| State | None. Each job makes one foreground, short-lived run | Durable runs and journals under the daemon's state directory |
| Setup | A workflow file, a provider secret and a packaged `trestle` binary | A GitHub App for webhooks and read-only source access, a webhook endpoint with its secret, and the daemon's source and runtime configuration |
| Output | SARIF (code scanning alerts), inline review comments and a job summary | Run receipts and review diagnostics |
| Fork pull requests | Not supported (no secrets, read-only token) | Not supported (the planner accepts only pull requests whose base and head are the configured repository) |

Neither path has run against GitHub. The Actions example has never run on a hosted runner. Open Trestle ships no GitHub App of its own: on the daemon path you register an App on your own account and run the daemon yourself. There is also no packaged `action.yml` (see the [roadmap](roadmap.md#next-release)).

Use the Actions path to try Open Trestle on a repository you control, with no server. Use the daemon path when you need durable runs. For the daemon path, see [webhook ingress](webhook-ingress.md) and [source acquisition](github-source-acquisition.md).

## Which changes are reviewed

Both paths review a pull request the way GitHub presents it: from the merge base of `pull_request.base.sha` and `pull_request.head.sha` up to the head. The Actions path computes the merge base with `git merge-base` in the checkout. The daemon path plans a `source-base` task that reads GitHub's merge base with one compare request and then acquires that commit. As a result, commits merged into the base branch after the branch point are never reported as reverse changes.

On the daemon path, a run fails in two cases:

- If the head equals the base or is already contained in it, the run fails with policy and the recorded reason `nothing_to_review`.
- If GitHub does not report a merge base, the run fails with `merge_base_unavailable`. This includes commits that share no history, because GitHub answers that compare with not found.

The daemon does not fall back to reviewing `base.sha` directly.

## How the Actions path fits together

1. `actions/checkout` runs with `fetch-depth: 0`, so the head, the base branch tip and the history between them are all present.
2. A `trestle` binary with its secret scan helper is installed. A plain `go build` pins no helper and refuses every review; see [remote model review](remote-model-review.md#prerequisite-1-a-trestle-with-its-secret-scanner).
3. `trestle setup bootstrap init --provider ...` and `check` write and verify the protected configuration and print the review command. That command carries `--specialists auto` unless `init` is given `--specialists none`. The provider key is passed through an environment variable whose name starts with `OPEN_TRESTLE_PROVIDER_`.
4. `trestle local-git model-review ... --format sarif --exit-code-policy findings` runs with the merge base `git merge-base "$BASE_SHA" "$HEAD_SHA"` as the base and `head.sha` as the head. `BASE_SHA` is `github.event.pull_request.base.sha`, the tip of the base branch when the event fired. Both SHAs are passed through `env`, not interpolated into `run:`.
5. The workflow uploads the SARIF only when the run succeeded (`trestleRunStatus` is `succeeded`). Uploading the empty result of a refused or failed run could close open alerts for the same category.

The upload sets `sha` to the pull request head and `ref` to `refs/pull/<number>/head`, because `upload-sarif` otherwise uses `github.sha`, the temporary merge commit. These inputs follow the `upload-sarif` documentation and are unverified live.

After the upload, the workflow posts inline comments with reviewdog, writes a job summary, and fails the job from the recorded exit status. Both the comments and the summary are GitHub Markdown, so the example first escapes the finding text, fix guidance and paths with a small `jq` module that follows the rules of `--format markdown`.

The step-by-step workflow, with its placeholders and caveats, is [`examples/github-actions/open-trestle-review.yml`](../examples/github-actions/open-trestle-review.yml) and its [README](../examples/github-actions/README.md). The SARIF mapping and the exit policy are specified in [local model review](local-model-review.md#headless-ci-use).

## What a green job means

`--exit-code-policy findings` exits 0 when the review ran to completion and no verified high or critical finding exists. Under this policy, the following do not fail the job:

- Medium and low findings.
- Pre-existing findings: on unchanged lines the change provably cannot reach (marked `trestlePreExisting` in the SARIF). A high or critical finding on unchanged lines that the change may affect (marked `trestleUnprovenOrigin`) still fails the job.
- Coverage gaps.

They still appear in the SARIF and in the summary, listed in rank order.

A green job does not mean the change is clear: abstentions and omitted source are listed as limitations in the SARIF, and `comprehensive_clearance` is always false. A job that could not run the review fails. That covers a refused review, an unreadable change, a missing secret and a provider failure.

## Status

The status of the Actions path:

- Tested offline in the repository tests, against synthetic model transports and inputs: the SARIF projection, the fingerprints, the exit policy, the diagnostics for shallow and partial checkouts, that the example workflow parses as YAML, and that its `jq` module escapes finding text, fix guidance and paths the way Open Trestle's Markdown renderer does.
- Not run on GitHub: the workflow has not executed on a hosted runner. The `upload-sarif`, `reviewdog`, `setup-go` and checkout steps, the source build of the packaged binary on a runner, the `jq` extraction of the review command and live provider behavior are written from documentation. The example pins action major versions only, and it tells you to pin commit SHAs. No Open Trestle release exists, so the release-artifact install is a placeholder.
- Fork pull requests do not receive repository secrets and get a read-only `GITHUB_TOKEN`, so the example skips them. Do not switch to `pull_request_target` to work around this: it would run with secrets against code from the fork.
- Source and findings are sent to the model provider you configure; see [privacy](privacy.md).
