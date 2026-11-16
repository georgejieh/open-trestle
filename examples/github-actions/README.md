# GitHub Actions example

`open-trestle-review.yml` is an example workflow that runs an Open Trestle model
review on each pull request. It reports the review three ways: as code scanning
alerts (SARIF), as inline pull-request review comments, and as a job summary. It
reuses `github/codeql-action/upload-sarif` and `reviewdog`, and Open Trestle posts
nothing to GitHub itself in this path.

Status: this workflow has never run on GitHub. The Open Trestle side (SARIF, exit
policy, checkout diagnostics) is tested offline. The workflow file itself is
checked only for being well-formed YAML and for its `jq` escaping module. Treat
every GitHub-facing step as unverified, and read the logs of your first run. See
[GitHub pull-request review](../../docs/github-pr-review.md).

## Before you copy it

Make these five changes before you use the workflow.

1. Check the install step. No Open Trestle release exists yet, so the workflow
   builds the unsigned Linux candidate from source, following
   [operations](../../docs/operations.md). That step is untested on a hosted
   runner and takes a while. The commented `PLACEHOLDER` block shows where a
   pinned release artifact and its checksum go once one exists. Set
   `OPEN_TRESTLE_REF` to a commit SHA.
2. Set the models. Set `GENERATION_MODEL` and `VERIFICATION_MODEL` to two
   different models. The job refuses to run while they still begin with `YOUR_`.
3. Add the secret. Add the repository secret `OLLAMA_API_KEY`. The workflow maps
   it to the variable name `OPEN_TRESTLE_PROVIDER_OLLAMA_CLOUD` that bootstrap
   records, and only the name is stored in the protected configuration. For
   OpenRouter ZDR or OpenCode Go, change `--provider` and the credential
   variable, and add the account and evidence declarations in
   [remote model review](../../docs/remote-model-review.md). Those declarations
   are attestations that a person should make, which is why the example uses
   `ollama-cloud`. Ollama Cloud makes no retention claim, so check its terms
   before you send private code.
4. Pin the actions. `actions/checkout`, `actions/setup-go`,
   `github/codeql-action/upload-sarif` and `reviewdog/action-setup` appear with
   major-version tags so that the file is readable. Replace each with a full
   commit SHA before you use it.
5. Check code scanning. `upload-sarif` needs code scanning to be enabled (free
   for public repositories; GitHub Code Security for private ones). Delete that
   step and the `security-events: write` permission if you do not use it.

## What the job does

- It checks out the pull request head with `fetch-depth: 0`. A shallow checkout
  makes `model-review` stop before any model call and print how to fetch the base
  (`git fetch --no-tags --depth=N origin <base>`). It never fetches for you.
- It computes the review base as `git merge-base "$BASE_SHA" "$HEAD_SHA"`, from
  `github.event.pull_request.base.sha` and `head.sha` (passed through `env`, never
  interpolated into a script). The tip of the base branch would count commits
  merged into the base branch after the branch point as part of the change. The
  merge base is the comparison that GitHub shows for the pull request.
- It runs `trestle setup bootstrap init`, then `check`, then the printed review
  command. Because `init` is not given `--specialists none`, that command carries
  `--specialists auto`. The job then runs the general review plus the specialists
  that Open Trestle selects, one after another, and each is a paid model run. Add
  `--specialists none` to the `init` step for a single review. The job runs the
  command with `--format text` replaced by
  `--format sarif --exit-code-policy findings`, and with the base and head set to
  that merge base and `head.sha`.
- It uploads SARIF to code scanning only when the SARIF run property
  `trestleRunStatus` is `succeeded` (a `jq` check). The SARIF of a refused, failed
  or canceled run has no results, and uploading it could close open alerts as if
  they were fixed. The upload passes `sha` (the pull request head) and `ref`
  (`refs/pull/<number>/head`), because `upload-sarif` otherwise uses `github.sha`,
  the temporary merge commit. Those inputs come from the `upload-sarif`
  documentation and are unverified live.
- It lists findings in rank order. A finding on lines that the change did not
  touch carries `trestlePreExisting` in the SARIF properties. Under
  `--exit-code-policy findings`, that finding and any medium or low finding do not
  fail the job. The job summary counts every result and does not mark
  pre-existing ones.
- It posts inline comments and the job summary from whatever SARIF was produced,
  and then fails the job from the recorded status. The job exits 0 only when the
  review completed with no verified high or critical finding. Refusals,
  unreadable changes and failures fail the job and appear as an unsuccessful
  invocation in the SARIF.
- It renders the job summary from the SARIF with `jq`. One review (several model
  runs when specialists are on) yields one output format, so the example does not
  run a second time for `--format text` or `--format markdown`.

Finding text, fix guidance and paths are untrusted, because they come from model
output and repository text. Both the job summary and reviewdog's pull-request
comments are GitHub Markdown, so a step first writes a small `jq` module,
`trestle-markdown.jq`, that escapes such text with the rules of Open Trestle's own
Markdown renderer (`localreview.MarkdownText` and `MarkdownCode`). The escaped
text cannot open emphasis, a link, an image, a heading, a table cell or an HTML
tag, and it cannot @-mention anyone. No URL, `www.` host or email address becomes
an autolink. The summary is rendered through the module, and reviewdog reads an
escaped copy of the SARIF (`open-trestle.reviewdog.sarif`). The SARIF for code
scanning keeps the raw text. The repository test runs the module with `jq` against
crafted SARIF and compares the output byte for byte with the Go renderer. If you
edit the summary, keep every untrusted value behind `trestle_md` or
`trestle_md_code`.

## Limits worth knowing

- The workflow skips fork pull requests. They get no secrets and a read-only
  token. Never use `pull_request_target` here, because it would run with secrets
  against fork code.
- reviewdog comments only on lines inside the diff (`-filter-mode=added`). Other
  findings stay in code scanning and the summary.
- Finding text and fix guidance are model output. The claim was independently
  verified, but the category and the fix were not. The fix appears only as a
  labeled property and in the summary, never as a suggested change that is
  applied.
- A passing job is not a clearance. The SARIF lists limitations, abstentions and
  omitted source, and `trestleComprehensiveClearance` is always `false`.
- Pushing again cancels the in-flight review (`concurrency`), which cancels the
  model calls. The provider bills the cost that was already incurred.
- The `openTrestleContentHash/v1` deduplication across pushes is best effort,
  because the model may describe the same defect differently on the next run.
