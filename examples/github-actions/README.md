# GitHub Actions example

`open-trestle-review.yml` runs an Open Trestle model review on each pull request
and reports it three ways: code scanning alerts (SARIF), inline pull-request
review comments, and a job summary. It reuses `github/codeql-action/upload-sarif`
and `reviewdog`; Open Trestle posts nothing to GitHub itself in this path.

**Status: never run on GitHub.** The Open Trestle side (SARIF, exit policy,
checkout diagnostics) is tested offline. The workflow file itself is checked only
for being well-formed YAML. Treat every GitHub-facing step as unverified and read
the logs of your first run. See [GitHub pull-request review](../../docs/github-pr-review.md).

## Before you copy it

1. **Install step.** No Open Trestle release exists yet, so the workflow builds the
   unsigned Linux candidate from source following [operations](../../docs/operations.md).
   That step is untested on a hosted runner and takes a while. The commented
   `PLACEHOLDER` block shows where a pinned release artifact and its checksum go
   once one exists. Set `OPEN_TRESTLE_REF` to a commit SHA.
2. **Models.** Set `GENERATION_MODEL` and `VERIFICATION_MODEL` to two different
   models. The job refuses to run while they still begin with `YOUR_`.
3. **Secret.** Add the repository secret `OLLAMA_API_KEY`. The workflow maps it to
   the variable name `OPEN_TRESTLE_PROVIDER_OLLAMA_CLOUD` that bootstrap records;
   only the name is stored in the protected configuration. For OpenRouter ZDR or
   OpenCode Go, change `--provider` and the credential variable, and add the account
   and evidence declarations in [remote model review](../../docs/remote-model-review.md);
   those are attestations a person should make, which is why the example uses
   `ollama-cloud`. Ollama Cloud makes no retention claim: check its terms before
   sending private code.
4. **Pin actions.** `actions/checkout`, `actions/setup-go`, `github/codeql-action/upload-sarif`
   and `reviewdog/action-setup` appear with major-version tags so the file is
   readable. Replace each with a full commit SHA before using it.
5. **Code scanning.** `upload-sarif` needs code scanning enabled (free for public
   repositories; GitHub Code Security for private ones). Delete that step and the
   `security-events: write` permission if you do not use it.

## What the job does

- Checks out the pull request head with `fetch-depth: 0`. A shallow checkout makes
  `model-review` stop before any model call and print how to fetch the base
  (`git fetch --no-tags --depth=N origin <base>`); it never fetches for you.
- Computes the review base as `git merge-base "$BASE_SHA" "$HEAD_SHA"` from
  `github.event.pull_request.base.sha` and `head.sha` (passed through `env`, never
  interpolated into a script). The base branch tip would count commits merged into
  the base branch after the branch point as part of the change; the merge base is
  the comparison GitHub shows for the pull request.
- Runs `trestle setup bootstrap init`, then `check`, then the printed review
  command with `--format text` replaced by `--format sarif --exit-code-policy findings`
  and base/head set to that merge base and `head.sha`.
- Uploads SARIF to code scanning only when the SARIF run property
  `trestleRunStatus` is `succeeded` (a `jq` check). A refused, failed or canceled
  run's SARIF has no results, and uploading it could close open alerts as if they
  were fixed. The upload passes `sha` (the pull request head) and `ref`
  (`refs/pull/<number>/head`), because `upload-sarif` otherwise uses `github.sha`,
  the temporary merge commit. Those inputs come from the `upload-sarif`
  documentation and are unverified live.
- Posts inline comments and the job summary from whatever SARIF was produced, then
  fails the job from the recorded status: exit 0 only when the review completed
  with no verified high or critical finding. Refusals, unreadable changes and
  failures fail the job and appear as an unsuccessful invocation in the SARIF.
- The job summary is rendered from the SARIF with `jq`. One review is a paid model
  run that yields one output format, so the example does not run a second time for
  `--format text` or `--format markdown`.
- Finding text, fix guidance and paths are untrusted (model output and repository
  text), and both the job summary and reviewdog's pull-request comments are GitHub
  Markdown. A step first writes a small `jq` module, `trestle-markdown.jq`, that
  escapes such text with the rules of Open Trestle's own Markdown renderer
  (`localreview.MarkdownText` and `MarkdownCode`): it cannot open emphasis, a link,
  an image, a heading, a table cell or an HTML tag, cannot @-mention anyone, and no
  URL, `www.` host or email address becomes an autolink. The summary is rendered
  through it, and reviewdog reads an escaped copy of the SARIF
  (`open-trestle.reviewdog.sarif`); the SARIF for code scanning keeps the raw text.
  The repository test runs the module with `jq` against crafted SARIF and compares
  it byte for byte with the Go renderer. If you edit the summary, keep every
  untrusted value behind `trestle_md` or `trestle_md_code`.

## Limits worth knowing

- **Fork pull requests are skipped.** They get no secrets and a read-only token.
  Never use `pull_request_target` here; it would run with secrets against fork code.
- **reviewdog comments only on lines inside the diff** (`-filter-mode=added`). Other
  findings stay in code scanning and the summary.
- Finding text and fix guidance are model output. The claim was independently
  verified; the category and the fix were not. The fix appears only as a labeled
  property and in the summary, never as a suggested change that is applied.
- A green job is not a clearance. The SARIF lists limitations, abstentions and
  omitted source, and `trestleComprehensiveClearance` is always `false`.
- Pushing again cancels the in-flight review (`concurrency`), which cancels the
  model calls; cost already incurred is the provider's to bill.
- `openTrestleContentHash/v1` deduplication across pushes is best effort: the model may
  describe the same defect differently on the next run.
