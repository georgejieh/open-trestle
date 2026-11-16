# Open Trestle

Open Trestle is an open-source AI code reviewer. It reads the codebase around a
change, tailors the review to it, and runs where you work: your terminal, CI and,
for viewing results, your editor. It does not depend on one model provider.
Remote providers and local models on your own hardware both work.

A review runs in stages. Deterministic checks run first. A finder model proposes
problems. A different, independent checker model confirms or rejects each one,
and only confirmed findings are reported, each tied to the source lines that
support it.

## Status

Open Trestle is a development release. No release is signed yet, and nothing here
is supported for production use.

- The packaged Linux amd64 install works today. Remote providers (OpenRouter,
  Ollama Cloud, OpenCode Go) need it. A plain `go build` works with a model
  server on your own machine.
- macOS and Windows are planned for the next release. See
  [platforms](docs/platforms.md) for what each system can do now.
- Model review quality has not been measured. The evaluation corpus awaits
  independent human adjudication, so there are no quality numbers to quote yet.
  See [quality evaluation](docs/quality-evaluation.md).

## Quick start

Install a build first: see [install](docs/install.md). Then, inside a Git repository:

```sh
trestle init      # choose where two models run; saves a protected setup
trestle review    # review the latest committed change
trestle           # home screen: setup, spending, last review, next actions
trestle update    # update a packaged install
```

`trestle init` asks for an API key with hidden input, and checks it where the
provider allows. You can set a spending limit per key; Open Trestle alerts and
refuses at the limit. Only committed changes are reviewed. Walk through the
first run in [getting started](docs/getting-started.md), and see [commands](docs/commands.md)
for every command. The [API keys](docs/keys.md) and
[spending limits](docs/spending-limits.md) pages cover those two topics.

## What a review gives you

- A walkthrough of what was verified: the secret scan, the deterministic checks,
  and how many candidates the checker confirmed or rejected. See
  [ranked findings and the walkthrough](docs/local-model-review.md#ranked-findings-and-the-walkthrough).
- Findings that are ranked and deduplicated. See
  [duplicates and rank](docs/local-model-review.md#duplicates).
- Separate classes for [pre-existing findings](docs/local-model-review.md#pre-existing-findings)
  (in code the change did not touch), which never block CI, and
  [advisory results](docs/local-model-review.md#advisory-results), where only
  low-severity or pre-existing findings remain and CI reports no verdict.
- Commit messages are given to the models as
  [stated intent](docs/local-model-review.md#commit-messages-as-stated-intent),
  labelled as unverified.
- [Pattern hygiene](docs/local-model-review.md#pattern-hygiene): deterministic
  counts of added lint suppressions, workaround comments and bare TODO markers,
  and of absolute rules added to agent instruction files.
- [Specialist profiles](docs/agent-profiles.md): nine packaged specialist
  reviewers. A new setup runs the general review, then the specialists the change
  calls for; `--specialists none` turns them off.
- Output as text, JSON, SARIF or Markdown. See
  [review output and options](docs/local-model-review.md#headless-ci-use).

The static `local-git inspect`, `local-git change`, and deterministic `local-git review` commands support verified loose objects only. They make no model call. For model-backed review see [local model review](docs/local-model-review.md).

## Privacy and security in brief

- Your source goes to a model only when you run a review, and only to the
  provider your setup names. With a model server on your machine, nothing leaves it.
- Before a request goes to a remote provider, it is scanned for secrets in a
  sandboxed process. A request that fails the scan is not sent. The scanner is
  a pattern scanner and misses some credential types, so it is not a guarantee.
- OpenRouter requests require zero data retention by default.
- There is no telemetry. Once releases are signed, a packaged install checks
  GitHub Releases for a newer version at most once a day. That request carries no
  repository or usage data, and `OPEN_TRESTLE_UPDATE_CHECK=off` turns it off.
- Repository text, including files that look like instructions, is data and never
  instructions to the model.

See [privacy](docs/privacy.md), the
[prompt-injection boundary](docs/prompt-injection-boundary.md) and
[SECURITY.md](SECURITY.md).

## Where it runs

- **CLI:** today, through the commands above.
- **CI:** an example GitHub Actions workflow exists, but it has not run on GitHub
  yet. A packaged `action.yml` is planned. See
  [GitHub pull-request review](docs/github-pr-review.md).
- **VS Code:** the extension currently shows the verified diagnostics of runs
  that a daemon already holds. Starting a review from VS Code is planned for the
  next release. See [VS Code](docs/vscode.md).

## Documentation

[docs/README.md](docs/README.md) indexes every page by what you want to do.

## Roadmap

[docs/roadmap.md](docs/roadmap.md) separates what exists today from the next
release and from later work.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) before you open a pull request.

## License

[Apache License 2.0](LICENSE) · attribution in [NOTICE](NOTICE)
