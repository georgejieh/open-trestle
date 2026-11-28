# Changelog

All notable changes to released versions of Open Trestle will be documented in this file.

## Unreleased

### Added

- `trestle review` and the first review of `trestle init` end by printing how long the review took,
  for example `Review took 2m 14s.`, on standard error. Standard output is unchanged.
- `trestle update` shows a spinner with the elapsed time while it downloads and verifies a release.
- **Open Trestle: Check Setup** in the VS Code extension runs `trestle doctor` in a terminal. See
  [VS Code](docs/vscode.md).
- `trestle review --model-checks` lets the checker write a test for a verified finding. The test
  runs in the sandbox against the base and the head, and a kept test is listed with its finding
  without changing the status or exit code. See
  [repository checks](docs/repository-checks.md#model-written-checks).
- A review reads the project's own intent documents, such as `.trestle/scope.md` or `PRD.md`, from
  the base tree, and the `drift_auditor` specialist compares the change with them. See
  [project intent documents](docs/local-model-review.md#project-intent-documents).

### Changed

- `trestle keys` on a terminal prints each variable name on its own row with its state beneath it,
  so a long name no longer pushes the state off a narrow terminal.
- `trestle review --model-checks` says why each test it ran was discarded, for example
  `Check 1 was discarded: it did not show a regression.`
- The setup summary of `trestle init` also shows the most a review can cost with its specialist
  reviews, not only the cost of the general review.

### Fixed

- `trestle init` also looks for a llama.cpp server on port 9931, the server's current default, as
  well as on 8080.
- A review is no longer refused with `provider_request_rejected` when the checker model accepts
  structured output but not the review's output schema. A request rejected with HTTP 400 or 422
  is sent once more without `response_format`.
- A review in which the checker rejected every proposed problem now ends as `no_candidates`
  instead of `incomplete`. `incomplete` remains for omitted source and inconclusive verdicts.
- A specialist review no longer lists one defect once per reviewer. Findings at one place that
  different reviewers worded differently now merge, and the other wordings stay listed under
  `also reported as:`. See
  [ranked findings](docs/local-model-review.md#ranked-findings-and-the-walkthrough).

## 0.1.0-alpha.1 - 2026-11-26

First pre-release, unsigned, for Linux and Windows (amd64).

### Added

- `trestle init`, a guided setup for the repository you are in. It proposes the base and head
  commits, asks where the two models run (OpenRouter, Ollama Cloud, OpenCode Go, Ollama signed in
  to Ollama Cloud, or a model server on this machine), and shows its settings before it asks for
  consent. Menus work with the arrow keys, and `--no-input` runs from flags alone. See
  [getting started](docs/getting-started.md).
- Re-running `trestle init` offers to review the latest change, re-run the checks, or change one
  setting. A changed provider or model makes a new setup folder and keeps the old one. See
  [running it again](docs/getting-started.md#running-it-again).
- API keys in an owner-only credential store, managed with `trestle keys list|set|remove`. Keys are
  typed hidden or piped, and OpenRouter keys are checked before they are saved. See
  [API keys](docs/keys.md).
- `trestle doctor` checks the install, the repository, the setup, the keys and the sandbox and
  prints the command that fixes each problem. `trestle status` and the home screen (`trestle` on a
  terminal) show the same state as a card. See [commands](docs/commands.md#trestle-doctor).
- `trestle review` reviews the latest change, `HEAD` against its merge base with the default
  branch, in one step. `--base` and `--head` pick other commits. See
  [getting started](docs/getting-started.md#running-it-again).
- Two-model review: a finder proposes problems and a separate checker verifies each one, with one
  retry when an answer is unusable. Only verified findings are reported, ranked, with duplicates
  merged and findings on unchanged code marked pre-existing. See
  [ranked findings](docs/local-model-review.md#ranked-findings-and-the-walkthrough).
- Review output as text, JSON, SARIF 2.1.0 or Markdown for a pull request comment, with a short
  view and live progress on a terminal and a walkthrough of what was checked. See
  [the result on a terminal](docs/local-model-review.md#the-result-on-a-terminal).
- Exit codes for CI: a blocking finding exits 4, and `--exit-code-policy`
  `default|findings|strict|always-zero` changes the mapping. A review with only low-severity or
  pre-existing findings is advisory and exits 3. See [exit codes](docs/exit-codes.md).
- Review context beyond the diff: the enclosing definitions, callers, tests and a ranked map from
  the repository index, commit messages as stated intent, the base tree's `AGENTS.md`,
  `CLAUDE.md` and similar instruction files, findings on removed lines, deletion-only changes and
  non-Go text files. See [review context](docs/local-model-review.md#review-context).
- Deterministic notes with no model call: pattern hygiene (anti-patterns, lint suppressions,
  absolute rules added to agent files), missing verification, style recommendations and token
  use. See [pattern hygiene](docs/local-model-review.md#pattern-hygiene).
- `trestle index build|status|query`, a repository index of every file with its role and the
  definitions, references, imports and tests found in it. See
  [repository index](docs/repository-index.md).
- Syntax analysis for Go, Java, JavaScript, TypeScript, TSX, Python, C, C++, C#, Rust, Swift, PHP,
  Ruby and HTML. See [syntax analysis](docs/syntax-analysis.md).
- `trestle profile` reports a repository's languages, test frameworks and the checks its CI
  enforces.
- Repository checks, off by default and enabled per repository with consent (`trestle checks`).
  A review runs the repository's own tests and linters for the changed area on base and head
  before any model call: Go, Node, pytest, unittest, Cargo, and `staticcheck`, `golangci-lint`,
  `ruff`, `flake8`, `mypy` and `cargo clippy`. A test that passes on base and fails on head is a
  check regression and blocks the review. See [repository checks](docs/repository-checks.md).
- A check sandbox with no network: unprivileged namespaces with a seccomp filter on Linux, and an
  AppContainer in a job object on Windows. It never falls back to running unconfined.
- Specialist reviews. `trestle profiles list` shows the nine packaged profiles, `--profile` runs
  one, and `--specialists auto|none|ID,...` runs a set after the general review. New setups use
  `auto`, and members run up to three at a time on remote routes. See
  [agent profiles](docs/agent-profiles.md).
- Providers: OpenRouter, Ollama Cloud, OpenCode Go, Ollama signed in to Ollama Cloud, and model
  servers on this machine (llama.cpp, vLLM, LM Studio, Ollama). OpenRouter setup is filled in from
  its public API and requires zero data retention unless you turn that off. See
  [remote model review](docs/remote-model-review.md).
- Spending limits per API key, a local usage ledger, and `trestle usage`. A limit has an amount, a
  weekly, monthly or yearly period and alert percentages, and a key at its limit refuses the
  review. Figures are an upper-bound estimate, not a bill. See
  [spending limits](docs/spending-limits.md).
- Secret scanning of everything before it leaves the machine, with a pinned scan helper prepared
  on first use. `--egress local-only` keeps source on this machine. See [privacy](docs/privacy.md).
- `trestle review --stop-on-stdin-close`, so a program that starts a review can cancel it by
  closing its input.
- One-line install scripts for Linux amd64 and Windows amd64 that verify the download against
  `SHA256SUMS` and can remove what they installed. A tagged release builds the archives and
  publishes a GitHub release. See [install](docs/install.md).
- `trestle update` for the packaged Linux amd64 install, a once-a-day update notice that
  `OPEN_TRESTLE_UPDATE_CHECK=off` turns off, and `trestle build-info`. In a script-installed
  copy, `trestle update` prints the install command to run again. See [updates](docs/updates.md).
- A VS Code extension with **Review Current Branch**, **Clear Findings** and **Set Up Repository**.
  It shows findings in the Problems panel and is built locally. See [VS Code](docs/vscode.md).
- A GitHub Actions example that uploads SARIF, posts inline comments and writes a job summary. See
  [GitHub pull request review](docs/github-pr-review.md).
- `trestled`, a review daemon for GitHub webhooks with an HTTP API, durable local state and
  workers, and MCP, LSP and web console surfaces to inspect its runs. These are frozen, with no
  new work planned, and may be removed. See [daemon API](docs/daemon-api.md).
- A static-debug quality evaluation and a pending 23-case corpus for the model reviewer, whose
  results are not release evidence until a human adjudicates the labels. See
  [quality evaluation](docs/quality-evaluation.md).
- Reference documentation under `docs/`. See [docs/README.md](docs/README.md).
- Linux and Windows amd64. macOS is not supported: its code builds as a starting point for a port,
  and repository checks are off there. See [platforms](docs/platforms.md).

### Security

- Provider keys are saved in owner-only files, and on Windows only your account and the system's
  own accounts may have access. A saved key is plaintext protected by file permissions, so it is
  kept from other accounts but not from programs running as you. See [API keys](docs/keys.md).
- Source is secret-scanned before it is sent to a remote model, and keys are read only when a
  request is made.
- Repository checks run only with your consent, in a sandbox without network access.
- Open Trestle's instructions travel in the system channel only, and repository text is treated as
  data. Instruction files are read from the base tree and used only when the head copy is
  identical. See [prompt-injection boundary](docs/prompt-injection-boundary.md).
- Model-written text is escaped in Markdown output and cannot open links, HTML or mentions.
- OpenRouter setup requires zero data retention by default, and the local route refuses models
  that a local Ollama relays to Ollama Cloud.
- The Go toolchain is 1.26.11, which fixes GO-2026-6859.
- Releases are unsigned, so check the SHA-256 against `SHA256SUMS`.
