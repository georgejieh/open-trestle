# Roadmap

Open Trestle aims to be the best open-source code-review agent, one that runs
wherever you work: the command line, your editor, a GitHub
Action and a desktop app. A review steers its models with specialist skills and
system prompts. It finds, verifies and ranks findings with memory of past
reviews and a map of the codebase, and ties every finding to the source it
concerns.

The only release so far is the unsigned pre-release `v0.1.0-alpha.1`. Items
carry no dates, and each one ships with tests, documentation and a CHANGELOG
entry.

## Available now

These items have code and tests in the source tree, which does not mean that
they are in the pre-release.

- **Guided setup.** `trestle init` asks where the two models run and fills in
  the rest. See [getting started](getting-started.md) and [API keys](keys.md).
- **Everyday loop.** `trestle review` reviews the current branch against its
  merge base with the default branch, and `trestle` on its own opens a home
  screen. `trestle status` prints the same card without the actions, and
  `trestle doctor` checks the install, the repository and the setup. A review
  shows live progress. Results come as text, JSON, SARIF or Markdown, with the
  findings ranked, a defect that several reviewers report merged into one, and
  a walkthrough. See
  [local model review](local-model-review.md) and [commands](commands.md).
- **Repository index and map.** A review builds an index of the base and head
  commits. The finder and the verifier see the definition around each changed
  hunk, the callers and tests of the changed code, and a ranked repository map.
  `trestle index` builds and queries the index. See
  [repository index](repository-index.md).
- **Syntax analysis.** Java, JavaScript, TypeScript, Python, HTML, C, C++, C#,
  Swift, Go, Rust, PHP and Ruby. See [syntax analysis](syntax-analysis.md).
- **Repository profile.** `trestle profile` reads the languages, test
  frameworks and enforced checks from the repository's tests and CI
  configuration. See [commands](commands.md).
- **Repository checks.** With your consent, a review runs the repository's own
  tests in a sandbox with no network and gives the outcomes to both models. With
  `--model-checks`, the checker also writes a test for each of up to 3 verified
  findings and keeps a test only when it fails on head and passes, or cannot be
  built, on base. See
  [repository checks](repository-checks.md).
- **Providers.** OpenRouter, Ollama Cloud, OpenCode Go, Ollama signed in to
  Ollama Cloud, and any OpenAI-compatible server on this machine. Remote
  providers work with any build that has its secret scan helper. Each profile is
  tested offline only. See [remote model review](remote-model-review.md) and
  [local models](named-local-runtimes.md).
- **Spending limits.** A limit per API key, a local usage ledger and
  `trestle usage`. See [spending limits](spending-limits.md).
- **Specialists.** Six packaged profiles can run as specialists, one at a time with
  `--profile` or as a set with `--specialists` (at most three at once when every route is
  remote). A review also reads project intent documents such as
  `.trestle/scope.md` and `PRD.md`. See [agent profiles](agent-profiles.md) and
  [project intent documents](local-model-review.md#project-intent-documents).
- **Install.** A release workflow builds Linux and Windows amd64 archives, and
  one-line install scripts install them for your account. The pre-releases are
  unsigned. See [install](install.md).
- **Updates.** `trestle update` for the packaged Linux amd64 install. No release
  key is pinned yet, so the release channel refuses. An install made by the
  scripts is updated by running the script again. See [updates](updates.md).
- **GitHub Actions example.** A workflow that runs the direct review and uploads
  SARIF. It has run on a GitHub-hosted runner in a private repository, and only
  its `upload-sarif` step is unverified. See
  [GitHub pull-request review](github-pr-review.md).
- **VS Code.** **Open Trestle: Review Current Branch** runs `trestle review` and
  shows the findings in the Problems panel. See [VS Code](vscode.md).
- **Daemon and observers.** `trestled` keeps durable runs and an authenticated
  API. The web console, MCP and LSP observe or submit daemon runs. They do not
  start a direct review. They are frozen, with no new work planned, and may be
  removed. See [architecture](architecture.md).
- **Evaluation corpus.** 23 synthetic Go cases with a run driver and a scorer.
  The labels await independent human adjudication, so no model quality has been
  measured. See [quality evaluation](quality-evaluation.md).
- **Platforms.** Linux and Windows run the whole loop from a release or a development build.
  macOS is not supported. See [platforms](platforms.md#macos).

## Next release

- A signed release, and `trestle update` for the installs that the install
  scripts make. Today the scripts install unsigned pre-releases on Linux and
  Windows (amd64). See [install](install.md).
- A desktop app, built from the web console in a native shell, that opens a
  repository, runs the setup wizard, starts a review and shows the findings.
- A GitHub Action (`action.yml`) verified on a test repository.
- Choosing which of the bundled checks to run for a pull request.
- Sign in with ChatGPT as a provider option, so that a review can use a
  ChatGPT plan instead of an API key.
- Syntax analysis for the languages used with game engines such as Godot, Unity
  and Unreal Engine, and for in-house languages.

## Later

- Review an entire codebase, not only a pull request.
- Review uncommitted changes without writing objects into the repository.
- Outcome memory: record whether a later commit addressed each finding, and use
  it as advisory context.
- Checks drafted from findings that recur, offered as a patch and never applied
  silently.
- Pull-request interaction: suggestion blocks, check runs and replies.
- An optional OS keyring backend for saved keys.
- Spending limits that the daemon records and enforces.
- Independent human adjudication of the evaluation corpus, public benchmarks and
  a comparison with minimal harnesses.

## Out of scope

- Hidden provider fallback for restricted repositories.
- Running arbitrary repository commands. Only the fixed test commands in
  [repository checks](repository-checks.md) run, after consent and in a sandbox.
- Source mutation, merge, deployment or external reporting by default.
- Unrestricted third-party plugins.
- Dynamic testing of public, third-party or unspecified targets.

## Release gates

A release candidate must show:

- source lines cited for every published finding;
- no unapproved provider route, egress, command or source change;
- a pinned scan helper with its limits and the reviewed 11 of 14 coverage
  baseline;
- no blocking finding that rests only on model output;
- signed artifacts with an SBOM and provenance;
- versioned quality evaluation with cost and latency evidence.
