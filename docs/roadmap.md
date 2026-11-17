# Delivery roadmap

Open Trestle aims to be the best open-source code-review agent, one that runs
wherever you work: the command line, a terminal UI, your editor, a GitHub
Action and a desktop app. The goal is a review that steers its models with
specialist skills and system prompts, and that finds, verifies and ranks
findings with memory of past reviews and a map of the codebase. Security and
evidence come first: every finding must point to the source that supports it.

## Status language

Each item on this page is in one of three states.

- **Available now** means the code and its tests exist in the source tree. It
  does not mean the feature is released. Nothing is released yet, and nothing
  counts as released until its release evidence exists (see
  [release gates](#release-gates)).
- **Next release** is the planned scope of the first release.
- **Later** is planned after the first release.

Items carry no dates. Each one ships with tests, documentation and a
CHANGELOG entry.

## Available now

The source tree is Linux-first. Remote providers work only with the packaged
Linux amd64 install. macOS and Windows are part of the first release, not of
what exists today. No model quality has been measured, the GitHub Actions
example has not run on GitHub, and the VS Code extension cannot start a
review.

### Guided setup

`trestle init`, run inside a repository, asks where the two models run: one
model that finds problems and a different model that double-checks them. It
fills in everything else it can, shows one settings panel, writes a protected
configuration and runs the setup checks. It runs the first review only after
you agree. It recommends a checker from a different model family than the
finder, because different families have different blind spots, and asks once
when both come from the same family; it does not enforce the choice.

If the provider's key is not set, `trestle init` asks for it with hidden input
and checks it with a free call where the provider offers one. It can save the
key in an owner-only credential store. `trestle keys` lists, saves and
removes saved keys. See [getting started](getting-started.md) and
[API keys](keys.md).

### Everyday loop

`trestle review` reviews the latest committed change in one step, using the
saved setup. The latest committed change is the current branch compared with
its merge base with the default branch. Re-running `trestle init` offers the
same review.

`trestle` on its own, in a terminal, shows a home screen with the setup, key
source, spending and last review, followed by numbered next actions. Each
action takes at most two steps.

### Direct model review

`trestle local-git model-review` runs the review inside the `trestle` process.
A finder model proposes candidate problems, and an independent verifier on a
different model checks them. The review uses the same nine-task graph as the
daemon. Output is JSON, text or SARIF, with opt-in CI exit-code policies.

Opt-in investigation tools (list, read and search the snapshot) are local
only. The memory index is empty unless you supply a retained-memory input
file. See [local model review](local-model-review.md).

### Provider profiles

A provider profile tells Open Trestle how to reach a model service. These are
available:

- OpenRouter, either with zero data retention required on every request (the
  default) or in a generic profile.
- Ollama Cloud.
- OpenCode Go.
- Ollama on this machine, signed in to Ollama Cloud.
- Any OpenAI-compatible server on loopback, without a key.

Remote providers work only with the packaged Linux amd64 install and its
secret scanner. Each profile is tested offline with synthetic transports, and
none is qualified against a live account. The OpenCode Console profile is
offline protocol support only, and the Codex ChatGPT session profile is a
disabled status report. See [remote model review](remote-model-review.md).

### Spending limits

You can set a limit for each key. Open Trestle keeps a local usage ledger,
raises alerts as you approach the limit and refuses requests at the limit.
`trestle usage` shows the totals, and an OpenRouter key also shows OpenRouter's
own figures.

The total is an upper-bound estimate at the highest pinned price, not a bill,
and the limit is best effort. The daemon does not record or enforce spending.
See [spending limits](spending-limits.md).

### Specialists

Nine specialist profiles are packaged. `trestle profiles list|plan` shows
them and `--profile` runs a single one. `--specialists auto|LIST` runs the
general review plus the selected specialists one after another, each as a
separately verified run. Open Trestle then merges their verified findings and
ranks them with the shared duplicate rule.

A new setup runs specialists by default, and `--specialists none` turns them
off. The daemon does not dispatch profiles. See
[agent profiles](agent-profiles.md).

### Model evaluation corpus

The corpus has 23 synthetic Go cases: 12 defects, 3 deletion defects, 3 near
misses, 3 clean changes and 2 abstentions. It comes with a run driver, a
scorer and a pinned format for human adjudication records.

The labels are the fixture author's and wait for independent human
adjudication. No model quality has been measured. See
[quality evaluation](quality-evaluation.md).

### GitHub Actions example

`examples/github-actions/open-trestle-review.yml` runs the direct review in a
workflow, uploads SARIF and posts inline comments with reviewdog. It is tested
offline only and has not run on GitHub. There is no packaged `action.yml`. See
[GitHub pull-request review](github-pr-review.md).

### Daemon and observers

`trestled` keeps durable runs, a hash-chained task journal and an
authenticated API. It supports scoped remote workers, verified GitHub webhook
intake and source acquisition. In required mode it publishes one `COMMENT`
review with a static publication token. Live GitHub publication is unverified.

The TUI, `trestle lsp` with the VS Code extension, the web console and ACP
each observe one daemon run. MCP reads run status and submits a pre-built
plan. None of them starts a review.

### Security and evidence

Only the system channel carries instructions. Repository text, including the
base tree's instruction files, is treated as data. Every request to a remote
route passes two sandboxed Betterleaks scans, which have a reviewed recall of
11 of 14 expected occurrences. Each finding is bound to the exact source
lines that support it, and publication is guarded by a fresh-head check and
idempotency. See the [prompt-injection boundary](prompt-injection-boundary.md).

### Updates

`trestle update` updates the packaged install in one step: it finds a newer
build, shows it, asks, runs the new build's own upgrade with `sudo` and
reports the result. `--check` only reports. The home screen and
`trestle review` show an update notice at most once a day.

The client side is available: GitHub release discovery, Ed25519 verification
against keys pinned in the build, a local update folder for development
builds, and an offline signing tool. Release signing waits for the release
phase. No key is pinned yet, so the release channel refuses until one is. See
[updates](updates.md).

### Packaging and release evidence

The packaging work covers an unsigned Linux amd64 candidate with install,
upgrade, one-step rollback and recovery, SPDX SBOMs, a passive vulnerability
gate and a static-debug evaluation over eight built-in cases. Nothing is
signed. See [operations](operations.md).

## Next release

The first release runs on Windows, macOS and Linux and is limited to four
areas. Anything outside them is listed under [Later](#later).

### Platforms and the everyday loop

Today the packaged install is Linux amd64 only, and remote providers are refused
on other systems (see [platforms](platforms.md)).
The release brings the whole loop to Windows and macOS:

- Native packages or installers on each system.
- A desktop app, built from the web console in a native shell. It opens a
  repository, runs the setup wizard, starts a review, shows the findings and
  updates Open Trestle with a button. The installers ship it on all three
  systems.
- `trestle init`, `trestle review`, `trestle update`, the home screen and
  remote providers on all three systems.
- A secret scanner that runs on all three systems, which remote providers
  depend on.

- Sign in with ChatGPT as a provider option, so that you can review with a
  ChatGPT plan instead of an API key. It uses OpenAI's official sign-in program
  for open-source tools and the public Responses API. The program does not
  accept an output limit, so Open Trestle bounds the output itself by stopping
  the stream at the limit, and it labels the route as using your plan's limits
  rather than per-token billing. The route makes no zero-data-retention claim,
  so the review asks you to allow it.

### Codebase understanding

- A repository index and a ranked repository map. The map gives the enclosing
  definition for each changed hunk, ranks symbol tags within a token budget,
  looks up callers and usages, and lists module boundaries and a feature map.
  The analysis works on syntax trees for Java, JavaScript, TypeScript, Python,
  HTML, C, C++, C#, Swift, Go, Rust, PHP and Ruby. Every one of these languages
  gets the same depth of analysis; none is treated as a special case.
- A repository profile read from the existing tests and CI configuration,
  which records the project's conventions and the maintainers' priorities.
  Open Trestle parses this configuration and never runs it.

### Generated verification

- For each pull request, Open Trestle decides which of its bundled checks and which of the repository's own tests to run, and whether new tests should be written for the change.
- Checks written by the model, and the repository's own tests, run in a sandbox on each system. The code decides the outcome, not the model.
- The tests cover the code that depends on the change as well as the changed code, so a change that breaks something elsewhere is caught.
- Running them needs your consent through an allow prompt: Allow, Deny, or
  Always allow for this repository. In CI, a workflow input gives the consent.
- This area needs a reviewed security design before any code is written.

### Integrations

- A GitHub Action (`action.yml`), verified on a test repository. This needs
  maintainer approval to push to one.
- A VS Code command that starts a review from the command palette through the
  direct path and shows the findings as diagnostics. Today the extension shows
  the verified diagnostics of one daemon run and cannot start a review.

## Later

### Review quality

- Review an entire codebase, not only a pull request, using the same understanding of the repository that pull-request review builds.
- Languages used with game engines such as Godot, Unity and Unreal Engine, and the custom languages that large companies build in-house.
- Review uncommitted changes without writing objects into the repository.
- Choose a route per profile for specialists.
- A pattern-hygiene specialist profile, deprecated-API detection, support for
  more languages than Go, JavaScript, TypeScript and Python, and multi-line
  Python signatures.
- Checks drafted from findings. When a finding category recurs or is
  accepted, Open Trestle would draft a deterministic rule (ast-grep, Semgrep,
  golangci-lint or ESLint) with a failing and a passing fixture. The rule is
  offered as a patch and never applied silently.
- An optional one-paragraph model summary, sent as a separate structured
  request on the verifier route under the same egress, scanning and spending
  rules. It would be labelled with its model and off for local setups. Also
  planned are an optional model-drawn state or sequence diagram, and the
  pre-existing class and walkthrough for investigation runs.
- Commit and pull-request context on the daemon and webhook path. The
  `pull_request` webhook payload already carries the title and body for the
  accepted event, but the webhook planner keeps neither, and the daemon's run
  has no bound artifact for them. Linked issue text needs the `issues: read`
  permission, which Open Trestle does not accept today. A distinct
  `intent_mismatch` candidate category needs candidate batch v3. Until then a
  mismatch is a `correctness` candidate.
- Inexpensive read-only evidence scouts, kept separate from candidate
  generation and verification, and remote investigation tools.
- Embeddings for context and memory retrieval.

### Memory and learning

- Outcome memory. Open Trestle would record findings and whether a later
  commit addressed them, and record explicit feedback (a future feedback command, the
  IDE, pull-request reactions). It would recall similar past outcomes as
  advisory context and suppress categories by their history, never security
  ones. Today the memory index is empty unless you supply a manually authored
  retained-memory file.
- Metrics: the address rate and the outdated rate, shown in `trestle usage`
  or a stats view and in the console.

### Surfaces

- An optional OS keyring backend for saved keys.
- A TUI that starts a review and browses findings interactively. Today the TUI
  observes, and can cancel, one daemon run.
- Pull-request interaction: suggestion blocks, check runs and replies to the
  bot. Today the daemon can post one `COMMENT` review.
- VS Code quick-fix code actions for suggestions.

- Additional forge adapters, hook integration for Git, a gRPC API, streaming
  subscriptions, and policy and provider administration.
- Spending limits that the daemon records and enforces.

### Measured quality

- An independent human reviewer adjudicates the 23 corpus cases.
- The sealed run bundle is scored against the adjudicated labels.
- Public benchmarks (SWR-Bench, AACR-Bench, c-CRAB) are added to the
  evaluation driver, and the numbers are published.
- A comparison with minimal harnesses. The same models review pull requests
  seeded with known bugs in a medium-size codebase, once through Open Trestle
  and once through a minimal coding-agent harness, and the comparison measures
  how many bugs each finds, how many false alarms it raises, and the tokens and
  cost of each review. Vendor coding agents serve as a second, stronger
  baseline. If Open Trestle helps, the same setup becomes a way to benchmark
  models.

### Policy, analysis and operations

- **Policy and analysis:** repository-scoped policy packs, deterministic CI
  planning and more user-visible deterministic rules.
- **Semantic evidence:** type-aware language adapters whose compiler or
  language-server facts could support verification, and heuristics such as
  historical co-change that may only point at review targets. Only the
  `structural` and `syntactic_candidate` grades exist today.
- **Setup:** reachability checks for external delivery, broader replica and
  failover coordination, no-egress enforcement, and governed bundle import.
- **Deployment:** supported installation profiles, OpenTelemetry
  observability, a Docker Compose profile for a single operator, Helm charts
  or Kubernetes manifests for larger installations, restore drills and
  air-gapped distribution. The setup planner's `kubernetes_ha` profile and its
  shared-store probe are setup checks, not a deployment.
- **Release:** signing, attestation publication and verification, supported
  production upgrade and crash-recovery guarantees, deployment qualification,
  accessibility evidence, and realistic adjudicated evaluation data with
  calibration, cost and latency evidence.

## Release gates

A release candidate must demonstrate all of the following:

- Exact evidence for every published finding.
- Negative tests for authorization and tenant isolation.
- No unapproved provider route, egress, command or source change.
- Exact packaged scanner identities, fail-closed behavior at 256 fields, 2 MiB,
  residual-scan and timeout limits, and the reviewed 11 of 14 coverage and
  known-near-miss baseline.
- No blocking finding that rests only on model output, heuristic impact
  evidence, or undeclared or incomplete semantic coverage.
- Visible human-review outcome, coverage and abstention semantics for every
  supported surface.
- Deployment, upgrade, backup, restore and recovery verification for its
  supported profile.
- Versioned quality evaluation, calibration, cost, latency and false-positive
  evidence.
- Signed artifacts, an SBOM, provenance, vulnerability reporting and release
  notes.

## How work becomes public

Public source contains original implementation, public contracts, tests, user
documentation and release evidence. Local research archives, development
records, upstream inspection copies and confidential configuration stay out of
the public repository.
