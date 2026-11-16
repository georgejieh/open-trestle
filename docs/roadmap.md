# Delivery roadmap

Open Trestle aims to be the best open-source code-review agent, one that runs
wherever you work: the command line, a terminal UI, your editor, a GitHub
Action and a desktop app. The goal is a review that steers its models with
specialist skills and system prompts, and that finds, verifies and ranks
findings with memory of past reviews and a map of the codebase. Security and
evidence come first: every finding must point to the source that supports it.

## Status language

**Available now** means the code and its tests exist in the source tree. It is
not a release. Nothing is released yet, and nothing counts as released until
its release evidence exists (see [release gates](#release-gates)). **Next
release** is the planned scope of the first release. **Later** is planned
after it. Items carry no dates, and each ships with tests, documentation and a
CHANGELOG entry.

## Available now

- **Guided setup.** `trestle init`, run inside a repository, asks where the two
  models run and which model finds problems and which different model
  double-checks them. It fills in everything else it can, shows one settings
  panel, writes a protected configuration, runs the setup checks and runs the
  first review only after consent. When the provider's key is not set, it asks
  for the key with hidden input, checks it with a free call where the provider
  has one, and can save it in an owner-only credential store; `trestle keys`
  lists, saves and removes saved keys. See [getting started](getting-started.md)
  and [API keys](keys.md).
- **Everyday loop.** `trestle review` reviews the latest committed change (the
  current branch against its merge base with the default branch) with the
  saved setup, in one step; a `trestle init` re-run offers the same. `trestle`
  on its own, in a terminal, shows a home screen with the setup, key source,
  spending and last review, and numbered next actions, each within two steps.
- **Direct model review.** `trestle local-git model-review` runs the review in
  the `trestle` process: a finder model proposes candidates and an independent
  verifier on a different model checks them, over the same nine-task graph the
  daemon uses. Output is JSON, text or SARIF, with opt-in CI exit-code policies.
  Opt-in investigation tools (list, read and search the snapshot) are
  local-only. The memory index is empty unless a retained-memory input file is
  supplied. See [local model review](local-model-review.md).
- **Provider profiles.** OpenRouter (zero data retention required on every
  request by default, or generic), Ollama Cloud, OpenCode Go, Ollama on this
  machine signed in to Ollama Cloud, and any OpenAI-compatible server on
  loopback without a key. Remote providers work only with the packaged Linux
  amd64 install and its secret scanner. Each is tested offline with synthetic
  transports; none is qualified against a live account. The OpenCode Console
  profile is offline protocol support only, and the Codex ChatGPT session
  profile is a disabled status report. See
  [remote model review](remote-model-review.md).
- **Spending limits.** Per-key limits with a local usage ledger, alerts and
  refusal at the limit, `trestle usage`, and OpenRouter's own figures for an
  OpenRouter key. The total is an upper-bound estimate at the highest pinned
  price, not a bill, and the limit is best effort. The daemon does not record
  or enforce spending. See [spending limits](spending-limits.md).
- **Specialists.** Nine packaged specialist profiles, `trestle profiles
  list|plan`, `--profile` for one profile, and `--specialists auto|LIST`, which
  runs the general review plus selected specialists one after another as
  separately verified runs, then merges and ranks their verified findings with
  the shared duplicate rule. A new setup runs specialists by default
  (`--specialists none` turns them off), and the daemon does not dispatch
  profiles. See [agent profiles](agent-profiles.md).
- **Model evaluation corpus.** 23 synthetic Go cases (12 defects, 3 deletion
  defects, 3 near misses, 3 clean changes, 2 abstentions), with a run driver, a
  scorer and a pinned human-adjudication record format. The labels are the
  fixture author's and await independent human adjudication. No model quality
  has been measured. See [quality evaluation](quality-evaluation.md).
- **GitHub Actions example.** `examples/github-actions/open-trestle-review.yml`
  runs the direct review in a workflow, uploads SARIF and posts inline comments
  with reviewdog. It is tested offline only and **has not run on GitHub**.
  There is no packaged `action.yml`. See
  [GitHub pull-request review](github-pr-review.md).
- **Daemon and observers.** `trestled` keeps durable runs, a hash-chained task
  journal and an authenticated API, with scoped remote workers, verified GitHub
  webhook intake, source acquisition, and required-mode publication of one
  `COMMENT` review with a static publication token. Live GitHub publication is
  unverified. The TUI, `trestle lsp` with the VS Code extension, the web console
  and ACP observe one daemon run; MCP reads run status and submits a pre-built
  plan. None of them starts a review.
- **Security and evidence.** Only the system channel carries instructions;
  repository text, including the base tree's instruction files, is data. Every
  request to a remote route passes two sandboxed Betterleaks scans, with a
  reviewed recall of 11 of 14 expected occurrences. Findings bind to exact
  source slices, and publication is fenced by a fresh-head check and
  idempotency. See the [prompt-injection boundary](prompt-injection-boundary.md).
- **Updates.** `trestle update` updates the packaged install in one step:
  find, show, ask, run the new build's own upgrade with `sudo`, report.
  `--check` reports only, and the home screen and `trestle review` show a
  notice at most once a day. The client side is available: GitHub release
  discovery, Ed25519 verification against keys pinned in the build, the local
  update folder for development builds, and the offline signing tool. Release
  signing is pending the release phase: no key is pinned yet, so the release
  channel refuses until one is. See [updates](updates.md).
- **Packaging and release evidence.** An unsigned Linux amd64 candidate with
  install, upgrade, one-step rollback and recovery; SPDX SBOMs; a passive
  vulnerability gate; and a static-debug evaluation over eight built-in cases.
  Nothing is signed. See [operations](operations.md).

## Next release

The first release runs on Windows, macOS and Linux and is limited to four
areas. Anything outside them is listed under [Later](#later).

### Platforms and the everyday loop

Today the packaged install is Linux amd64 only, and remote providers and the
saved-key store are refused on other systems (see [platforms](platforms.md)).
The release brings the whole loop to Windows and macOS:

- Install with native packages or installers on each system.
- `trestle init`, `trestle review`, `trestle update`, the home screen and
  remote providers on all three systems.
- A secret scanner that runs on all three systems, which remote providers
  depend on.
- Owner-only credential and configuration files on Windows, using ACLs.

### Codebase understanding

- A repository index and a ranked repository map: enclosing definitions for
  changed hunks, symbol tags ranked within a token budget, caller and usage
  lookups, module boundaries and a feature map. Go uses its AST; other
  languages begin with lexical tags.
- A repository profile read from existing tests and CI configuration:
  conventions and the maintainers' priorities. Configuration is parsed and
  never executed.

### Generated verification

- AI-written checks, and the repository's own tests, run in a sandbox on each
  system. The code decides the outcome, not the model.
- Execution needs consent through an allow prompt: Allow, Deny, or Always
  allow for this repository. In CI, a workflow input does the allowing.
- This area needs a reviewed security design before any code.

### Integrations

- A GitHub Action (`action.yml`), verified on a test repository. This needs
  maintainer approval to push to one.
- VS Code starts a review from the command palette through the direct path and
  shows the findings as diagnostics. Today the extension shows the verified
  diagnostics of one daemon run.

## Later

### Review quality

- Review uncommitted changes without writing objects into the repository.
- Per-profile route assignment for specialists.
- A pattern-hygiene specialist profile, deprecated-API detection, more
  languages than Go, JavaScript, TypeScript and Python, and multi-line Python
  signatures.
- Checks from findings: when a finding category recurs or is accepted, draft a
  deterministic rule (ast-grep, Semgrep, golangci-lint or ESLint) with a
  failing and a passing fixture, offered as a patch and never applied silently.
- The optional one-paragraph model summary (a separate structured request on
  the verifier route under the same egress, scanning and spending rules,
  labelled with its model and off for local setups), the optional model-drawn
  state or sequence diagram, and the pre-existing class and walkthrough for
  investigation runs.
- Commit and pull-request context on the daemon and webhook path. The
  `pull_request` webhook payload already carries the title and body under the
  admitted event, but the webhook planner keeps neither and the daemon's run
  has no bound artifact for them. Linked issue text needs `issues: read`,
  which is not admitted. A distinct `intent_mismatch` candidate category needs
  candidate batch v3; today a mismatch is a `correctness` candidate.
- Inexpensive read-only evidence scouts, kept separate from candidate
  generation and verification, and remote investigation tools.
- Embeddings for context and memory retrieval.

### Memory and learning

- Outcome memory: record findings and whether a later commit addressed them;
  record explicit feedback (`trestle feedback`, the IDE, pull-request
  reactions); recall similar past outcomes as advisory context; suppress
  categories by their history, never security. Today the memory index is empty
  unless a manually authored retained-memory file is supplied.
- Metrics: address rate and outdated rate in `trestle usage` or a stats view
  and in the console.

### Surfaces

- An optional OS keyring backend for saved keys.
- TUI: start a review and browse findings interactively. Today the TUI
  observes, and can cancel, one daemon run.
- Pull-request interaction: suggestion blocks, check runs and replies to the
  bot. Today the daemon can post one `COMMENT` review.
- VS Code quick-fix code actions for suggestions.
- A desktop app that reuses the web console in a native shell.
- Additional forge adapters, Git-hook integration, a gRPC API, streaming
  subscriptions, and policy and provider administration.
- The daemon recording and enforcing spending limits.

### Measured quality

- An independent human reviewer adjudicates the 23 corpus cases.
- Score the sealed run bundle against the adjudicated labels.
- Add public benchmarks (SWR-Bench, AACR-Bench, c-CRAB) to the evaluation
  driver, and publish the numbers.

### Policy, analysis and operations

- **Policy and analysis:** repository-scoped policy packs, deterministic CI
  planning and broader user-visible deterministic rules.
- **Semantic evidence:** type-aware language adapters whose compiler or
  language-server facts could support verification, and heuristics such as
  historical co-change that may only point at review targets. Only the
  `structural` and `syntactic_candidate` grades exist today.
- **Setup:** external delivery reachability, broader replica and failover
  coordination, no-egress enforcement, and governed bundle import.
- **Deployment:** supported installation profiles, OpenTelemetry observability,
  a Docker Compose profile for a single operator, Helm charts or Kubernetes
  manifests for larger installations, restore drills, and air-gapped
  distribution. The setup planner's `kubernetes_ha` profile and its
  shared-store probe are setup checks, not a deployment.
- **Release:** signing, attestation publication and verification, supported
  production upgrade and crash-recovery guarantees, deployment qualification,
  accessibility evidence, and realistic adjudicated evaluation data with
  calibration, cost and latency evidence.

## Release gates

A release candidate must demonstrate:

- exact evidence for every published finding;
- authorization and tenant-isolation negative tests;
- no unapproved provider route, egress, command, or source mutation;
- exact packaged scanner identities, fail-closed 256-field, 2 MiB, residual-scan, and timeout behavior, plus the reviewed 11/14 coverage and known-near-miss baseline;
- no blocking finding derived only from model output, heuristic impact evidence, or undeclared/incomplete semantic coverage;
- visible human-review outcome, coverage, and abstention semantics for every supported surface;
- deployment, upgrade, backup, restore, and recovery verification for its supported profile;
- versioned quality evaluation, calibration, cost, latency, and false-positive evidence;
- signed artifacts, SBOM, provenance, vulnerability reporting, and release notes.

## How work becomes public

Public source contains original implementation, public contracts, tests, user documentation, and release evidence. Local research archives, development records, upstream inspection copies, and confidential configuration remain excluded from the public repository.
