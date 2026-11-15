# Delivery roadmap

Open Trestle aims to be the best open-source code-review agent, one that runs
wherever you work: the command line, a terminal UI, your editor, a GitHub
Action and a desktop app. The goal is a review that steers its models with
specialist skills and system prompts, and that finds, verifies and ranks
findings with memory of past reviews and a map of the codebase. Security and
evidence come first: every finding must point to the source that supports it.

## Status language

**Shipped on this branch** means the code and its tests exist at this commit.
It is not a release. Nothing is released yet, and nothing counts as released
until its release evidence exists (see [release gates](#release-gates)).
**Planned** means not built. Waves are listed in their intended order and carry
no dates. Each planned item ships with tests, documentation and a CHANGELOG
entry.

## Shipped on this branch

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
  separately verified runs and merges their verified findings with a heuristic
  duplicate check. Specialists are off by default, and the daemon does not
  dispatch profiles. See [agent profiles](agent-profiles.md).
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
- **Packaging and release evidence.** An unsigned Linux amd64 candidate with
  install, upgrade, one-step rollback and recovery; SPDX SBOMs; a passive
  vulnerability gate; and a static-debug evaluation over eight built-in cases.
  Nothing is signed. See [operations](operations.md).

## Planned work

### Wave 1: the everyday loop and onboarding

Shipped on this branch (see above): `trestle review`, hidden API key entry with
an owner-only credential store and `trestle keys`, the `trestle` home screen,
and the documentation truth pass, including the three code-side mismatches
(the `knowledge_graph` and `style_conformance` purpose text, the usage text,
and the Dockerfile port). Remaining:

- Review uncommitted changes without writing objects into the repository.
- An OS keyring as an optional backend for saved keys.

### Wave 2: review quality core

- **W2.1 Rank and summarise.** Shipped on this branch: one deterministic
  duplicate rule for a run, the specialists and repeated runs; deterministic
  ranking; confirmed high and medium findings by default with `--all`; a
  pre-existing class that never blocks CI; a verification-led walkthrough
  (what was verified, a per-file change summary, missing verification); and
  text, `--format markdown` and rank-ordered SARIF. See
  [ranked findings and the walkthrough](local-model-review.md#ranked-findings-and-the-walkthrough).
  Remaining: the optional one-paragraph model summary (a separate structured
  request on the verifier route under the same egress, scanning and spending
  rules, labelled with its model and off for local setups); the daemon
  publisher's summary body and the web console, which keep their own rendering;
  the pre-existing class and the walkthrough for investigation runs; the
  optional model-drawn state or sequence diagram; and the evaluation scorer
  reading ranked output.
- **W2.2 Context.** Enclosing definitions for changed hunks; a
  language-agnostic repository map of symbol tags with personalised ranking
  within a token budget; and caller and usage lookups. Go already uses its AST;
  other languages begin with lexical tags, and tree-sitter is a later upgrade.
- **W2.3 Commit and pull-request context.** Shipped on this branch for the
  direct path: `trestle review` and `trestle local-git model-review` read the
  commit messages of `base..head` from the verified Git objects and give them
  to the finder and the verifier as bounded, risk-flagged, secret-scanned
  stated-intent data (generation context 9, verification context 8), never
  instructions; the walkthrough shows the subjects as author-stated and
  unverified; and the drift auditor's intent condition fires under
  `--specialists auto`. See
  [commit messages as stated intent](local-model-review.md#commit-messages-as-stated-intent).
  Remaining: the daemon and webhook path. The `pull_request` webhook payload
  already carries the title and body under the admitted event, so no new
  permission or call is needed, but the webhook planner keeps neither and the
  daemon's run has no bound artifact for them; the daemon also reads no commit
  messages. Linked issue text needs `issues: read`, which is not admitted, so
  it waits for a permission decision. A distinct `intent_mismatch` candidate
  category needs candidate batch v3 (v2 bytes are pinned in every recorded
  context); today a mismatch is a `correctness` candidate.
- **W2.4 Specialists by default.** Shipped on this branch: new setups save
  `--specialists auto` and `trestle review` uses it; specialists run up to
  three at a time on remote routes when no spending limit could be passed, and
  one by one otherwise; the spending warning counts every member;
  `--specialists none` turns them off. Remaining: per-profile route
  assignment.
- **W2.5 Checks from findings.** Planned: when a finding category recurs or is
  accepted, draft a deterministic rule (ast-grep, Semgrep, golangci-lint or
  ESLint) with a failing and a passing fixture, offered as a patch and never
  applied silently.
- **W2.6 Pattern hygiene.** Shipped on this branch, deterministic part: every
  generation context records curated anti-patterns whose count a change raised
  in a directory (base against head), added lint and type suppressions,
  workaround comments, TODO markers without an issue reference and absolute
  rules added to agent instruction and skill files, with a deterministic
  low-severity root-cause note for a suppression beside a workaround comment;
  the walkthrough reports it in text, Markdown and JSON; and the bug hunter and
  frontend skills name per-language nuance traps. See
  [pattern hygiene](local-model-review.md#pattern-hygiene). Remaining: a
  pattern-hygiene specialist profile, deprecated-API detection, more languages
  than Go, JavaScript, TypeScript and Python, and multi-line Python
  signatures.

### Wave 3: memory and learning

- **W3.1 Outcome memory.** Record findings and whether a later commit addressed
  them; record explicit feedback (`trestle feedback`, the IDE, pull-request
  reactions); recall similar past outcomes as advisory context; suppress
  categories by their history, never security. Today the memory index is empty
  unless a manually authored retained-memory file is supplied.
- **W3.2 Metrics.** Address rate and outdated rate in `trestle usage` or a
  stats view and in the console.

### Wave 4: runs anywhere

- **W4.1 A GitHub Action** (`action.yml`), verified live on a test repository.
  This needs maintainer approval to push to one.
- **W4.2 VS Code.** Start a review from the command palette through the CLI
  direct path, show findings as diagnostics, and offer quick-fix code actions
  for suggestions. Today the extension shows the verified diagnostics of one
  daemon run.
- **W4.3 TUI.** Start a review and browse findings interactively. Today the TUI
  observes, and can cancel, one daemon run.
- **W4.4 Pull-request interaction.** Suggestion blocks, check runs and replies
  to the bot. Today the daemon can post one `COMMENT` review.
- **W4.5 Desktop app (last).** Reuse the web console in a native shell.

### Wave 5: tests and execution

This wave needs a security design, reviewed before any code.

- **W5.1 A sandboxed executor** for configured linters and tests, with no
  network and a read-only checkout. Linter and static-analysis findings come
  first, as hints the model must confirm; then test selection and runs as
  evidence; then generated tests, kept only if they build, pass and add
  coverage. Dynamic validation stays separately authorized and off by default.

### Wave 6: measured quality

- An independent human reviewer adjudicates the 23 corpus cases.
- Score the sealed run bundle against the adjudicated labels.
- Add public benchmarks (SWR-Bench, AACR-Bench, c-CRAB) to the evaluation
  driver.

### Other planned work

These items are planned but not yet assigned to a wave.

- **Policy and analysis:** repository-scoped policy packs, deterministic CI
  planning, broader user-visible deterministic rules, and inexpensive read-only
  evidence scouts kept separate from candidate generation and verification.
- **Semantic evidence:** type-aware language adapters whose compiler or
  language-server facts could support verification, and heuristics such as
  historical co-change that may only point at review targets. Only the
  `structural` and `syntactic_candidate` grades exist today.
- **Surfaces and integration:** additional forge adapters, Git-hook
  integration, a gRPC API, streaming subscriptions, and policy and provider
  administration.
- **Setup:** external delivery reachability, broader replica and failover
  coordination, no-egress enforcement, and governed bundle import.
- **Deployment:** supported installation profiles, OpenTelemetry observability,
  a Docker Compose profile for a single operator, Helm charts or Kubernetes
  manifests for larger installations, restore drills, and air-gapped
  distribution. The setup planner's `kubernetes_ha` profile and its
  shared-store probe are setup checks, not a deployment.
- **Release:** signing, attestation publication and verification, supported
  multi-platform packaging, supported production upgrade and crash-recovery
  guarantees, deployment qualification, accessibility evidence, and realistic
  adjudicated evaluation data with calibration, cost and latency evidence.

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
