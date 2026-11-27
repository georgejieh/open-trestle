# Agent profiles and routing plans

Open Trestle packages nine specialist review profiles and a deterministic router. For one change, the router decides which profiles apply, how hard the change is for each of them, which difficulty tier to use, and which exact model route you have assigned to that tier. The package is `agentprofile`, and the CLI is `trestle profiles`.

This page is for contributors and for operators who want to understand or tune which specialists review a change.

## Status

This is mainly a **planning layer**. Its only production use is in the direct `trestle local-git model-review` path. There you can pick one profile (`--profile`), or let Open Trestle select the profiles automatically, or list them yourself (`--specialists`). The daemon's durable task graph for generation and verification does not use it.

### What exists today

- An embedded, versioned catalog of profiles, identified by its content, with skill instructions for each profile (`agentprofile/skills/*.md`).
- A versioned assignments document that maps tiers to exact `provider.RouteReference` values.
- A versioned change-features document, and a constructor that derives the same features from an `evidence.Change` and a `semanticimpact.Profile`.
- `agentprofile.Plan`, which returns a `RoutingPlan` that is identified by its content.
- `trestle profiles list` and `trestle profiles plan`.
- `trestle local-git model-review --profile PROFILE_ID` (and `localreview.NewSpecialistSession`). It places the skill instructions of one profile that you selected, and that calls a model, into the candidate-generation request. The skill text goes only into the trusted system channel, looked up from the embedded catalog. The context's optional `specialist` block (review-context schema versions 7, 8 and 9) carries only the profile and catalog identities, which bind the request identity, and the result reports them. The verifier request does not carry the instructions. See [local model review](local-model-review.md#specialist-profile-opt-in) and the [prompt-injection boundary](prompt-injection-boundary.md).
- `trestle local-git model-review --specialists auto|ID[,ID...]`, described below.
- Specialists by default, described below.

#### Automatic specialist selection

With `--specialists auto`, the command derives change features from the general review's own recorded change-model and semantic-impact artifacts, plus the declared style that it reads from the base tree's style configuration files (`localreview.Session.ChangeFeatures`, then `agentprofile.ChangeFeaturesFromFileSpecs`; see [Declared style in local reviews](#declared-style-in-local-reviews)). It then calls `Plan`, and keeps the activated, planned direct-review profiles in priority order, cut to `--max-specialists` (default 3, at most 6).

It then runs the general review and each selected profile as its own verified run. On remote routes, the runs go concurrently (at most three at a time) when no spending limit could be passed, and one by one otherwise. The command merges the verified findings with the shared duplicate rule: near-identical statements first, then paraphrases at one place in one changed declaration.

The selection trace records the plan identity and every dropped profile with its reason. It is in the JSON output and in `--verbose` text, while the default text names the reviewers that ran. See [local model review](local-model-review.md#specialist-review-set-opt-in).

#### Specialists by default

A new setup (`trestle init`, or `trestle setup bootstrap init`) saves `--specialists auto` in its review command, so `trestle review` runs the set. To keep the single general review, pass `--specialists none` at setup, or `trestle review --specialists none` for one run. The wizard does not ask. Setups saved before this default keep the single review.

### Current limits

- The daemon does not dispatch profiles. Its context-assembly handler never binds a specialist block. The request validators that it shares accept a version 7 specialist block only when the block re-derives exactly from the embedded catalog.
- `--profile` does not accept `test_author`, because its test proposals do not fit the defect-claim candidate contract.
- There is no daemon fan-out. Automatic selection exists only in the direct `local-git model-review` path. The daemon never runs more than one generation per review run.
- There is no per-profile route assignment. A `--profile` or `--specialists` run uses the one runtime-policy pair of generation and verification routes for every member. For `--specialists auto`, `Plan` needs an assignments document, so the command synthesizes a minimal one. It maps every tier to the policy's generation route (its pin, else its first preferred route, else the first inventory route), and every verifier tier to its verification route. The command does not read an assignments file from the operator and has no total token cap, so `budget_cap_exceeded` does not occur there. The plan's tiers, token budgets and route choice are informational.
- Recorded change features carry only the counts of changed head lines (deleted lines count as zero). They declare change intent when the generation context of the general review carried the commit messages of the range (presence only, never the text; see [commit messages as stated intent](local-model-review.md#commit-messages-as-stated-intent)). They also list, as linked docs, the [project intent documents](local-model-review.md#project-intent-documents) that context carried (paths only). The intent condition of `drift_auditor` therefore activates under `auto` on a change with commits or with a project intent document in the base tree. No pull-request description is read. `style_conformance` activates under `auto` when the base tree declares a style that governs a changed language. Difficulty tiers are informational.
- `trestle profiles plan` reads a features file. It does not derive features from a Git change by itself.

### What the plan does not bypass

A `RoutingPlan` is advisory input to dispatch, not authority. Gateway eligibility (`internal/gateway/route_eligibility_filter.go`) still runs for every request. That check covers:

- provider policy zones
- local-only requests (no silent remote fallback)
- route capacity: `max_output_tokens` must fit the output capacity, and input plus output must fit the context
- cost budgets
- operational readiness

The gateway also re-checks the independence of generator and verifier on resolved records (`internal/gateway/route_independence.go`). A plan that names a route the registry does not have, or one that is ineligible, fails at dispatch. It never silently falls back.

## Authority

Every profile has the same fixed authority. It is part of the catalog JSON and cannot be configured:

- Output is **candidates only**. Candidates need verification on a separate route before they can become findings.
- A profile has no tool execution, no network access outside gateway dispatch, no publication and no source mutation.
- A profile does no dynamic validation. `security_probe` is static and read-only. Dynamic validation needs the separate governed-execution authorization described in [architecture](architecture.md#execution), and this layer cannot grant it.
- `test_author` output is a proposed test artifact. This layer never writes or runs it. Specialist runs (`--specialists`) never select it either. The tests that `--model-checks` runs come from the checker of an ordinary review, not from this profile; see [model-written checks](repository-checks.md#model-written-checks).

## Profiles

| ID | Model call | Activates on | Priority |
|---|---|---|---|
| `orchestrator` | none | every change | 100 |
| `security_probe` | required | security signals (auth, crypto, http, exec, sql, webhook, secrets, deserialization, CI config, dependency manifests) and `.env`, `.pem`, `.key` files | 90 |
| `bug_hunter` | required | source files | 80 |
| `backend` | required | server-side languages, SQL, or concurrency and persistence signals | 70 |
| `frontend` | required | HTML, CSS, JavaScript, TypeScript, Vue, Svelte | 70 |
| `knowledge_graph` | gap only | source files; a model is needed only when a changed source language has no deterministic analyzer (Go has one) or the analyzer reported a gap | 60 |
| `test_author` | required | source files | 50 |
| `drift_auditor` | required | a declared description or linked docs (including project intent documents), or docs and code changing together | 40 |
| `style_conformance` | required | a declared style intent that governs a changed language | 20 |

The `bug_hunter` (version 2) and `frontend` (version 2) skills each end their checklist with a short list of **nuance traps**: APIs that are easy to use almost correctly and deserve extra scrutiny. `bug_hunter` names Go goroutine and channel leaks, `defer` in a loop, loop-variable capture before Go 1.22, `time.Sleep` and library `panic`, and Python mutable defaults and bare `except:`. `frontend` names React `useEffect` and imperative timers. Both point the model at the lines that the packet's deterministic `pattern_hygiene` evidence cites (see [pattern hygiene](local-model-review.md#pattern-hygiene)). Both also ask that a candidate about a new suppression or workaround comment name the root cause.

The `drift_auditor` skill (version 2) compares the change with the commit messages and project intent documents. Besides intent versus code and docs versus code, it looks for **scope** (behaviour no stated intent asks for, work against a stated non-goal or constraint, a subsystem much larger than the stated need) and **residue** (code the change makes dead, a second implementation of something the context already has, new use of an API the context marks deprecated, an abstraction with one caller and no stated reason, comments that narrate the change). Each candidate quotes the intent line or cites the code lines it rests on.

### Catalog and profile versions

The catalog is version 1. Six profiles are at profile version 2 and the other three are at version 1:

- Version 2: `security_probe`, `bug_hunter`, `frontend`, `knowledge_graph`, `style_conformance` and `drift_auditor`.
- Version 1: `orchestrator`, `backend` and `test_author`.

A profile version bump changes the catalog identity, and with it the identity of every plan that includes the profile.

### How profiles activate

Activation predicates are OR-combined. Vendor files (`vendor/`, `node_modules/`, `third_party/`) and generated files never activate or score a profile. Each entry records the predicates that matched, or why none did.

Language, file class and path signals come from exact path rules in `agentprofile/paths.go`: extensions, directory names, and whole words in the path. Analyzers can add signals such as `concurrency` or `public_api` through the features document. Path signals are heuristics. For example, any path with the word `api` or `server` carries the `http` signal.

### How a declared style is detected

Declared style intents come from configuration files only (`agentprofile/style.go`). Detection never infers a style from source code.

- `go.mod` gives `gofmt_effective_go`.
- `.editorconfig` gives `editorconfig`.
- Prettier and ESLint configs give `prettier` and `eslint`.
- `.flake8`, `ruff.toml`, and the matching sections of `setup.cfg`, `tox.ini` or `pyproject.toml` give `pep8`.
- A `[tool.black]` section gives `black`.
- A yapf configuration is read from its own section only: `[style]` in `.style.yapf`, `[yapf]` in `setup.cfg`, and `[tool.yapf]` in `pyproject.toml`. Its `based_on_style` gives `google_python` when it is `google` or `yapf` (a style that yapf derives from Google's), and `pep8` for any other base or none, since yapf's default base is PEP 8. A `.style.yapf` without a `[style]` section also gives `pep8`. A `based_on_style` outside those sections, or in `tox.ini`, which yapf does not read, declares nothing.
- `.clang-format` gives `clang_format`, and `BasedOnStyle: Google` in it also gives `google_cpp`.
- `rustfmt.toml` and `.rubocop.yml` give `rustfmt` and `rubocop`.

The `style_conformance` skill has guidance for gofmt and Effective Go, PEP 8 with Black and Google Python style, Google C++ with clang-format, and Prettier, ESLint and EditorConfig. It has no section for `rustfmt` or `rubocop`, so a review that activates it for those styles gets only its general rules.

### Declared style in local reviews

`trestle local-git model-review` reads the configuration files for style detection from the review's base tree (the default-branch side), not from the head. Open Trestle reviews an edit to a style configuration as ordinary changed code. A configuration that exists only in the head declares nothing. A configuration that differs between base and head is read as it is in the base, including one that the head deletes.

- Only root-level files are read, following the repository instruction files (see [context assembly](runtime.md#context-assembly)). A subproject's own configuration, such as `services/api/ruff.toml`, is not read.
- Only the names that detection recognizes are read (`agentprofile.IsStyleConfigFile`): `go.mod`, `.editorconfig`, `.prettierrc` and `.prettierrc.*`, `prettier.config.*`, `package.json`, `.eslintrc` and `.eslintrc.*`, `eslint.config.*`, `.flake8`, `.pycodestyle`, `ruff.toml`, `.ruff.toml`, `setup.cfg`, `tox.ini`, `pyproject.toml`, `.style.yapf`, `.clang-format`, `_clang-format`, `rustfmt.toml`, `.rustfmt.toml` and `.rubocop.yml`.
- Contents come from the base file artifacts that source acquisition already recorded for the run. No Git object is read again.
- A file larger than 64 KiB, or not valid UTF-8, is skipped whole and never truncated. So is every readable file after the first 256 in path order, and so is every file that would push the change-features document past its 1 MiB bound. Files are added in path order, so a later, smaller file may still fit. A skipped file declares nothing. The selection trace of the review set counts the skipped files in `features.style_configuration_unread`.

The same declared style decides the review result's [style recommendations](local-model-review.md#style-recommendations) (`agentprofile.RecommendStyles`). It uses the files that the change-features document carries, so a file that routing skips is unread for the recommendations too. Only when routing has no change features (the analysis was not recorded) do the recommendations use every readable file.

## Assignments document

The schema is `open-trestle/agent-profile-assignments`, version 1. Decoding is strict: unknown fields, duplicate keys and trailing data are rejected, and the document may be at most 64 KiB.

```json
{
  "schema": "open-trestle/agent-profile-assignments",
  "version": 1,
  "independence": "distinct_provider",
  "tiers": {
    "light":    {"zone": "local", "provider_id": "ollama", "adapter_id": "chat-completions", "connection_id": "local/ollama", "model_id": "qwen3:8b", "model_version": ""},
    "standard": {"zone": "local", "provider_id": "ollama", "adapter_id": "chat-completions", "connection_id": "local/ollama", "model_id": "qwen3:32b", "model_version": ""}
  },
  "verifier_tiers": {
    "light":    {"zone": "local", "provider_id": "llamacpp", "adapter_id": "chat-completions", "connection_id": "local/llamacpp", "model_id": "gemma-3-27b", "model_version": ""}
  },
  "profiles": {
    "security_probe": {
      "tiers": {"light": {"zone": "local", "provider_id": "ollama", "adapter_id": "chat-completions", "connection_id": "local/ollama", "model_id": "qwen3:32b", "model_version": ""}}
    }
  },
  "escalation_order": ["light", "standard", "deep"],
  "total_token_budget": 400000
}
```

- `independence` is required. Its value is `distinct_route`, `distinct_model` or `distinct_provider`, which are the gateway's terms.
- `tiers` and `verifier_tiers` hold global routes. `profiles.<id>` holds overrides, which win over the global routes. The orchestrator takes no routes. An override must assign at least one route, and the document must assign at least one generator route.
- `escalation_order` is optional and controls what happens to a tier without a route.
- `total_token_budget` is optional. A value of 0, or no value, means no cap.

### Unassigned tiers

When a tier has no route, the profile is omitted with the reason `tier_unassigned`. It never borrows another tier's route unless `escalation_order` is set. With an escalation order, the router uses the first assigned tier that is listed after the scored tier, and records it as `escalated_from`. The requirements and the token budget still come from the scored tier.

### Verifier routes

If no verifier route is independent of the generator route at the configured level, the entry is `unverifiable`. Its candidates cannot become findings. Verifier routes follow the same override, global and escalation rules.

### Token budget

Each planned entry counts its tier's input plus output budget, doubled when an independent verifier is planned. When the total is over the cap, the router drops planned entries one at a time. It drops the lowest priority first and, on equal priority, the higher profile ID first. It stops as soon as the total fits. Each drop is recorded as `budget_cap_exceeded` with the running totals.

## Change-features document

The schema is `open-trestle/agent-profile-change-features`, version 1. Decoding is strict, and the document may be at most 1 MiB. Construction enforces the same bound on the canonical encoding (`ErrChangeFeaturesTooLarge`), so every features value can be written and read back. `agentprofile.FitConfigFiles` selects the configuration files that fit.

```json
{
  "schema": "open-trestle/agent-profile-change-features",
  "version": 1,
  "files": [
    {"path": "web/src/Login.tsx", "added_lines": 40, "deleted_lines": 2},
    {"path": "internal/auth/session.go", "added_lines": 12, "deleted_lines": 0, "signals": ["concurrency"]}
  ],
  "public_api_changes": 1,
  "reference_fan_out": 9,
  "coverage": {"uncovered_changed_lines": 30},
  "intent": {"description_present": true, "linked_doc_paths": ["docs/auth.md"]},
  "config_files": [{"path": "go.mod"}, {"path": "pyproject.toml", "content": "[tool.black]\n"}],
  "semantic_gap_paths": [],
  "change_identity": "",
  "semantic_profile_identity": ""
}
```

- Paths must be clean, relative and slash-separated, and none may repeat.
- `coverage` is optional. When it is absent, coverage is recorded as unknown and adds no points.
- `intent` records only whether intent was declared, never the text.
- `config_files[].content` is optional and at most 64 KiB. It is read only for the exact markers listed above.
- In the canonical form, path-derived signals are merged into `files[].signals`. Parsing the canonical form again gives the same identity.

## Difficulty scoring

All scoring lives in `agentprofile/scoring.go`. Owners tune it in two tables, `difficultyWeights` and `profileTierThresholds`. The arithmetic uses integers only:

```
points(signal) = min(cap, (observed / divisor) * points)
score          = sum(points)        # 0..125
```

| Signal | Observed value | Divisor | Points | Cap |
|---|---|---|---|---|
| `changed_lines` | added + deleted lines in scope | 25 | 1 | 20 |
| `changed_files` | files in scope beyond the first | 1 | 2 | 16 |
| `languages` | distinct languages in scope beyond the first | 1 | 4 | 8 |
| `public_api_changes` | changed exported declarations (change-wide) | 1 | 5 | 20 |
| `reference_fan_out` | references to changed declarations (change-wide) | 4 | 1 | 15 |
| `security_sensitive_signals` | distinct security signal kinds in scope | 1 | 6 | 18 |
| `concurrency` | files in scope with a concurrency signal | 1 | 4 | 12 |
| `test_absence` | 1 when scope has source changes and no test file changed | 1 | 6 | 6 |
| `coverage_gap` | uncovered changed lines (0 when unknown) | 20 | 1 | 10 |

"Scope" means the files that activated the profile. The tier comes from the profile's thresholds: a score below `standard` is light, a score from `standard` up to `deep` is standard, and a score of `deep` or above is deep.

| Profile | standard | deep |
|---|---|---|
| `security_probe` | 8 | 30 |
| `bug_hunter` | 12 | 40 |
| `backend`, `frontend`, `test_author` | 15 | 45 |
| `drift_auditor` | 20 | 60 |
| `knowledge_graph` | 25 | 70 |
| `style_conformance` | 30 | 80 |

Each plan entry includes every row of its breakdown. The scoring table and thresholds are bound into the catalog identity.

The token budgets for each tier are below, as input / output. The minimum context covers both.

| Tier | Review profiles | Compact profiles (style, drift, knowledge graph) |
|---|---|---|
| light | 16,384 / 4,096 (min context 24,576) | 12,288 / 2,048 (min context 16,384) |
| standard | 65,536 / 8,192 (min context 81,920) | 40,960 / 4,096 (min context 49,152) |
| deep | 163,840 / 16,384 (min context 196,608) | 114,688 / 8,192 (min context 131,072) |

All model-calling profiles require `structured_output`.

## Determinism and identity

`Plan` makes no model call and no network request. It reads no clock and uses no randomness. The catalog, the assignments, the features and the plan each have a SHA-256 identity over canonical JSON. The plan identity binds the other three identities and every entry. Entries are in profile-ID order. The omissions list the unassigned tiers first, in profile order, and then the budget drops, in drop order.

## CLI

```
trestle profiles list [--format text|json]
trestle profiles plan --assignments assignments.json --features features.json
```

By default (`--format text`), `list` prints one line per profile with these columns:

- its ID
- when it calls a model (`required`, `gap_only` or `none`)
- whether `local-git model-review` accepts it in `--profile` and `--specialists` (`--profile`) or only plans it (`plan only`)
- its purpose

Three closing lines give the profile count and the catalog identity, explain the `REVIEW` column, and point to `profiles plan` and the JSON form. The catalog binds no provider, model or zone, and an assignments document binds those for each tier.

`list --format json` prints the catalog as one JSON line: the profiles, skills, scoring table and authority. `plan` prints the `RoutingPlan` as one JSON line. Both input files must be regular files within their size bounds. The singular `trestle profile` is a different command: it reports the repository profile, not these review profiles.

Exit codes:

- `0` success
- `1` an input could not be read or parsed, or planning failed
- `2` usage error

## Known limitations

- Path signals and file classes are heuristics over paths. They do not inspect file content, so concurrency and deserialization signals come only from analyzers.
- Deterministic semantic coverage exists only for Go. Every other source language counts as a knowledge-graph gap.
- For cap accounting, the verifier budget is assumed to equal the generator budget.
- Pricing is not consulted. `PlanEntry.CostBudget` takes a cost cap that the caller supplies, and the gateway enforces it.
