# Agent profiles and routing plans

Open Trestle packages nine specialist review profiles and a deterministic router
that decides, for one change, which profiles apply, how hard the change is for
each, which difficulty tier to use, and which exact model route the user has
assigned to that tier. The package is `agentprofile`; the CLI is
`trestle profiles`.

## Status

This is a **planning layer**. It is not yet wired into the durable generation and
verification task graph.

What exists today:

- An embedded, versioned, content-identified profile catalog with skill
  instructions for each profile (`agentprofile/skills/*.md`).
- A strict, versioned assignments document that maps tiers to exact
  `provider.RouteReference` values.
- A strict, versioned change-features document, plus a constructor that derives
  the same features from an `evidence.Change` and a `semanticimpact.Profile`.
- `agentprofile.Plan`, which returns a content-identified `RoutingPlan`.
- `trestle profiles list` and `trestle profiles plan`.

What does **not** exist yet:

- No review run dispatches a profile. `trestle local-git model-review`, the
  daemon, and the local review session still use one runtime-policy route pair
  per run.
- Skill instructions are not yet placed into model requests.
- `trestle profiles plan` reads a features file. It does not derive features
  from a Git change by itself.

### Integration seam (follow-up)

The plan already produces the values the existing route authorities take:

| Plan output | Existing consumer |
|---|---|
| `PlanEntry.Requirements()` (`provider.ModelRequirements`) | `requirements` argument of `runtimecatalog.NewGenerationPolicyAuthorizer` and `NewVerificationPolicyAuthorizer` |
| `PlanEntry.CostBudget(maxCostMicroUSD)` (`provider.ModelCostBudget`) | `budget` argument of both authorizers |
| `PlanEntry.RankingPolicy()` (`gateway.RouteRankingPolicy`, pinned) | `ranking` argument of `NewGenerationPolicyAuthorizer` |
| `PlanEntry.VerifierRankingPolicy()` | `ranking` argument of `NewVerificationPolicyAuthorizer` |
| `Assignments.Independence()` (`gateway.RouteIndependencePolicy`) | `independence` argument of `NewVerificationPolicyAuthorizer` |

Today `runtimecatalog.NewGenerationPolicyAuthorizerFromRuntimePolicy` and
`NewVerificationPolicyAuthorizerFromRuntimePolicy` take all of these from one
`runtimeconfig.RuntimePolicy`. Their callers are `localreview/session.go` and
`cmd/trestled/main.go`. To integrate profiles:

1. Add a per-entry constructor in `runtimecatalog` that calls the lower-level
   authorizers with the plan values above.
2. Create one candidate-generation task per planned entry. Create an
   independent-verification task only when `PlanEntry.Verification()` is
   `independent`, using the existing `handlers/model` generation and verification
   handlers. Retain candidates from `unverifiable` entries as non-findings.
3. Carry the profile skill text and the profile identity into the model request
   and context packet (`internal/review/context_packet.go`), so the instruction
   and its version are bound into request identity.
4. Derive change features from the run's `evidence.Change` and semantic-impact
   profile with `agentprofile.ChangeFeaturesFromSemanticImpact`, instead of a
   file.

The verification authorizer currently ranks with an unpinned preference list,
because a generation pin cannot also pin a route that independence excludes.
A per-profile verifier pin has to keep that check.

### What the plan does not bypass

A `RoutingPlan` is advisory input to dispatch. It is not authority. Gateway
eligibility (`internal/gateway/route_eligibility_filter.go`) still runs for every
request. That check covers provider policy zones, local-only requests (no silent
remote fallback), route capacity (`max_output_tokens` must fit the output
capacity, and input plus output must fit the context), cost budgets, and
operational readiness. The gateway also re-checks generator and verifier
independence on resolved records (`route_independence.go`). A plan that names a
route the registry does not have, or one that is ineligible, fails at dispatch.
It never silently falls back.

## Authority

Every profile has the same fixed authority. It is part of the catalog JSON and
cannot be configured:

- Output is **candidates only**. Candidates need independent verification on a
  separate route before they can become findings.
- No tool execution, no network access outside gateway dispatch, no
  publication, and no source mutation.
- No dynamic validation. `security_probe` is static and read-only. Dynamic
  validation needs the separate governed-execution authorization described in
  [architecture](architecture.md#execution), and this layer cannot grant it.
- `test_author` output is a proposed test artifact. This layer never writes or
  runs it.

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
| `drift_auditor` | required | a declared description or linked docs, or docs and code changing together | 40 |
| `style_conformance` | required | a declared style intent that governs a changed language | 20 |

Activation predicates are OR-combined. Vendor (`vendor/`, `node_modules/`,
`third_party/`) and generated files never activate or score a profile. Each
entry records the predicates that matched, or why none did.

Language, file class, and path signals come from exact path rules in
`agentprofile/paths.go`: extensions, directory names, and whole words in the
path. Analyzers can add signals such as `concurrency` or `public_api` through
the features document. Path signals are heuristics. For example, any path with
the word `api` or `server` carries the `http` signal.

Declared style intents come from configuration files only
(`agentprofile/style.go`). `go.mod` gives `gofmt_effective_go`.
`.editorconfig` gives `editorconfig`. Prettier and ESLint configs give
`prettier` and `eslint`. `.flake8`, `ruff.toml`, and the matching `setup.cfg`,
`tox.ini`, or `pyproject.toml` sections give `pep8`. A `[tool.black]` section
gives `black`. A yapf config `based_on_style = google` gives `google_python`.
`.clang-format` gives `clang_format`, and `BasedOnStyle: Google` in it also gives
`google_cpp`. `rustfmt.toml` and `.rubocop.yml` give `rustfmt` and `rubocop`.
Detection never infers a style from source code.

## Assignments document

Schema `open-trestle/agent-profile-assignments`, version 1. Decoding is strict:
unknown fields, duplicate keys, and trailing data are rejected, and the document
may be at most 64 KiB.

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

- `independence` is required: `distinct_route`, `distinct_model`, or
  `distinct_provider`. These are the gateway's terms.
- `tiers` and `verifier_tiers` hold global exact routes. `profiles.<id>` holds
  overrides, which win over global routes. The orchestrator takes no routes.
  An override must assign at least one route, and the document must assign at
  least one generator route.
- **Unassigned tier.** The profile is omitted with reason `tier_unassigned`.
  It never borrows another tier's route unless `escalation_order` is set. With
  an escalation order, the router uses the first assigned tier listed after the
  scored tier and records it as `escalated_from`. Requirements and token budget
  still come from the scored tier, so escalation never loosens what the work
  needs.
- **Verifier.** Without a verifier route that is independent of the generator
  route at the configured level, the entry is `unverifiable`. Its candidates
  cannot become findings, and the router never invents a verifier. Verifier
  routes follow the same override, global, and escalation rules.
- **`total_token_budget`** is optional; 0 or absent means no cap. Each planned
  entry counts its tier's input plus output budget, doubled when an independent
  verifier is planned. Over the cap, the router drops planned entries one at a
  time: lowest priority first, and on equal priority the higher profile ID
  first. It stops as soon as the total fits. Each drop is recorded as
  `budget_cap_exceeded` with the running totals.

## Change-features document

Schema `open-trestle/agent-profile-change-features`, version 1. Decoding is
strict, and the document may be at most 1 MiB.

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

- Paths must be clean, relative, and slash-separated, and none may repeat.
- `coverage` is optional. When it is absent, coverage is recorded as unknown
  and adds no points.
- `intent` records only whether intent was declared, never the text.
- `config_files[].content` is optional and at most 64 KiB. It is read only for
  the exact markers listed above.
- In the canonical form, path-derived signals are merged into `files[].signals`.
  Re-parsing the canonical form gives the same identity.

## Difficulty scoring

All scoring lives in `agentprofile/scoring.go`. Owners tune it in two tables:
`difficultyWeights` and `profileTierThresholds`. The arithmetic is integer-only:

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

"Scope" means the files that activated the profile. The tier comes from the
profile's thresholds: below `standard` is light, from `standard` up to `deep` is
standard, and `deep` or above is deep.

| Profile | standard | deep |
|---|---|---|
| `security_probe` | 8 | 30 |
| `bug_hunter` | 12 | 40 |
| `backend`, `frontend`, `test_author` | 15 | 45 |
| `drift_auditor` | 20 | 60 |
| `knowledge_graph` | 25 | 70 |
| `style_conformance` | 30 | 80 |

Each plan entry includes every row of its breakdown. The scoring table and
thresholds are bound into the catalog identity, so a tuned router is always
distinguishable from the packaged one.

Per-tier token budgets (input / output; the minimum context covers both):

| Tier | Review profiles | Compact profiles (style, drift, knowledge graph) |
|---|---|---|
| light | 16,384 / 4,096 (min context 24,576) | 12,288 / 2,048 (min context 16,384) |
| standard | 65,536 / 8,192 (min context 81,920) | 40,960 / 4,096 (min context 49,152) |
| deep | 163,840 / 16,384 (min context 196,608) | 114,688 / 8,192 (min context 131,072) |

All model-calling profiles require `structured_output`.

## Determinism and identity

`Plan` makes no model call and no network request. It reads no clock and uses no
randomness. The catalog, assignments, features, and plan each have a SHA-256
identity over canonical JSON. The plan identity binds the other three
identities and every entry. Entries are in profile-ID order. Omissions list
unassigned tiers first, in profile order, then budget drops in drop order.

## CLI

```
trestle profiles list
trestle profiles plan --assignments assignments.json --features features.json
```

`list` prints the catalog as one JSON line: profiles, skills, scoring table, and
authority. `plan` prints the `RoutingPlan` as one JSON line. Both inputs must be
regular files within their size bounds.

Exit codes:

- `0` success
- `1` an input could not be read or parsed, or planning failed
- `2` usage error

Example plan entry (abridged):

```json
{
  "profile_id": "bug_hunter",
  "status": "omitted",
  "activation_reasons": ["file_class:source (files=2)"],
  "difficulty": {"score": 20, "max_score": 125, "signals": ["..."]},
  "scored_tier": "standard",
  "verification": "not_applicable",
  "omission": "tier_unassigned",
  "omission_detail": "no generator route is assigned for tier standard and no escalation order supplies one",
  "authority": {"candidates_only": true, "requires_independent_verification": true, "tool_execution": false, "dynamic_validation": false, "network_access": false, "publication": false, "source_mutation": false}
}
```

## Known limitations

- Path signals and file classes are heuristics over paths. They do not inspect
  file content, so concurrency and deserialization signals come only from
  analyzers.
- Deterministic semantic coverage exists only for Go. Every other source
  language counts as a knowledge-graph gap.
- The verifier budget is assumed equal to the generator budget for cap
  accounting.
- Pricing is not consulted. `PlanEntry.CostBudget` takes a caller-supplied cost
  cap, and the gateway enforces it.
