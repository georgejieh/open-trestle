# Local model review

`trestle local-git model-review` asks language models to review the change between two commits that you name. Developers and CI jobs use it, and `trestle review` runs it for you after `trestle init`. This page covers how to run it, the options, the output and the exit codes.

The command is an explicit request for model calls. It does not publish a forge review or create a required check, and it does not change `local-git review`.

For private source, prefer a local model or a provider whose retention terms you have checked (see [why](rationale.md#local-models-and-zero-data-retention-providers-are-recommended)). `--egress policy-approved` can send sanitized, scanned source to an approved remote route (see [Authority and egress](#authority-and-egress) and [remote model review](remote-model-review.md)).

```text
trestle local-git model-review \
  --objects-root /approved/repository/.git/objects \
  --repository-authority example.test \
  --repository-namespace team \
  --repository-name repository \
  --revision-algorithm sha1 \
  --base-revision-digest FULL_LOWERCASE_BASE_COMMIT_DIGEST \
  --head-revision-digest FULL_LOWERCASE_HEAD_COMMIT_DIGEST \
  --tenant TENANT --repository REPOSITORY \
  --route-inventory /protected/routes.json \
  --runtime-policy /protected/policy.json \
  --egress local-only --timeout 5m \
  --object-store loose-and-pack-index-v1 --format json
```

Write each flag and its value as two separate words. The command refuses repeated flags, flags in `--flag=value` form, missing values, unknown flags and equal revisions. It has no flags to publish, resume, keep state or name an existing run.

| Flag | Meaning |
| --- | --- |
| `--objects-root`, `--revision-algorithm`, `--base-revision-digest`, `--head-revision-digest` | Select the two commits from a Git objects folder, by full lowercase SHA-1 or SHA-256 digest. |
| `--checkout`, `--base`, `--head` | Select the two commits from an ordinary checkout (see [Ordinary checkout source selection](#ordinary-checkout-source-selection)). Do not combine with the flags above or `--object-store`. |
| `--repository-authority`, `--repository-namespace`, `--repository-name` | Labels for the repository. They authenticate nothing and trigger no request. |
| `--tenant`, `--repository` | The scope labels your operator approved. |
| `--route-inventory`, `--runtime-policy` | The protected configuration files (see [Authority and egress](#authority-and-egress)). |
| `--egress` | `local-only` or `policy-approved`. |
| `--timeout` | From one second to 15 minutes. |
| `--object-store` | `loose-only` (the default) or `loose-and-pack-index-v1` (see [Object store profile](#object-store-profile)). |
| `--format` | `json` (the default), `text`, `sarif` or `markdown`. |
| `--all`, `--verbose` | Without a value. `--all` lists every finding in text and Markdown. `--verbose` adds the limitations and, for a review set, the selection trace to the text output. |
| `--exit-code-policy` | `default`, `findings`, `strict` or `always-zero` (see [Exit-code policy](#exit-code-policy)). |
| `--profile`, `--specialists`, `--max-specialists` | Specialist reviewers (see [Specialist profile](#specialist-profile-opt-in) and [Specialist review set](#specialist-review-set-opt-in)). |
| `--investigation-policy` | Bounded snapshot tools for the generation model (see [Snapshot investigation](#snapshot-investigation-opt-in)). |
| `--retained-memory-input` | Operator advice from an earlier review (see [Retained advisory input](#retained-advisory-input-opt-in)). |
| `--repository-checks` | Without a value. Runs the repository's own tests and linters in a sandbox first (see [repository checks](repository-checks.md)). Do not combine with `--investigation-policy`. |

## How a review works

1. You select two distinct commits, a base and a head. The command reads their objects and works out what changed. It reviews committed work only, not the index or the working tree.
2. Open Trestle selects the changed source that it may send, sanitizes it and scans it for secrets. It sends the result to the generation route that your route inventory and runtime policy name. That model proposes candidate findings.
3. A second model reviews each candidate. The runtime policy must name this verification route separately from the generation route, and a different model family is recommended (see [why](rationale.md#the-checker-should-come-from-a-different-model-family)). Only a candidate that the verifier confirms becomes a verified finding.
4. The command prints one result and exits with a code that summarizes it.

`--egress local-only` refuses any route that is not local.

### What the output tells you

The result is a single document on standard output. Read the `status`, `ci_disposition`, `run_status`, `limitations` and `diagnostics` fields together:

- A run that succeeded means that the pipeline finished. It does not mean that the repository is clear.
- Verified findings give `ci_disposition: blocked`. The exception is an [advisory](#advisory-results) run, which gives `inconclusive`.
- No candidates, incomplete evidence and an abstention all give `inconclusive`.
- A test regression that the [repository checks](repository-checks.md) proved gives `blocked`, whatever the models did (see [check regressions](#check-regressions)).
- Refusal and failure are separate terminal statuses.
- An empty finding list is not an approval, and the result carries `comprehensive_clearance: false`.

The JSON output is one receipt of type `open-trestle/local-git-model-review-result`. Text and Markdown list the confirmed high, critical and medium findings and count the rest. When there are none of those, they list up to 10 lower-severity findings. `--all` lists every finding. JSON and SARIF always carry every finding. The JSON is at most 256 KiB and the text at most 64 KiB (1 MiB and 256 KiB for a review set). An output that does not fit fails the command instead of truncating findings.

### Exit codes

By default the command never exits with 0:

| Exit | Meaning |
| --- | --- |
| 4 | There are verified findings that block (an introduced medium, high or critical finding), the repository checks proved a test regression, or the run was refused for policy or resource reasons. |
| 3 | There are only [advisory](#advisory-results) findings, or there are no candidates, the evidence is incomplete, the source is unsupported, or the run was canceled. |
| 2 | The command was used incorrectly. |
| 1 | The result was internal or malformed, or the output failed. |

If a CI step must pass when a completed review has no blocking findings, use the opt-in `--exit-code-policy` (see [Exit-code policy](#exit-code-policy)).

## Reviewing the latest change with `trestle review`

After `trestle init` (see [getting started](getting-started.md)), `trestle review` runs this same command for you. It finds the saved setup and takes the route inventory, runtime policy, scope labels, egress and timeout from the saved review command. It replaces only the two commits, which it picks again on every run:

- the head is `HEAD`;
- the base is the newest commit that `HEAD` shares with the default branch.

`--base REF` and `--head REF` pick the commits exactly. With `--head REF` alone, the base is the newest commit that REF shares with the default branch. A new setup saves `--format text` and, unless you set it up with `--specialists none`, `--specialists auto`.

The result goes to standard output in the saved format or in the one you pass with `--format`. Every other line, including the commits, where the source is sent and the spending and scanning messages, goes to standard error. These flags pass through: `--directory`, `--timeout`, `--profile`, `--specialists`, `--max-specialists`, `--exit-code-policy`, `--all`, `--verbose`, `--checks` and `--no-checks`.

The command sends nothing and exits with 3 when the repository has no setup, when there is no committed change to review, or when the API key of the setup is missing (set it with `trestle keys set NAME`). It exits with 4 when the saved setup cannot be loaded. It exits with 2 outside a Git checkout, with flags that the saved setup cannot combine, or when the setup belongs to another repository. `trestle review PATH` reviews a local fixture file instead.

### The result on a terminal

When standard output is a terminal and the format is `text`, `trestle review`
prints a short view instead of the text document. It starts with the verdict
and the exit status, then the reviewers that ran, any reviewer that did not
finish and its hint, the check regressions, and the findings, numbered by rank,
with the severity in color (`error` red, `warning` amber, the others dim), the
location, category, the reviewers that confirmed each, the claim and the fix
text. A short "Checked" line follows, then the reminder that the review is not a
complete audit. The verdict is printed once, at the top, and standard error no
longer repeats it.

```text
  ✗ 1 confirmed finding · CI blocked (exit 4)
    4 of 4 reviewers ran: general, bug_hunter, backend,
    drift_auditor

  1. error  Zero-valued caller now panics
     a.go:2-2 · correctness · confirmed by general,
     bug_hunter, backend, drift_auditor
     Consume passes zero to Changed after removal of the
     division guard.

  Checked:  secret scan clean · checker confirmed 4 of 4
            candidates · 1 changed function without a test
  Not a complete audit. Details: trestle review --verbose
```

`--verbose` prints the full text document on a terminal too. When standard
output is not a terminal, and in the `json`, `sarif` and `markdown` formats,
the output is the same as before, byte for byte, and the verdict line stays on
standard error.

### Progress

A review can take several minutes, so standard error shows what it is doing. On a terminal, one line names the stage, with a spinner and the time it has taken, redrawn in place. When a stage ends, a line with its duration stays behind:

```text
✓ Repository checks · 38s
⠹ Checking findings · bug_hunter (2 of 4 reviewers) · 1m 12s
```

When a review finishes, the progress line is replaced by one closing line with the total time, `Reviewed in 2m 14s.`. A review that stops early prints no closing line.

The stages are indexing the repository, the repository checks, preparing the secret scanner (first use only), preparing the review, finding problems, checking findings, finishing, and a request sent again after a failure or an answer that could not be used, which shows as `(retrying)`. In a specialist review each line names the reviewer and its place, and reviewers that run at once share one line: `Reviewing · 2 of 4 reviewers done · 2m 03s`. There is no percentage, because the time a model takes is not known; the counts are the only bound shown. The repository checks run as one stage, without a count of tests.

When the locale is set and is not UTF-8, the spinner is `|`, `/`, `-` and `\` in turn and a finished stage starts with `[ok]`. `NO_COLOR` removes the colors. When standard error is not a terminal, such as in CI or a pipe, or `TERM` is `dumb`, each stage prints one plain line when it starts, with no control characters:

```text
Preparing the review
Finding problems
Checking findings
Finishing
Reviewed in 2m 14s.
```

The stages that already print their own notice (indexing, checks, the scanner) print nothing more. The line is cleared before any other message and before the result, so standard output is the result alone, byte for byte, in every format. A line is cut to the width of the terminal, or 60 columns when it is not known.

## Ordinary checkout source selection

Instead of the object-root flag and the three revision flags, you can select two immutable commits from an ordinary local checkout:

```sh
trestle local-git model-review \
  --checkout /path/to/repository \
  --base refs/heads/main --head HEAD \
  --repository-authority example.test \
  --repository-namespace team --repository-name repository \
  --tenant TENANT --repository REPOSITORY \
  --route-inventory /protected/routes.json \
  --runtime-policy /protected/policy.json \
  --egress local-only --timeout 5m --format text
```

`--base` and `--head` are both required. Each accepts `HEAD`, an exact full lowercase commit digest, or a full `refs/heads/...` or `refs/tags/...` name. The command has no default base and does not infer a merge base. It does not accept short branch names or revision expressions, and it does not review the index or a dirty worktree. An annotated tag must resolve to a commit. If both selections resolve to the same commit, the command refuses.

This form needs an installed Git that supports `--no-lazy-fetch`. Git resolves the shared object directory (including linked worktrees), the object format and the selected commit IDs. The immutable reader then authenticates those exact objects with `loose-and-pack-index-v1`. A ref that changes after the selection does not change the commits that were already acquired.

Preparing the source runs no shell, fetch, checkout, filter, textconv, hook, credential helper or maintenance command. It clears inherited Git overrides and the global and system configuration. The repository configuration and its includes are still read as ordinary metadata by the same user, so do not point the command at an untrusted checkout if those reads are not acceptable.

## Headless CI use

`trestle ci --format=json|sarif PATH` reviews a local fixture file. It does not select an arbitrary checkout and does not call models. For a model-backed review of a checkout without a terminal, use the foreground command below. It needs no terminal prompt and creates no durable run.

Before you run it, prepare both commits in the checkout and set `BASE_COMMIT` and `HEAD_COMMIT` to two distinct full lowercase commit digests. Provision the protected route inventory, the runtime policy and any required credential references separately.

```sh
trestle local-git model-review \
  --checkout /approved/repository \
  --base "$BASE_COMMIT" --head "$HEAD_COMMIT" \
  --repository-authority example.test \
  --repository-namespace team --repository-name repository \
  --tenant TENANT --repository REPOSITORY \
  --route-inventory /protected/routes.json \
  --runtime-policy /protected/policy.json \
  --egress local-only --timeout 5m --format json
```

Replace the example paths and labels with approved values. The CI runner needs the supported Git version and permission to read the selected objects. This example uses `local-only`, which refuses remote routes.

Capture stdout as one JSON receipt and keep the process exit status. Inspect `status`, `ci_disposition`, `run_status`, `limitations` and `diagnostics` together. The opt-in [exit-code policy](#exit-code-policy) can map a completed review to 0.

For a pull request, use `github.event.pull_request.base.sha` and `head.sha` as the pinned commits. See [GitHub pull-request review](github-pr-review.md) and the [example workflow](../examples/github-actions/README.md).

### SARIF output

`--format sarif` writes one newline-terminated SARIF 2.1.0 document. It carries only verified findings:

| SARIF | Source |
| --- | --- |
| `ruleId` | `open-trestle/<category>`, or `open-trestle/uncategorized` |
| `level` | high and critical are `error`, medium is `warning`, low is `note` |
| `message.text` | `title: claim`, the text the verifier checked |
| `locations[0].physicalLocation` | repository-relative path and start and end line |
| `fingerprints` | `openTrestleVerifiedFindingId/v1`, the run-specific finding identity |
| `partialFingerprints` | `openTrestleFindingFingerprint/v1` and `openTrestleContentHash/v1` (path, category, title and claim, plus `side=base` for a finding on a removed base line) |
| `properties` | category, severity, verification independence, evidence IDs, `trestleRank`, `trestlePreExisting` and `trestleUnprovenOrigin` (the last two only when true), and `trestleFixGuidance` with `trestleFixAuthority: unverified_model_guidance` |
| run `properties` | status, CI disposition, run status, failure, sorted limitations, counts, source coverage and omissions, `trestleComprehensiveClearance: false`, and the [style advice](#style-recommendations) |

Fix guidance is a result property, not a SARIF `fixes[]` entry, because it is prose that nothing applies. `openTrestleContentHash/v1` stays equal across pushes when the same path, category, title and claim recur, which lets code scanning match an alert between runs. The model may word the same problem differently, so the matching is best effort. Identical input yields identical bytes.

A run that was refused, could not read the change, was canceled or failed is still valid SARIF. It has zero `results`, `executionSuccessful: false` and one `error` notification. A run that completed with no candidates or with coverage gaps has an empty result list, `executionSuccessful: true` and a `note` or `warning` notification.

[Check regressions](#check-regressions) name no source line, so they are not results. Each listed one is an `error` notification, and the run property `trestleCheckRegressions` carries the `check_regressions` object.

### Markdown output

`--format markdown` writes a pull request summary comment with a `## Open Trestle review` heading, then `### Check regressions` when there are any, `### What was verified`, `### Changes`, `### Missing verification`, `### Confirmed findings` (a numbered list in rank order), `### Pre-existing findings`, the hidden count, and a footer that states that comprehensive clearance is false and that titles, claims and fix text are untrusted model output. A review set adds the members that confirmed each finding.

Titles, claims, fix text, paths and declaration names are escaped. They cannot open emphasis, a link, an image, a heading, a table cell or an HTML tag, and they cannot mention anyone or become an autolink.

### Exit-code policy

By default the exit status follows the table above and is never 0. A CI step that must pass on a completed review without blocking findings can opt in with `--exit-code-policy`. The flag changes only the process exit status. The output is identical under every policy.

| Policy | Exit 0 when | Otherwise |
| --- | --- | --- |
| `default` (when the flag is absent) | never | 4, 3, 2 or 1 as in the table |
| `findings` | the run succeeded, no verified finding has high or critical severity (including no candidates, medium or low findings only, and coverage gaps) and there is no check regression | the default code |
| `strict` | the run succeeded with no candidates at all and no check regression | the default code, so any verified finding or check regression fails the step |
| `always-zero` | a valid result was written, including a refused or failed run | 1 only if the result could not be written; 2 for invalid usage |

`always-zero` is for advisory use only. Pair it with SARIF or the JSON status, because a green step says nothing about whether the review ran or whether a check regression was found.

### Shallow and pull-request checkouts

Checkout mode reads only the objects of the two named commits. It does not fetch and does not deepen a shallow clone. When the command cannot resolve the selected base or head, the run is `incomplete`, no model is called, and stderr says why.

In a shallow checkout, the message names the missing revision and the commands to run. Either run `git fetch --no-tags --depth=N origin <sha>`, where N must reach the base, or, in GitHub Actions, use `actions/checkout` with `fetch-depth: 0`. A partial clone (`--filter=...`) can resolve the commits but still lack file contents. The run is then `incomplete`, and stderr suggests checking out again without a filter.

## Object store profile

The default profile is `loose-only`. It reads only loose Git commit, tree and blob objects under the `objects` root that you supply.

`--object-store loose-and-pack-index-v1` opts in to a narrow subset of packed Git storage. It still uses loose objects when they exist, and it reads `.pack` files and version-2 `.idx` files from `objects/pack` only when a loose object is absent. The `--revision-algorithm` you select binds the packed reader to SHA-1 or SHA-256 object names.

The packed subset has these limits:

- The reader acquires commit, tree and blob objects. It refuses a selected tag and a delta chain that resolves to a tag.
- The bases of OFS_DELTA and REF_DELTA objects must be in the same pack. Thin packs with external bases are refused.
- Duplicate object IDs across accepted packs are refused. Repacking during a run can make the source invalid or incomplete.
- Multi-pack-index files, promisor objects and alternates are not supported.
- The command does not take an atomic snapshot of the repository.

Repositories that have only packs are unsupported without the opt-in. Also unsupported are worktree pointer files given as object roots, symlink and gitlink source entries, unavailable objects, and other Git layouts.

## Authority and egress

You supply both the route-inventory and the runtime-policy JSON files. The policy must bind the identity of the decoded inventory. Both files must pass the owner, ancestor, mode, symlink and replacement checks of `internal/fileauthority`. The inventory may be at most 8 MiB and the policy under 1 MiB. On platforms where ownership checks are unsupported, loading fails. There is no policy fallback from the environment.

`local-only` requires local routes and canonical numeric loopback endpoints. The local transport disables proxies.

`policy-approved` still applies the protected inventory and policy. It accepts two kinds of remote route:

- a `private_remote` route;
- a `brokered_remote` route with a current OpenRouter ZDR, OpenCode Go or OpenCode Console declaration, or with an OpenRouter ZDR witness observed through the API.

Such a route is used only after separate Betterleaks scans, a fresh residual scan with zero findings and a dispatch proof. A binary that pins no scan helper, or whose helper is missing or changed, refuses remote requests before it retrieves any credential. Use a build with its secret scan helper, as [remote model review](remote-model-review.md) describes. Remote routes work on Linux, macOS and Windows (see [platforms](platforms.md)).

Investigation and retained-memory requests stay local-only. Provider credentials come only from environment references that the protected policy names.

The repository and audit labels are scope labels that the host supplies. They do not authenticate the Git origin or the forge. Only the Git commits that you request are acquired, and the object-root path does not run Git and does not read the worktree.

## Chat Completions transport

In runtime policy v2, set the `implementation` of a protected connection to `openai_chat_completions` to select Chat Completions instead of `openai_responses`. The endpoint stays the API base, for example `http://127.0.0.1:8080/v1`. Changing the implementation changes the policy and adapter identities, so recompute the bindings and obtain any exact approvals that are required.

For that base, Chat sends `POST /v1/chat/completions` with the exact model selector, a trusted system message, the authorized user payload, `max_tokens` and `stream:false`. It uses the same bearer credential resolver, request bounds, locality checks, sanitization proofs and audit path as Responses. It sends no tools. Responses keeps its existing wire format and identity. Neither transport activates or approves a route.

The adapter accepts only bounded text or refusal output from one assistant choice. The returned model selector must match exactly. Tool calls, streaming and unsupported fields are rejected. The adapter does not infer model-specific `developer` roles or `max_completion_tokens` profiles. Test your exact server and model before you approve the route. A local connection needs a bearer credential unless its policy sets `credential_mode: "none"`.

For a local connection that you opt in explicitly, set `local_structured_output: true` as a JSON boolean in an explicitly versioned, protected v6 JSON policy. It works only with `openai_chat_completions`, a canonical numeric-loopback endpoint and no request profile. Both bearer and explicit local no-auth configurations are supported. Within v6, leaving the field out or setting it to false produces the same bound bytes and the same policy identity. An explicit v6 policy has its own versioned identity, and it does not migrate historical v1 or v2 policies. Versions 1 through 5 reject the field, even when it is false. Historical v1 and v2 templates without the option still bind to v2 with unchanged bytes and identities. V6 is generic only: it does not accept named request profiles or brokered, OpenCode Go or Console authorities.

When the option is on, Chat also sends `response_format` with `type: json_schema`, `strict: true`, the fixed name `open_trestle_review`, and the exact candidate, verifier or investigation schema that the host pins and validates from the authorized inner request. It does not accept a schema that the caller selects, and it does not change the temperature. Setting the option to true changes the policy, adapter and catalog identities, so bind the changed protected policy and obtain fresh exact approvals where they are required.

Dispatch refuses an approved reservation that is below the larger of two values, and it refuses before it retrieves a credential or makes an HTTP request. The first value is the normal byte-based request estimate of the host. The second is the inner payload bytes, plus the trusted system channel bytes, plus the serialized `response_format` object (including its field wrapper), plus 256 framing bytes.

Route planning counts the same `response_format` bytes, which are deterministic from the pinned schema, whenever the candidate routes of a planning step include a connection with this option. The generation and verification route authorizers, the local generation route plan and each investigation turn reserve the payload, the system channel and the schema framing, so `estimated_input_tokens` does not need to carry that margin. A step reserves once for all of its candidate routes, so a route without the option that is planned in the same step is reserved the same way. An investigation decides per role, from the pinned generation route and from the verification routes.

Such an authorizer binds `input_transport: local_structured_output` into its identity. Such an investigation binds the transports of its roles into the route owner and pipeline profile identities. This estimate is conservative byte accounting, not exact tokenization. Set a justified reservation that fits the approved context capacity of the route. No budget is increased after authorization.

The command does not assume that a server supports these schema keywords. Requests that the server does not support fail through the existing transport and response checks, without a simplified schema, retry or fallback. The checks on candidate coverage, evidence, usage, tool calls and authorization stay unchanged.

## Local Responses configuration bootstrap

The files in [`examples/local-model-review/`](../examples/local-model-review/) are illustrative bootstrap configurations. They name a loopback OpenAI Responses-style endpoint at `http://127.0.0.1:11434/v1`. At dispatch time the adapter sends `POST /v1/responses` with the model, one user `input_text` item, `max_output_tokens` and `store:false`. OpenAI-compatible local servers vary, so do not assume that every local server implements this protocol.

Before you use the example, edit `routes.json` for your actual local server, model, capabilities, content-logging posture, status, health, quota, pricing and evidence manifest. Where the repository cannot know the value, the example uses unknown or pending declarations. Replace the credential reference with the name of an environment variable that exists in your protected runtime environment. Do not put credentials in these JSON files. The `review_policy_identity` in the example is a placeholder label. Replace it with the stable identity that your review policy uses.

Compute the inventory identity:

```sh
trestle config inventory-identity \
  --route-inventory /protected/routes.json
```

The `decoded` result reports structural identities of the inventory and of its route records only. It says nothing about policy binding or live health. For a policy template, bind its identities with `trestle config bind` (see [named local runtimes](named-local-runtimes.md#use-the-existing-configuration-and-setup-caller)). The shipped example pair is already structurally bound. For a v1 policy, copy the reported `inventory_identity` into `runtime-policy.json` after you edit the inventory, and leave `preferred_route_record_identities` empty unless you intend to pin or prefer records that the same command reports.

After binding, validate the pair:

```sh
trestle config validate \
  --route-inventory /protected/routes.json \
  --runtime-policy /protected/runtime-policy.json
```

Identity and validation make no provider calls, so they do not check reachability or health. Run `trestle local-git model-review` with the same protected files only after validation. Pending routes stay pending, and you cannot run them merely because binding and validation succeeded.

## Retained advisory input (opt-in)

For an ordinary `local-only` review, add `--retained-memory-input /protected/operator-feedback.json`. Do not combine it with `--investigation-policy` or `--egress policy-approved`. Without the flag, the command keeps an empty memory index and does not look for memory files near the repository.

The input is a read-only advisory snapshot that the operator attests to. It contains only `human_feedback` records with `user_controlled` taint. It does not authenticate who wrote the feedback, and it is not permission to publish. The normal changed-path retrieval step selects the records, so loading a record does not guarantee that a model sees it. Generation and verification both receive the selected advice.

The input is an `open-trestle/retained-memory-input` schema version 1 envelope, not a free-form notes file. The authoring command builds it from a protected feedback file that you select. It does not run a review, resolve credentials or call providers.

The example below authors path and text preferences for an explicit head. To record decisions on verified findings, pass `--review-input` with a completed foreground result instead of the two revision flags. See [manual review feedback](local-feedback.md) for that form and for removing an input.

```text
trestle local-git retained-memory-input \
  --repository-authority example.test \
  --repository-namespace team \
  --repository-name repository \
  --revision-algorithm sha1 \
  --head-revision-digest FULL_LOWERCASE_HEAD_COMMIT_DIGEST \
  --tenant TENANT --repository REPOSITORY \
  --route-inventory /protected/routes.json \
  --runtime-policy /protected/policy.json \
  --egress local-only --timeout 5m --valid-for 1h \
  --feedback-input /protected/operator-feedback-source.json \
  --output /protected/operator-feedback.json --format json
```

Every flag except `--format` is required. The command accepts only `--egress local-only`. `--timeout` must be between one second and 15 minutes. `--valid-for` is in whole milliseconds, must exceed the timeout, and can be at most seven days.

The feedback file is a protected JSON file:

```json
[{"path":"src/file.go","text":"operator advisory text"}]
```

- The file is at most 64 KiB and holds 1 to 16 records.
- Each record has exactly the keys `path` and `text`. Unknown or duplicate keys and nested or non-string values are refused.
- A path must be a clean, printable, repository-relative path. It cannot be `.` or `..`, absolute or duplicated, and it cannot contain a backslash.
- The text must be non-empty after trimming. Hidden control characters and Unicode format characters are refused.

The command writes the retained-memory JSON only to `--output`. The parent directory must already exist, and the command refuses to create directories or to overwrite, truncate or replace a file. Stdout is a receipt with identities, counts and the expiry, and no advice text. If a failure happens after the command has created the output, a partial output file can remain.

The input is bound to the tenant, the repository, the requested head and the runtime policy. A file for a different head or policy is refused, not relabeled. Each record must be fresh when admitted and must expire after the full review timeout. Use mode `0600` and a private directory for sensitive advice.

A review that uses the input lists the limitations `retained_input_advisory_not_all_records_selected` and `retained_input_read_only`. If the command refuses the input, the result is `refused` with exit 4.

## Specialist profile (opt-in)

Add `--profile PROFILE_ID` to select one packaged specialist profile described in [agent profiles](agent-profiles.md). The accepted IDs are `backend`, `bug_hunter`, `drift_auditor`, `frontend`, `security_probe` and `style_conformance`. The command refuses `orchestrator` (it uses no model), `knowledge_graph` (it reports gaps only) and `test_author` (its test proposals do not fit the defect-claim contract).

An unknown or refused ID is a usage error (exit 2) that lists the valid IDs. Do not combine `--profile` with `--investigation-policy`. You can combine it with `--retained-memory-input`.

The profile's skill text goes into the system message of the candidate-generation request only. The verifier does not receive it. Route selection does not change: the same generation and verification routes apply, and verification still runs. The result adds a `specialist` object with `profile_id`, `profile_identity` and `catalog_identity`, and text output adds a `specialist profile:` line. The retained-memory feedback review and the [model-result evaluation](model-result-evaluation.md) import refuse a result that carries a `specialist` object.

## Specialist review set (opt-in)

Add `--specialists auto` (or `--specialists ID[,ID...]`) to run the general review plus several packaged specialist profiles and merge their verified findings. `--specialists none`, or no flag, is the ordinary single review.

A setup made by `trestle init` or `trestle setup bootstrap init` saves `--specialists auto`, unless you gave it `--specialists none`. So `trestle review` runs the set. `trestle review --specialists none` runs the single review once, and `--profile ID` replaces the saved set with one specialist. `--profile`, `--specialists` and `--investigation-policy` cannot be combined with one another. The IDs are the ones that `--profile` accepts.

### How the command selects specialists

With `auto`, the command derives the change features from the general review's recorded change model and semantic-impact profile, and the declared style from the root-level style configuration files of the base tree (see [declared style in local reviews](agent-profiles.md#declared-style-in-local-reviews)). No model is called for the selection. It keeps the activated profiles that may steer defect review, in descending priority, up to `--max-specialists`. It records the others in `selection.dropped` with a reason (`not_applicable`, `max_specialists` or a planner omission such as `tier_unassigned`), and the inactive ones in `selection.inactive`. If the general review did not reach analysis, `selection.status` is `features_unavailable` and no specialist runs.

With an explicit list, the specialists run in the order that you give. A list longer than `--max-specialists` is a usage error.

`--max-specialists N` (1 to 6, default 3) bounds how many specialists run. Every member is a full run. The `max_cost` of the runtime policy applies to its generation and to its verification separately, so the spending of the set can reach 2 × (1 + N) times that `max_cost`.

### Routes, concurrency and time

Every member uses the one generation and verification route pair of the runtime policy. The general review runs first. Each selected specialist then runs as its own session and run, with its own verification.

Specialists run concurrently, at most three at a time, when every route is remote and no limited API key could reach its limit during the wave. Otherwise they run one by one, and `bounds.sequential_reason` says why: `local_model_route`, `loopback_model_service`, `spending_limit_could_be_passed` or `at_most_one_specialist`.

The general review shares the `--timeout` window with configuration loading, and each specialist gets a fresh `--timeout` window, so model work is bounded by (1 + the number of waves) times `--timeout` (`bounds.max_model_wall_time_milliseconds`). No further wave starts once the invocation is canceled or a launched member's run did not succeed. Members that did not start appear with `launched: false` and a `not_launched_reason`. Nothing is retried.

### Review set output

The JSON output is `open-trestle/local-git-model-review-set` schema version 1. Its fields are:

- `selection`: the mode, the status, a features summary, the plan identities, and the selected, dropped and inactive profiles.
- `members`: one entry per member (`general`, then the profile IDs) with its status, CI disposition, run status, failure, identities, usage and cost, verification counts, limitations and [`token_usage`](#token-usage).
- `walkthrough`: the [walkthrough](#walkthrough) of the general member.
- `check_regressions`: the [check regressions](#check-regressions) of the change, once for the set.
- `model_written_checks`: the [model-written checks](#model-written-checks) of all members, once for the set.
- `findings`: the merged verified findings in [rank order](#rank). Each has its `rank`, the location of the representative and every contributor with its own finding identity, severity and range. Only members whose run succeeded contribute. Merging uses the [duplicate rule](#duplicates), so findings that a person would merge can stay apart (`deduplication_is_heuristic`).
- `summary`, `bounds`, `limitations` and `comprehensive_clearance: false`.
- `style_recommendations` and related fields: the [style advice](#style-recommendations) of the general review, once for the set.

The status and CI disposition of the set follow the members:

| Set | `status` | `ci_disposition` | Default exit |
|---|---|---|---|
| The general review completed and a specialist failed, with an introduced medium, high or critical merged finding | `findings` | `blocked` | 4 |
| The general review completed and a specialist failed, every merged finding low severity or pre-existing | `findings` | `inconclusive` | 3 |
| The general review completed and a specialist failed, with no merged finding | `incomplete` | `inconclusive` | 3 |
| Otherwise a member did not complete and an introduced merged finding is high or critical | most serious member status | `blocked` | 4 |
| Otherwise a member did not complete, no such finding | most serious member status | `failed` gives `error`, `refused` gives `blocked`, otherwise `inconclusive` | 1, 4 or 3 |
| Every member completed, an introduced medium, high or critical merged finding | `findings` | `blocked` | 4 |
| Every member completed, every merged finding low severity or [pre-existing](#pre-existing-findings) | `findings` | `inconclusive` | 3 |
| Every member completed with no candidates | `no_candidates` | `inconclusive` | 3 |
| Every member completed, otherwise | `incomplete` | `inconclusive` | 3 |

An incomplete set never demotes the verified high or critical finding of a completed member. A set with a failed specialist keeps `complete: false`, lists that member's failure, and `trestle review` names it on stderr (`Not finished: backend (failed: internal (task verification): model_output_invalid)`). A check regression makes any set `blocked` and keeps its status.

Text output starts with `status:` and `ci:`, then lists the reviewers that ran (`reviewers: general, bug_hunter, backend (3 of 3 ran)`). A member whose run did not succeed gets a `not finished:` line and a `hint:` line, and a member that was not started gets a `not run:` line. The walkthrough, the merged findings in rank order (each with a `confirmed by:` line and, when wordings were merged, an `also reported as:` line), the pre-existing findings, the hidden count, the token total, the style advice and `comprehensive clearance: false` follow. `--verbose` adds the selection trace, one `member:` line for each member and the `limitations:` list. `--format markdown` renders the set as a pull request summary. The SARIF output is one run whose results are the merged findings, each with a `trestleContributors` property.

The exit-code policies apply to the merged set:

- `default` maps `blocked` to 4, `inconclusive` to 3 and `error` to 1.
- `findings` exits 0 only when every member completed, no introduced merged finding is high or critical and there is no check regression.
- `strict` exits 0 only when every member completed with no candidates and there is no check regression.
- `always-zero` exits 0 when the general review completed, even if a specialist was refused or failed.

## Snapshot investigation (opt-in)

Add `--investigation-policy /protected/investigation.json` to let the generation model request bounded snapshot tools. Without this flag, the flow is a single generation. The runtime policy must pin one generation route and must permit a verifier. Investigation requests are not secret-scanned, so an investigation runs only with `--egress local-only`.

The investigation policy is a separate protected file of at most 4096 bytes. Its parser requires exact canonical JSON, so the field order, the spelling of integers and the whitespace all matter. Do not pretty-print the file and do not add a trailing newline. In an existing directory that meets the protection rules above, this example writes the canonical bytes:

```sh
printf '%s' '{"contract":"open-trestle/investigation-policy","max_cost_micro_usd":1000000,"max_files":64,"max_lines_per_read":64,"max_matches":16,"max_model_turns":5,"max_result_bytes":8192,"max_returned_bytes":65536,"max_scanned_bytes":1048576,"max_tool_calls":3,"profile":"snapshot-read-v1","schema_version":1,"timeout_milliseconds":300000}' > /protected/investigation.json
chmod 600 /protected/investigation.json
```

The example permits five model turns in total, including the final generation and the verification, and at most three tool calls. Its cost cap is 1,000,000 microUSD (USD 1) and must not exceed the cap of the protected runtime policy. Zero cost is valid for routes whose admitted cost is zero. Both the command timeout and the investigation timeout apply, and neither extends the other.

The tools list files, read inclusive line ranges and search for a literal string within the immutable snapshot. They do not run shell commands or regular expressions. The model's proposals carry opaque references that the host issued, and the controller checks each proposal against the source bindings and the remaining limits before it runs a tool. Each read or search charges the full file bytes that it loaded. Every string in the request, including tool results, is untrusted repository data (see [prompt-injection boundary](prompt-injection-boundary.md)).

If the effects on the model are unknown, if persistence fails or if the usage is uncertain, the run stops without an automatic replay. A fresh command is new paid work, not a recovery. The result includes every retained turn with its token counts, and `token_usage` sums the turns by role. An investigation run has no walkthrough and classifies no finding as pre-existing.

## Deletion-only changes

A diff can contain deletions without any changed head lines, for example a removed guard. The change model records such a file as `no_changed_head_lines`. The analysis compares the exact base and head files and gives the model the unchanged head lines on each side of every deletion point (as `changed_hunk` sources) and the removed lines themselves (as `removed_lines` sources, with base line numbers). Each deletion point is also recorded as a source omission, so a review of a deletion is never a full clearance. Removed text is bounded per deletion point and per file. A bound that is exceeded records the whole removed text of that point as an omission instead of truncating it.

A change that only removes files is reviewed from its removed text. If that text cannot be supplied, for example because the content is binary, the change is refused with `all_sources_omitted`. A file over the diff bound is an `analysis_resource_limit` omission, and the rest of the change is still reviewed.

### Base-side findings

A finding about code that still exists is located on head lines. A finding about the removed code itself is a base-side finding. Its `start_line` and `end_line` are base line numbers inside a `removed_lines` source, and it records the `head_line` beside which the lines were removed. Base and head line numbers are different coordinate spaces, so evidence from one side never covers a location on the other, and only cited `removed_lines` evidence can verify a base-side finding. Review sets never merge a base-side finding with a head finding.

| Output | Base-side finding |
|---|---|
| Text | `source: path removed base lines a-b (beside head line h)` |
| JSON | the diagnostic set, with `side` and `head_line` |
| SARIF | a result at the head line beside the deletion point, with `(removed base lines a-b)` in the message and `trestleSide`, `trestleBaseStartLine` and `trestleBaseEndLine` properties; with no head line, a run-level notification |
| GitHub | the review summary only, never an inline comment |
| Language server | a file-level diagnostic whose message starts `Base lines a-b (removed code):` |

## Ranked findings and the walkthrough

The command, not a model, decides which findings survive after verification. A completed direct run adds these members to the result:

- `rank`: every distinct verified finding in rank order, with the identities of the duplicates that were merged into it.
- `pre_existing`: the finding identities classified as [pre-existing](#pre-existing-findings).
- `unproven_origin`: the finding identities on unchanged lines whose origin could not be proven.
- `declaration_anchors`: the changed Go declaration that holds each anchored finding.
- `walkthrough`: the [walkthrough](#walkthrough).

Results without verified findings carry none of these except the walkthrough.

### Duplicates

One function decides duplicates wherever several verified findings can describe one defect: within one run, across the members of a [review set](#specialist-review-set-opt-in), and across repeated runs of the same change. Two findings merge when they have the same path and side, overlapping line ranges, compatible categories and nearly identical defect statements. Security findings merge only this way.

A second pass merges paraphrases of one defect at one place when both findings are inside the same changed declaration (or within a few lines when no declaration holds them), their categories are in the same non-security family and their statements share enough wording: half of their words with no differing identifier or number, or a fifth of their words when the findings come from different reviewers or runs, which describe one defect in different detail. The place alone does not merge findings: two different defects on one line stay two findings.

The representative of a merged finding is the most severe one, then the one that cites the most distinct evidence. A merged finding never hides another wording. Text and Markdown list the other titles on an `also reported as:` line, and the JSON of a set finding has a `merged[]` list with each contributor and the rule that merged it (`near_identical`, `same_declaration` or `same_lines`). A merge never relaxes a CI disposition or an exit code.

### Rank

Findings are ordered by final severity, then by verification confidence (how many origins confirmed the defect and the strongest verification independence), then by the strength of the evidence (distinct evidence items, then a narrower range), then by location, category and identity. Text and Markdown show hidden lower-severity findings as a count, for example `hidden: 1 lower-severity finding not shown; add --all to list every finding (the JSON output lists all)`.

### Pre-existing findings

A verified finding is on unchanged lines when it overlaps no changed line and no deletion window, and none of its cited evidence is a changed hunk or removed lines. That does not prove that the change did not cause the defect, since a changed function can break an unchanged caller. A finding on unchanged lines is therefore pre-existing only when all of these hold:

- It is in an unchanged Go file.
- Every changed file was analysed as Go, with no coverage gap.
- No changed declaration is a method, an `init` function or a package-level variable, and no blank package-level variable (`var _ = register()`) was added, removed or changed.
- The [repository index](repository-index.md), or the analysis of the review's own snapshots, covered the whole head, records value uses for the changed definitions' language, and found no dependent of a changed definition outside the changed definitions.

Any other finding on unchanged lines has an unproven origin. It is listed in `unproven_origin`, it shows `origin: unproven` in text and Markdown, and it blocks CI like an introduced finding. A finding on removed base lines, in an added file or in a file that the diff cannot represent is introduced. Only a direct run classifies findings.

Pre-existing findings get their own section in the text and Markdown output, and they never block CI.

### Advisory results

Only a medium, high or critical finding that the change introduced blocks CI. A completed review is advisory when its confirmed findings are all low severity, all pre-existing, or a mix of the two. An advisory review keeps `status` `findings` and has `ci_disposition` `inconclusive`, and its findings are still listed. SARIF keeps the level of each result. The exit-code policies keep their meaning:

| Policy | Advisory (every finding low severity or pre-existing) | An introduced medium finding, none higher | An introduced high or critical finding |
| --- | --- | --- | --- |
| `default` | 3 | 4 | 4 |
| `findings` | 0 | 0 | 4 |
| `strict` | 3 | 4 | 4 |
| `always-zero` | 0 | 0 | 0 |

A review set follows the same rule over its merged findings. A merged finding is pre-existing only when every contributor is.

### Check regressions

When the review ran the [repository checks](repository-checks.md), a test that passed on base and failed on head is a proven regression. The command reports each one itself, from the check outcomes and not from a model answer, so it is reported when the models found nothing and when the model review failed. A regression is not a verified finding and has no source line. The result lists it in `check_regressions`:

```json
"check_regressions": {"source": "repository_check", "count": 1, "tests": [{"check": "go test ./calc", "test": "example.com/calc.TestDivide"}]}
```

`tests` lists at most 16 and `not_listed` counts the rest. The check names and test IDs are repository text, cut and with control characters replaced, as in the walkthrough. A result with check regressions has `ci_disposition` `blocked` and keeps the `status` and findings of the model review. The exit code is 4 under `default`, `findings` and `strict`, and 0 under `always-zero`, the same as for a blocking finding. A review set reports them once for the set.

Text output puts them after the status lines:

```text
status: no_candidates
ci: blocked
run: succeeded
check regressions: 1 test passed on base and failed on head in the repository's own checks (source: repository check, not a model finding)
check regression: go test ./calc: example.com/calc.TestDivide
```

When the model review did not finish, the result keeps its failure lines and adds `check regressions: the model review did not finish; these come from the repository's own tests alone`. `trestle review` also prints the count on standard error.

### Model-written checks

With `--model-checks`, the result lists the tests the checker wrote that the sandbox kept (see [model-written checks](repository-checks.md#model-written-checks)):

```json
"model_written_checks": {"source": "model_written_check", "kept": [{"finding_identity": "…", "status": "regression", "framework": "go_test", "path": "calc/trestle_check_1_test.go", "content": "package calc\n…", "tests": ["example.com/calc.TestTrestleDivide"]}], "discarded": 1}
```

`finding_identity` is the diagnostic finding the test demonstrates; in a review set it is the member's finding, as `contributors` name it. `status` is `regression` or `fails_on_head`, `tests` are the test IDs that failed on head, and `discarded` counts every other check the checker wrote. The block never changes `status`, `ci_disposition` or the exit code. Text and Markdown name the finding and the test's path and point to the JSON for the text; the terminal view shows one line per kept test under its finding. SARIF does not carry it.

### Review context

The model sees, under one budget and in this order: the changed hunks and removed lines, the repository instruction files and project intent documents, the stated intent, and then context from the [repository index](repository-index.md):

1. the whole definition that encloses each changed hunk;
2. callers and other uses of the changed definitions;
3. tests that reference the changed definitions;
4. a ranked repository map: signatures of the definitions near the changed files that a reference-graph ranking places highest.

The byte budget comes from the smallest context window of the configured routes. An item that does not fit is left out with its reason. A review with a checkout or an objects root builds or refreshes the index of its base and head before it starts, under its own deadline of two minutes or a quarter of the review timeout, whichever is shorter. Without a usable index, the plan comes from the review's own snapshots, whose Go files are analysed in process, and the walkthrough says so.

The index proposes line ranges only. The text comes from the review's own verified head snapshot and is secret-scanned with the rest of the request before any remote egress. When the review ran the repository's own tests and linters in the sandbox (see [repository checks](repository-checks.md)), the generation context also carries their outcomes as `check_runs`, and the verifier receives the same object.

Non-Go hunks that are valid UTF-8 are sent as changed hunks, and semantic analysis is recorded as unsupported for them. Lock files, vendored files, minified files and binary files are omitted with a named reason. The command also adds the root `AGENTS.md`, `CLAUDE.md`, `.github/copilot-instructions.md` and `.trestle/review-instructions.md` of the base tree as bounded advisory context, only when the head holds a byte-identical copy. A change to one of these files is reviewed as a changed hunk instead. The same rule adds up to three [project intent documents](#project-intent-documents). These files are repository data and cannot override the review instructions (see the [prompt-injection boundary](prompt-injection-boundary.md)). The exact rules are in [context assembly](runtime.md#context-assembly).

### Walkthrough

The walkthrough is built from the artifacts that the run recorded. It has four parts:

1. What was verified (`walkthrough.verified`): the secret scan (requests, bytes and matches), the static checks, style detection, the semantic-impact summary, the context the review saw, the repository check outcomes, [pattern hygiene](#pattern-hygiene) and the verifier counts and independence.
2. A summary of the change for each file (`walkthrough.files`): the change kind, the added and removed line counts and, for Go files, the added, removed and changed declarations.
3. Missing verification (`walkthrough.missing_verification`): the added or changed functions, outside test files, that no test file references. It is informational and does not change the status, the CI disposition or the exit code. Dependents are matched by name.
4. The stated intent (`walkthrough.stated_intent`): the commit subjects of the range, labelled `author_stated_unverified`. Text output quotes each subject and Markdown puts each in a code span.

The JSON lists a bounded number of files, declarations and notes and counts the rest. If the result would exceed its output bound, the command leaves the walkthrough out and records `walkthrough_omitted_output_limit`. The walkthrough of a review set describes the whole set, and the secret scan and verifier lines total the completed members. This is the text output of the offline fixture that the tests use:

```text
status: findings
ci: blocked
run: succeeded
walkthrough:
verified: secret scan: 2 model requests scanned before sending (292 bytes, 0 secret matches)
verified: static check static_debug_output: passed (1 file checked, 0 matches)
verified: pattern hygiene: 0 added suppressions, 0 added workaround comments, 0 spreading anti-patterns
verified: style detection: ran (1 recommendation, 0 withheld)
verified: semantic impact: 1 changed declaration, 0 public API changes, 1 reference (0 from tests), 0 gaps
verified: independent verifier (distinct_provider): 1 of 1 candidate confirmed, 0 rejected, 0 inconclusive
file: a.go modified +1 -1; changed function Changed
missing verification: no test file references the changed function Changed (a.go)
confirmed findings (ranked): 1
finding: error Zero-valued caller now panics
rank: 1
source: a.go:2-2
message: Consume passes zero to Changed after removal of the division guard.
evidence: 8d0ff8ec..., f84bfca8...
category: correctness
fix: Restore the zero guard before dividing.
coverage: candidates=1 verified=1 rejected=0 inconclusive=0
source coverage: analyzed=2 selected=2 omitted=0
tokens: input=200 output=200 cached_input=0 over 2 route attempts
style: no declared Go style for 1 changed file; consider gofmt and Effective Go, and commit its configuration
comprehensive clearance: false
```

If the policy of a run did not require zero data retention on an OpenRouter route, the output shows that on a `zero data retention:` line.

### Commit messages as stated intent

A direct review reads the commit messages of its range, `base..head`, from the same verified Git objects that source acquisition read. It runs no `git` command for them. If the range could not be separated completely, for example because a parent is missing from a shallow checkout, the range is marked `range_incomplete`.

The messages enter the generation context as its `stated_intent` object, oldest first, labelled `author_stated_unverified`, within fixed bounds on commits and bytes. A message that is not UTF-8 text keeps no text. Each message carries `risk_flags` from the same content rules as every source, and both models receive it after secret scanning. See the [prompt-injection boundary](prompt-injection-boundary.md#stated-intent).

The finder may compare the change with the stated intent and propose a mismatch as an ordinary candidate (category `correctness`). The verifier checks such a claim against both the intent and the evidence. Under `--specialists auto`, the `drift_auditor` profile activates on a change with commits or with a [project intent document](#project-intent-documents). An investigation run carries no stated intent.

### Project intent documents

A project intent document states what the project is for: its goals, non-goals and constraints. The review reads the first three of these files that exist in the base tree, in this order:

1. `.trestle/scope.md`
2. `.specify/memory/constitution.md`
3. `.kiro/steering/product.md`
4. `openspec/project.md`
5. `agent-os/product/mission.md`
6. `.taskmaster/docs/prd.txt`
7. `memory-bank/projectbrief.md`
8. `PRD.md`
9. `docs/PRD.md`
10. `docs/prd.md`

These are common locations for project intent documents. To give a repository one without another tool, write its goals and non-goals in `.trestle/scope.md`.

A document is used only when the head holds an identical copy, like the instruction files; an edit to it is reviewed as a changed hunk. It reaches both models as a `repository_context` source at its own path, 8 KiB per document and 16 KiB across the three, a budget separate from the instruction files. The finder may compare the change with it as with the commit messages: work the document does not ask for, work that contradicts a stated non-goal, and code the change leaves behind. A candidate quotes the line it relies on and is located on the changed code. The document's text is data, never instructions. Under `--specialists auto`, a document that was used activates `drift_auditor`; the change features record its path, not its text. A document that was not supplied is counted in `instruction_context_omitted` with the instruction files.

### Pattern hygiene

Every generation context records deterministic evidence about pattern hygiene, computed without a model. For each changed file in a supported language, it counts a small set of anti-patterns in the base and in the head of the file's directory, and reports those whose count rose. On the changed lines it also finds lint and type suppressions, comments that justify a workaround, TODO markers without an issue reference and, in agent instruction and skill files, added absolute rules such as `NEVER` or `ALWAYS`. A suppression beside a workaround comment becomes a `root_cause_not_fixed` note: the change silences a check and explains why, instead of fixing the cause.

The matching is lexical and prefers a missed match to a false one. Vendored trees are skipped, and a directory over the comparison bounds is not compared and is counted in `unread_directories`. The object carries no repository text and no path. The finder treats it as attention markers, not findings, and the verifier does not receive it. A `root_cause_not_fixed` item is a deterministic finding of severity `low`. It does not change the status, the CI disposition or the exit code.

| Rule | Language | Matches |
|---|---|---|
| `go.time_sleep` | Go | `time.Sleep(` outside `_test.go` |
| `go.library_panic` | Go | `panic(` in a non-main, non-test package |
| `go.library_print` | Go | `fmt.Print`, `fmt.Println`, `fmt.Printf` in a non-main, non-test package |
| `go.nolint_without_reason` | Go | `//nolint` without a trailing `// reason` |
| `js.use_effect` | JS, TS | `useEffect(` in `.jsx` and `.tsx` files |
| `js.set_timeout` | JS, TS | `setTimeout(` outside test files |
| `js.request_animation_frame` | JS, TS | `requestAnimationFrame(` outside test files |
| `js.eslint_disable` | JS, TS | a comment starting `eslint-disable` |
| `js.ts_ignore` | JS, TS | a `@ts-ignore` comment |
| `py.mutable_default` | Python | a one-line `def` with a `[]`, `{}`, `list()`, `dict()` or `set()` default |
| `py.bare_except` | Python | `except:` |
| `py.type_ignore` | Python | a `# type: ignore` comment |
| `py.noqa_without_code` | Python | `# noqa` without `: CODE` |

## Results and limits

A run that did not succeed adds two text lines after `run:`:

```text
status: refused
ci: blocked
run: failed
failure: policy (task context)
hint: usually no changed source could be supplied to the model (every source was omitted, unsupported, or not authorized); see the context task's source omissions
```

`failure:` gives the failure class of the run, the first plan task that failed and, when one was observed, a detail. `hint:` is a fixed one-line explanation for each class (`policy`, `resource_limit`, `transient`, `invalid_input`, `canceled`, `dependency`, `internal`). It describes what the class usually means and is not a diagnosis. A run that succeeded prints neither line. See [failure details](failure-details.md) for every detail.

### Route context too small

Every request reserves a byte-based upper bound on its input tokens, plus the output allowance. A route whose declared `max_context_tokens` is smaller is not eligible, so a small model server does not truncate the prompt. When that leaves no eligible route, the run is refused with the failure `policy`. The JSON result then adds `"failure_detail": "route_context_insufficient"` and a `context_shortfall` object with `required_tokens`, `estimated_input_tokens`, `max_output_tokens` and `declared_context_tokens`. Text output reads as follows, with the counts in place of N, I, O and D:

```text
failure: policy (task context): route_context_insufficient
hint: the review needs up to N tokens (a byte-based upper bound: I input plus O output) but the route declares max_context_tokens D; raise max_context_tokens on the route and the model server's context length to at least N (docs/named-local-runtimes.md#context-length)
```

Raise the declared context of the route and the context length of the server together. See [named local runtimes](named-local-runtimes.md#context-length).

### Exhausted model output

When a response stops at the output token limit without a complete answer, the failure stays `internal` and the JSON result adds `"failure_detail": "model_output_exhausted"`. Reasoning models do this when they spend the output allowance on their reasoning. The failed attempt keeps the usage that the provider reported. Text output reads:

```text
failure: internal (task verification): model_output_exhausted
hint: the model used its whole output allowance, usually on reasoning, before finishing its answer; choose a non-reasoning model for this role, or set up again with a larger output allowance (trestle init --directory NEW_FOLDER --max-output-tokens N)
```

The output allowance and the request deadline are described in [remote model review](remote-model-review.md#output-allowance-and-request-deadline).

### Provider refusals

When a provider answers a model request with an HTTP refusal, the command classifies it by the status alone and discards the error body without interpreting it. A `policy` refusal gives exit 4. A `transient` failure gives exit 1, and a rate limit is retried first. The status table, the retry rules and the `failure_detail` values are in [provider failures](remote-model-review.md#provider-failures).

### Spending limits

An API key that a remote route uses can have a [spending limit](spending-limits.md). When the spend recorded in the current period is at or over that limit, the command refuses the review before it reads any credential or sends any request. The result has `status` `refused`, `ci_disposition` `blocked`, `run_status` `not_opened`, `failure_detail` `spending_limit_reached`, and exit code 4. Text output reads:

```text
failure: policy: spending_limit_reached
hint: the spend recorded for an API key this review uses has reached its spending limit for the current period, so the review was not started and nothing was sent: run trestle usage to see it, then raise or clear the limit (trestle usage set, trestle usage clear) or wait for the next period; the figures are Open Trestle's upper-bound estimate at the highest pinned price, not a bill, and the limit is best effort, so your provider's own limit is the guarantee
```

A review whose worst case could pass a limit runs with a warning. After a run that sent at least one request, the command appends one entry to the local usage ledger, and a crossed alert percentage prints one line. These lines go to standard error. A review set warns once before its first member, checks each member before it starts, and stops when a member is refused at the limit. Results do not carry spending figures.

### Token usage

A result that opened a run reports `token_usage`: the input, output and cached-input tokens that the provider reported, summed over every route attempt that the run claimed, with `generation` and `verification` objects of the same shape.

```json
"token_usage":{"known":true,"route_attempts":2,"input_tokens":200,"output_tokens":200,"cached_input_tokens":0,"generation":{"known":true,"route_attempts":1,"input_tokens":100,"output_tokens":100,"cached_input_tokens":0},"verification":{"known":true,"route_attempts":1,"input_tokens":100,"output_tokens":100,"cached_input_tokens":0}}
```

- `route_attempts` is the number of claimed attempts that were summed. A direct review claims one generation and one verification attempt, plus one for each retry after a rate limit or after an answer that was not usable (`model_answer_retried` in `limitations`). A run with `--investigation-policy` claims one for each turn.
- `input_tokens` includes `cached_input_tokens`. The counts are the provider's report, not a tokenization by Open Trestle.
- `known` is true only when every summed attempt reported usage. Otherwise it is false and the counts are absent, never zero, for example `{"known":false,"route_attempts":1}`. A rate limit records known zero usage. Any other HTTP error, a transport failure or an invalid reply counts as unknown.
- `usage_known` and `actual_cost_micro_usd` cover the same claimed attempts. The cost is reported only when every attempt has a known settlement.

Text output adds one line:

```text
tokens: input=200 output=200 cached_input=0 over 2 route attempts
tokens: unknown over 2 route attempts (not every attempt reported usage)
```

A result that never opened a run reports no token use. SARIF does not carry token usage. A member of a review set carries the `token_usage` of its own result.

### Style recommendations

When a changed language has a style detector but the base tree of the review declares no style that governs it, the result recommends a standard style. The command reads the base tree as it does for [`--specialists auto`](agent-profiles.md#declared-style-in-local-reviews): root-level style configuration files only, not the head. EditorConfig alone does not count. The recommendations come from a fixed table, not from a model:

| Changed language | Recommendation |
| --- | --- |
| Go | gofmt and Effective Go |
| Python | PEP 8, enforced with Ruff or Black |
| JavaScript, TypeScript, Vue, Svelte | Prettier with ESLint |
| CSS, HTML, JSON, YAML, Markdown | Prettier |
| C, C++ | Google C++ Style through clang-format (`BasedOnStyle: Google`) |
| Rust | rustfmt |
| Ruby | RuboCop and the community Ruby Style Guide |

Other languages get no recommendation. Vendored and generated files, removed files and the dependency lock files that package managers generate are not counted. Text output adds one line for each language, for example:

```text
style: no declared Python style for 3 changed files; consider PEP 8, enforced with Ruff or Black, and commit its configuration
```

JSON adds `style_recommendations`, with `language`, `changed_files` and `recommendation` for each language. A recognized base style configuration file can be unreadable (over 64 KiB, not valid UTF-8, beyond the first 256, or past the 1 MiB change-features bound). The languages that file could govern are then listed in `style_withheld` and not recommended, and `style_configuration_unread` counts the unread files. If the recorded change or base style configuration cannot be read back, JSON adds `style_advice_unavailable: true`.

A recommendation is advice only. It is not a finding and does not change `status`, `ci_disposition`, the exit code or `comprehensive_clearance`. SARIF carries it at run level only.

Other optional counts report advisory accounting of the repository context without changing `status` or `ci_disposition`: `instruction_context_omitted` (base-tree instruction files and project intent documents that were not supplied), `repository_context_anchor_candidates_omitted` (model candidates dropped because they were located in an instruction file or intent document and not in reviewed code), and `agent_configuration_sources` and `instruction_like_sources` (generation context sources flagged as repository AI material or instruction-like text). All are absent when zero.
