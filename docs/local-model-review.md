# Local model review

`trestle local-git model-review` asks language models to review the change between two commits that you name. It is the model-backed review command. Developers and CI jobs use it, and `trestle review` runs it for you after `trestle init`. This page explains how a review works, what the output looks like and what the exit codes mean, and then covers each option and each boundary in detail.

The command is an explicit request for model calls. It does not change `local-git review`. It cannot publish a forge review or create a required check.

For private source, prefer a local model or a provider whose retention terms you have checked (see [why](rationale.md#local-models-and-zero-data-retention-providers-are-recommended)). `--egress policy-approved` can send sanitized, scanned selected source to an approved remote route (see Authority and egress below and [remote model review](remote-model-review.md)).

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

Write each flag and its value as two separate words. The command refuses repeated flags, flags in `--flag=value` form, missing values, unknown flags and equal revisions. It supports full SHA-1 and SHA-256 commit digests. The timeout must be between one second and 15 minutes. JSON is the default output format, and `--format text` selects a short summary for people.

`--object-store` is optional. It accepts only `loose-only` and `loose-and-pack-index-v1`. When you leave it out, the command reads loose objects only. The command has no flags to publish, resume, keep state, or name an existing run.

## How a review works

A review takes four steps, and the command runs them in order:

1. You select two distinct commits, a base and a head. The command reads the objects of those two commits and works out what changed. It reviews committed work only, not the index or the working tree.
2. Open Trestle selects the changed source that it may send, sanitizes it, and scans it for secrets. It sends the result to the generation route that your route inventory and runtime policy name. That model proposes candidate findings.
3. A second model reviews each candidate. The runtime policy must name this verification route separately from the generation route, and a different model family is recommended (see [why](rationale.md#the-checker-should-come-from-a-different-model-family)). Only a candidate that the verifier confirms becomes a verified finding.
4. The command prints one result and exits with a code that summarizes it.

Your protected route inventory and runtime policy decide which models may be called and where the source may go. `--egress local-only` refuses any route that is not local. See [Authority and egress](#authority-and-egress).

### What the output tells you

The result is a single document on standard output. `--format` selects one of four formats:

- `json` is the default. It is one terminal receipt, which a script can read.
- `text` is a short summary for people.
- `sarif` is a SARIF 2.1.0 document that code-scanning tools can read (see [SARIF output](#sarif-output)).
- `markdown` is a pull request summary comment (see [Markdown output](#markdown-output)).

Read the `status`, `ci_disposition`, `run_status`, `limitations` and `diagnostics` fields together. They mean different things:

- A run that succeeded means that the pipeline finished. It does not mean that the repository is clear.
- Verified findings give `ci_disposition: blocked`. The exception is an [advisory](#advisory-results) run whose confirmed findings are all low severity or pre-existing, which gives `inconclusive`.
- No candidates, incomplete evidence, and an abstention all give `inconclusive`.
- Refusal and failure are separate terminal statuses.
- An empty finding list is not an approval, and the result carries `comprehensive_clearance: false`.

[Results and limits](#results-and-limits) describes the rest of the output.

### Exit codes

By default the command never exits with 0. The exit code summarizes the result:

| Exit | Meaning |
| --- | --- |
| 4 | There are verified findings that block (an introduced medium, high or critical finding), or the run was refused for policy or resource reasons. |
| 3 | There are only [advisory](#advisory-results) findings, or there are no candidates, the evidence is incomplete, the source is unsupported, or the run was canceled. |
| 2 | The command was used incorrectly. |
| 1 | The result was internal or malformed, the command could not drain or close safely, or the output failed. |

If a CI step must pass when a completed review has no blocking findings, use the opt-in `--exit-code-policy` (see [Exit-code policy](#exit-code-policy)). Exit 0 is then a decision about your pipeline, not a statement that the change is clear.

## Reviewing the latest change with `trestle review`

After `trestle init` (see [getting started](getting-started.md)), `trestle review` runs this same command for you. It finds the saved setup and takes the route inventory, runtime policy, scope labels, egress and timeout from the saved review command. It replaces only the two commits, which it picks again on every run:

- the head is `HEAD`;
- the base is the newest commit that `HEAD` shares with the default branch.

`--base REF` and `--head REF` pick the commits exactly. Only committed work is reviewed. A new setup saves `--format text` and, unless you set it up with `--specialists none`, `--specialists auto`.

The result goes to standard output as one document, in the saved format or in the one you pass with `--format text|json|sarif|markdown`. Every other line goes to standard error. That includes the commits, where the source is sent, and the spending and scanning messages. `--timeout`, `--profile`, `--specialists`, `--max-specialists`, `--exit-code-policy`, `--all` and `--verbose` pass through, and the exit code follows this page's [exit table](#exit-codes).

The command sends nothing and exits with `3` in these cases:

- the repository has no setup;
- there is no committed change to review;
- the API key of the setup is missing (set it with `trestle keys set NAME`).

Outside a Git checkout, or with flags that the saved setup cannot combine, the command exits with `2`. `trestle review PATH` reviews a local fixture file instead. The rest of this page describes the underlying command and its output, which `trestle review` shares.

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

`--base` and `--head` are both required. Each accepts `HEAD`, an exact full lowercase commit digest, or a full `refs/heads/...` or `refs/tags/...` name. The command has no default base, and it does not infer a merge base. It does not accept short branch names or revision expressions, and it does not review the index or a dirty worktree. An annotated tag must resolve to a commit. If both selections resolve to the same commit, the command refuses. Do not combine checkout selection with `--objects-root`, the revision flags or `--object-store`.

This form needs an installed Git that supports `--no-lazy-fetch`. Git resolves the shared object directory (including linked worktrees), the object format and the selected commit IDs. The existing immutable reader then authenticates those exact objects with `loose-and-pack-index-v1`, and its restrictions on packs, alternates, missing objects, symlinks and gitlinks still apply. A ref that changes after the selection does not change the commits that were already acquired. If objects are removed while the review runs, the review can be incomplete. The command does not take an atomic snapshot of the checkout, and it does not authenticate where the checkout came from.

Preparing the source runs no shell, fetch, checkout, filter, textconv, hook, credential helper or maintenance command. It clears inherited Git overrides and the global and system configuration. It disables lazy fetching, replacements and transports, and it limits the size of metadata output and the execution time. The repository configuration and its includes are still read as ordinary metadata by the same user, so do not point the command at an untrusted checkout if those reads are not acceptable. This form runs in the foreground only, and it grants no publication authority.

## Headless CI use

`trestle ci --format=json|sarif PATH` reviews a local fixture file. It does not select an arbitrary checkout, and it does not call models. For a model-backed review of a checkout without a terminal, use the foreground command below. It needs no terminal prompt and creates no durable run.

Before you run the command, prepare both commits in the checkout. Set `BASE_COMMIT` and `HEAD_COMMIT` to two distinct full lowercase commit digests. The command does not infer a merge base and does not fetch. Set the tenant and repository IDs to the scope that your operator approved. Provision the protected route inventory, the runtime policy and any required credential references separately. They must bind the approved generation and verification pair. Use the configuration steps below instead of building identities by hand.

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

Replace the example paths and identity labels with approved values. The repository identity fields label the selected repository. They do not authenticate an origin, and they do not trigger a network request. Do not combine checkout mode with the object-root, revision-digest or object-store flags. The CI runner needs the supported Git version and permission to read the selected objects.

The command runs no repository hooks, credential helpers or fetch, and it publishes nothing. This example uses `local-only`, which refuses remote routes.

Capture stdout as one terminal JSON receipt, and keep the process exit status. The receipt uses `open-trestle/local-git-model-review-result`. Its schema version is 6 for every run that opened, which adds [token usage](#token-usage) to the fields of versions 1 to 5. A request that never opened a run gets version 1 (see [Results and limits](#results-and-limits)), except a [spending-limit refusal](#spending-limits), which is version 6.

Inspect `status`, `ci_disposition`, `run_status`, `limitations` and `diagnostics` together (see [What the output tells you](#what-the-output-tells-you)). By default there is no exit-0 branch, as the [exit table](#exit-codes) shows. The opt-in [exit-code policy](#exit-code-policy) can map a completed review to 0 for CI.

`--format` selects `json` (the default), `text`, `sarif` or `markdown`. Markdown is a pull request summary comment (see [ranked findings and the walkthrough](#ranked-findings-and-the-walkthrough)). Text and Markdown list the confirmed high, critical and medium findings and count the rest. When there are none of those, they list up to 10 lower-severity findings. `--all` lists every finding. `--verbose` adds the list of limitations to the text output and, for a review set, the selection trace and the details of each member. It does not change JSON, SARIF or Markdown.

For a run that the daemon accepted separately, `runs status --format json|sarif` retrieves the result. The headless example above is ephemeral and cannot resume an older run.

### SARIF output

`--format sarif` writes one newline-terminated SARIF 2.1.0 document instead of the JSON receipt. It is built from the same sealed result and the same SARIF types as the other Open Trestle exports, and it carries only verified findings:

| SARIF | Source |
| --- | --- |
| `ruleId` | `open-trestle/<category>` from the generator's advisory category, or `open-trestle/uncategorized` |
| `level` | verified severity: high and critical are `error`, medium is `warning`, low is `note` |
| `message.text` | `title: claim`, the text the verifier checked |
| `locations[0].physicalLocation` | repository-relative path and start/end line |
| `fingerprints` | `openTrestleVerifiedFindingId/v1`, the run-specific finding identity |
| `partialFingerprints` | `openTrestleFindingFingerprint/v1` (bound to the reviewed snapshot) and `openTrestleContentHash/v1` (path, category, title and claim only) |
| `properties` | `trestleCategory`, `trestleSeverity` (`error`, `warning` or `information`; the diagnostic severity, so high and critical are not distinguished), `trestleVerificationIndependence`, evidence IDs, `trestleRank` (the finding's rank), `trestlePreExisting` (present and true for a [pre-existing](#pre-existing-findings) finding) and `trestleUnprovenOrigin` (present and true for a finding of [unproven origin](#pre-existing-findings)) |
| `properties.trestleFixGuidance` | the generator's fix text, with `trestleFixAuthority: unverified_model_guidance` |
| run `properties` | `trestleModelReviewStatus`, `trestleCiDisposition`, `trestleRunStatus`, `trestleFailure`, sorted `trestleLimitations`, candidate/verified/rejected/inconclusive counts, source coverage and omissions, and `trestleComprehensiveClearance: false` |
| run `properties.trestleStyleAdvice` | the [style advice](#style-recommendations): `recommendations` (`language`, `changedFiles`, `recommendation`), `withheld`, `configurationUnread` and `unavailable`, absent when there is none; each advice line is also a `note` in `invocations[0].toolExecutionNotifications`, never a result |

Fix guidance is a result property, not a SARIF `fixes[]` entry. The SARIF schema requires every fix to contain machine-applicable `artifactChanges`, and this text is prose that nothing applies. The verifier checked the claim, not the category or the fix.

`openTrestleContentHash/v1` stays equal across pushes when the same path, category, title and claim recur, which lets code scanning match an alert between runs. The model may word the same problem differently, so the matching is best effort. Results, rules, limitations and omissions are sorted, so identical input yields identical bytes.

A run that was refused, could not read the change, was canceled or failed is still valid SARIF. It has zero `results`, `invocations[0].executionSuccessful: false` and one `error` notification that states the status and the failure. A run that completed with no candidates or with coverage gaps has an empty result list, `executionSuccessful: true` and a `note` or `warning` notification.

### Exit-code policy

By default the exit status follows the table in [Results and limits](#results-and-limits) and is never 0. A CI step that must pass on a completed review without blocking findings can opt in with `--exit-code-policy`. The flag changes only the process exit status. The output, including `status`, `ci_disposition` and `comprehensive_clearance: false`, is identical under every policy.

| Policy | Exit 0 when | Otherwise |
| --- | --- | --- |
| `default` (the behavior when the flag is absent) | never | 4, 3, 2 or 1 as in the table |
| `findings` | the run succeeded and no verified finding has high or critical severity (including no candidates, medium or low findings only, and a completed run with coverage gaps) | the default code: 4 for a verified high or critical finding or a policy/resource refusal, 3 when the change could not be read or finished or was canceled, 1 for an internal failure |
| `strict` | the run succeeded with no candidates at all, so no finding of any severity and no verification gap | the default code, so any verified finding fails the step: 4 when it blocks, 3 when the run is [advisory](#advisory-results), and any coverage gap is 3 |
| `always-zero` | a valid result was written, including a refused or failed run | 1 only if the result could not be written; 2 for invalid usage |

The results are listed in [rank order](#rank), with a merged duplicate after the finding that it was merged into.

A run with the status `findings` whose diagnostics cannot be read back is treated as blocking. `always-zero` is for advisory use only. Pair it with SARIF or the JSON status, because a green step then says nothing about whether the review ran. Invalid usage (2) and an output write failure (1) keep their codes.

### Shallow and pull-request checkouts

Checkout mode reads only the objects of the two named commits. It does not fetch, and it does not deepen a shallow clone. When the command cannot resolve the selected base or head, the run is `incomplete`, no model is called, and stderr says why.

In a shallow checkout, the message names the missing revision and the commands to run. Either run `git fetch --no-tags --depth=N origin <sha>`, where N must reach the base, or, in GitHub Actions, use `actions/checkout` with `fetch-depth: 0`. A shallow clone that holds both commits reviews normally.

A partial clone (`--filter=...`) can resolve the commits but still lack file contents. The command does not fetch those on demand, so the run is `incomplete`, and stderr suggests checking out again without a filter.

For a pull request, use `github.event.pull_request.base.sha` and `head.sha` as the pinned commits. See [GitHub pull-request review](github-pr-review.md) and the [example workflow](../examples/github-actions/README.md).

## Runtime policy route-pair boundary

In runtime policy v1, a single entry in `preferred_route_record_identities` is a ranking hint. It does not grant a specific verifier.

Runtime policy v2 adds the required field `verification_route_record_identity`. It must name one record in the bound inventory, and that record must differ from the generation pin. A route-pair resolver for local generation, which is still preliminary, uses only that explicit grant. It requires local-only zones with logging disabled, and it checks both routes for eligibility and for the configured independence. Preferred-route hints cannot replace the grant or redirect the pair.

A v2 document that passes the schema does not authorize a model request, and neither does a preflight check of the pair. Before dispatch, generation and verification each need a separate eligibility check for their actual sanitized request and the exact record pins, with no fallback. The foreground `local-git model-review` command behaves as it does under v1. The opt-in durable full-review daemon resolves the explicit v2 pair before it builds its generation worker, but its handlers still need separate authorization for each sanitized request.

## Object store profile

The default profile is `loose-only`. It reads only loose Git commit, tree and blob objects under the `objects` root that you supply.

`--object-store loose-and-pack-index-v1` is an explicit opt-in for a narrow subset of packed Git storage. It still uses loose objects when they exist. It reads `.pack` files and version-2 `.idx` files from `objects/pack` only when a loose object is truly absent. The `--revision-algorithm` you select binds the packed reader to SHA-1 or SHA-256 object names for that session.

The packed subset has deliberate limits:

- The reader acquires commit, tree and blob objects. A pack may contain unused tag objects, but the reader does not acquire tags. It refuses a selected tag, and a delta chain that resolves to a tag.
- The bases of OFS_DELTA and REF_DELTA objects must be in the same pack. The reader refuses thin packs with external bases.
- The reader refuses duplicate object IDs across the packs it accepts. Repacking during a run can make the source invalid or incomplete.
- The reader does not support multi-pack-index files, promisor objects or alternates. Refs and linked worktrees need the checkout selection described above. Object acquisition never falls back to a Git subprocess.
- The command validates the selected bytes and the structure of the pack and index. It does not take an atomic snapshot of the repository, and it grants no extra filesystem permissions.

Provider routes and credentials still come only from the inventory and policy that you supply. The object-store option adds no provider configuration.

## Authority and egress

You supply both the route-inventory and the runtime-policy JSON files. The policy must bind the identity of the decoded inventory. Both files must pass the owner, ancestor, mode, symlink and replacement checks of `internal/fileauthority`. The loader checks that the content is bounded and stable, and it checks the pair again after decoding. The inventory may be at most 8 MiB, and the policy at most 1 MiB. On platforms where ownership checks are unsupported, loading fails. There is no policy fallback from the environment.

`local-only` requires local routes and canonical numeric loopback endpoints. The local transport disables proxies and confines dialing.

`policy-approved` still applies the protected inventory and policy. The direct review uses the standard runtime handlers for generation and verification. These handlers accept two kinds of remote route:

- a `private_remote` route;
- a `brokered_remote` route with a current OpenRouter ZDR, OpenCode Go or OpenCode Console declaration, or with an OpenRouter ZDR witness observed through the API (which has no time window).

They accept such a route only after separate Betterleaks scans, a fresh residual scan with zero findings, a reload of the artifact, and a dispatch proof that the handler seals. A binary that pins no scan helper, or whose helper is missing or changed, therefore refuses remote requests before it retrieves any credential. Use a build with its secret scan helper as described in [remote model review](remote-model-review.md), whose bootstrap writes the protected remote configuration. Remote routes work on Linux, macOS and Windows (see [platforms](platforms.md)).

Investigation and retained-memory requests remain local-only. Route approval, data classification, logging restrictions, provider independence, capacity and per-request cost budgets stay in force. Provider credentials come only from environment references that the protected policy names explicitly, through the existing credential resolver.

The repository and audit labels are scope labels that the host supplies. They do not authenticate the Git origin or the forge, and they grant no permission to publish. The opened source root is bound to its session, and only the Git commits that you request are acquired. The object-root path does not run Git and does not read the worktree. Checkout selection runs only the metadata commands described above.

Without the packed opt-in, repositories that have only packs are unsupported. With the opt-in, only the pack and index subset above is supported. Also unsupported are alternates, worktree pointer files given as object roots, symlink and gitlink source entries, unavailable objects, and other Git layouts.

## Chat Completions transport

In runtime policy v2, set the `implementation` of a protected connection to `openai_chat_completions` to select Chat Completions instead of `openai_responses`. The endpoint stays the API base, for example `http://127.0.0.1:8080/v1`. Changing the implementation changes the policy and adapter identities, so recompute the bindings and obtain any exact approvals that are required.

For that base, Chat sends `POST /v1/chat/completions` with the exact model selector, a trusted system message, the authorized user payload, `max_tokens` and `stream:false`. It uses the same bearer credential resolver, request bounds, locality checks, sanitization proofs and audit path as Responses. It sends no tools. Responses keeps its existing wire format and identity. Neither transport activates or approves a route.

The adapter accepts only bounded text or refusal output from one assistant choice. The returned model selector must match exactly. Tool calls, streaming and unsupported fields are rejected. The adapter does not infer model-specific `developer` roles or `max_completion_tokens` profiles. Test your exact server and model before you approve the route. The local credential requirement stays in force.

For a local connection that you opt in explicitly, set `local_structured_output: true` as a JSON boolean in an explicitly versioned, protected v6 JSON policy. It works only with `openai_chat_completions`, a canonical numeric-loopback endpoint and no request profile. Both bearer and explicit local no-auth configurations are supported. Within v6, leaving the field out or setting it to false produces the same bound bytes and the same policy identity. An explicit v6 policy has its own versioned identity, and it does not migrate historical v1 or v2 policies. Versions 1 through 5 reject the field, even when it is false. Historical v1 and v2 templates without the option still bind to v2 with unchanged bytes and identities. V6 is generic only: it does not accept named request profiles or brokered, OpenCode Go or Console authorities.

When the option is on, Chat also sends `response_format` with `type: json_schema`, `strict: true`, the fixed name `open_trestle_review`, and the exact candidate, verifier or investigation schema that the host pins and validates from the authorized inner request. It does not accept a schema that the caller selects, and it does not change the temperature. Setting the option to true changes the policy, adapter and catalog identities, so bind the changed protected policy and obtain fresh exact approvals where they are required.

Dispatch refuses an approved reservation that is below the larger of two values, and it refuses before it retrieves a credential or makes an HTTP request. The first value is the normal byte-based request estimate of the host. The second is the inner payload bytes, plus the trusted system channel bytes, plus the serialized `response_format` object (including its field wrapper), plus 256 framing bytes.

Route planning counts the same `response_format` bytes, which are deterministic from the pinned schema, whenever the candidate routes of a planning step include a connection with this option. The generation and verification route authorizers, the local generation route plan and each investigation turn reserve the payload, the system channel and the schema framing, so `estimated_input_tokens` does not need to carry that margin. A step reserves once for all of its candidate routes, so a route without the option that is planned in the same step is reserved the same way. An investigation decides per role, from the pinned generation route and from the verification routes.

Such an authorizer binds `input_transport: local_structured_output` into its identity, and the verification authorizer moves to identity version 3 for it. Such an investigation binds the transports of its roles into the route owner and pipeline profile identities, in version 2 of each. Without the option, every estimate and identity is unchanged. This estimate is conservative byte accounting, not exact tokenization. Set a justified reservation that fits the approved context capacity of the route. No budget is increased after authorization.

The command does not assume that a server supports these schema keywords. Requests that the server does not support fail through the existing transport and response checks, without a simplified schema, retry or fallback. The checks on candidate coverage, evidence, usage, tool calls and authorization stay unchanged.

## Local Responses configuration bootstrap

The files in [`examples/local-model-review/`](../examples/local-model-review/) are illustrative bootstrap configurations. They name a loopback OpenAI Responses-style endpoint at `http://127.0.0.1:11434/v1`.

At dispatch time the adapter sends `POST /v1/responses` with JSON that contains `model`, one user `input` item of type `input_text`, `max_output_tokens` and `store:false`. It sends `Authorization: Bearer <credential>`, `Content-Type: application/json` and `Accept: application/json`. The response must be a bounded OpenAI Responses object with `object:"response"`, the selected model, the status `completed` or a supported `incomplete` reason, and assistant `output_text` or `refusal` content. OpenAI-compatible local servers vary, so do not assume that every local server implements this protocol.

Before you use the example, edit `routes.json` for your actual local server, model, capabilities, content-logging posture, status, health, quota, pricing and evidence manifest. Where the repository cannot know the value, the example uses unknown or pending declarations. Replace the credential reference with the name of an environment variable that exists in your protected runtime environment. Do not put credentials in these JSON files.

The `review_policy_identity` in the example is a placeholder label. Replace it with the stable identity that your review policy uses.

Then compute the inventory identity and bind it, using the native command:

```sh
trestle config inventory-identity \
  --route-inventory /protected/routes.json
```

The `decoded` result reports structural identities of the inventory and of its route records only. It says nothing about policy binding or live health. Use `config validate` to check the pair.

For a daemon generation and verifier pair, prepare a policy template and bind its identities with the offline command:

```sh
trestle config bind \
  --route-inventory /protected/routes.json \
  --runtime-policy-template /protected/runtime-policy.template.json \
  --generation-adapter local-generation \
  --verification-adapter local-verification
```

Each adapter must select exactly one local record, and the two adapters must differ. The selected pair must meet the verification independence level of the template. This static check does not require live health or approval.

The command prints one runtime-policy-v2 JSON document for a historical v1 or v2 template, or runtime-policy-v6 for an explicit v6 template. It never upgrades a historical template to v6 and never adds the schema option. It writes no files, reads no credentials, contacts no provider, approves no routes, and changes no setup state. Save the output as a new protected file before you validate it. The command opens no output file, so you control its path, its permissions and any replacement.

Empty, omitted and all-zero binding identities are placeholders. Nonzero inventory, generation-pin and verifier identities that already exist must match the selected records. Other policy values, including the constraints, the independence and the connections, are kept. A v1 template cannot contain the verifier field. V2 and v6 templates may leave it out before binding. Only an explicit v6 template may contain `local_structured_output`. The command refuses null values, unknown or duplicate fields, conflicting bindings and ambiguous adapter selections. Its inputs must pass the protected-file checks described above. Pending routes stay pending, and you cannot run them merely because binding and validation succeeded.

For a historical v1 policy, copy the reported `inventory_identity` into `runtime-policy.json` after you edit the inventory. The shipped example pair is already structurally bound. Leave `preferred_route_record_identities` empty unless you intend to pin or prefer records that the same inventory command reports.

After binding, validate the pair without provider calls:

```sh
trestle config validate \
  --route-inventory /protected/routes.json \
  --runtime-policy /protected/runtime-policy.json
```

Run `trestle local-git model-review` with the same protected files only after validation. Identity and validation make no provider calls, so they do not check reachability or health. The model-review command is where provider calls happen. It cannot publish results.

## Retained advisory input (opt-in)

For an ordinary `local-only` review, add `--retained-memory-input /protected/operator-feedback.json`. Do not combine it with `--investigation-policy` or `--egress policy-approved`. If you leave the flag out, the command keeps the empty memory index. The command does not look for memory files near the repository.

The input is a read-only advisory snapshot that the operator attests to. It contains only `human_feedback` records with `user_controlled` taint. It does not authenticate who wrote the feedback, and it is not permission to publish. The normal changed-path retrieval step selects the records, so loading a record does not guarantee that a model sees it. Generation and verification both receive the selected advice through the existing context pipeline.

The input must be an `open-trestle/retained-memory-input` schema version 1 envelope, implemented in [`runtimeconfig/retained_memory_input.go`](../runtimeconfig/retained_memory_input.go) and its protected loader. It is not a free-form notes file. The loader checks the record identities, the operator-note references, the declared scope, the repository identity and the runtime-policy identity. The authoring command can build this envelope from a protected feedback file that you select explicitly. It does not run a review, resolve credentials, call providers, or update other memory stores.

The example below authors path and text preferences for an explicit head. To record feedback on verified findings, pass `--review-input` with a protected, completed foreground result instead of the two revision flags. That mode derives the head and the finding identities from the result. See [Manual review feedback](local-feedback.md) for the decision selectors, for opting in to reuse later, and for removing an exact input with `--remove-input`. Removal requires the matching review, scope and policy. It does not revoke copies, and it does not change past results.

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

In this explicit-head example, every flag except `--format` is required. The authoring command accepts only `--egress local-only`. `--timeout` must be between one second and 15 minutes. `--valid-for` must be in whole milliseconds, must exceed the timeout, and can be at most seven days. The command reads the clock once, after it has loaded the protected configuration and the feedback. It then sets the `observed_at` and `valid_from` of every record to that millisecond.

The feedback file is a protected JSON file for your convenience, not the wire contract:

```json
[{"path":"src/file.go","text":"operator advisory text"}]
```

This path and text form has these limits and rules:

- The file is at most 64 KiB and holds 1 to 16 records.
- Each record has exactly the keys `path` and `text`. Unknown or duplicate keys, comments, trailing tokens, nested values, and null, boolean or numeric values are refused.
- A path must be a clean, printable, repository-relative path. It cannot be `.` or `..`, absolute, or duplicated, and it cannot contain a backslash.
- The text must be non-empty after trimming. It may contain newlines and tabs. Hidden control characters and Unicode format characters are refused.

The command sorts `allowed_paths` in ascending order and sorts the records by `record_identity`.

The command writes the retained-memory JSON only to `--output`. The parent directory of the output must already exist. The command refuses to create directories, and it refuses to overwrite, truncate or replace a file. Stdout is a receipt that contains only identities, counts and the expiry, without the output path or any advice text. Stderr uses stable reason classes. If a failure happens after the command has created the output exclusively, a partial or complete output file can remain, and the command does not remove it automatically.

The scope must match the tenant and the logical repository, with actor `local-reviewer`, visibility `exact`, and the single path prefix `.`. Its ref-set is the versioned `RevisionIdentity.Identity()` of the requested head, not the raw Git commit digest or the new run ID. A file for a different head or runtime policy is refused, not relabeled. A later invocation reopens the same file and builds a fresh index. It does not resume the previous run.

The limits are 64 KiB of raw input, 16 records and 16 allowed paths, 4096 bytes per canonical record, 1024 bytes of text per record, 8192 bytes of text in total, and 32768 bytes of decoded strings, including repeated keys and values. Every record needs a validity window of at most seven days. Each record must be fresh when it is admitted, and it must expire strictly after the full configured review timeout. Even a record that is not selected can make this admission check fail. Context expiry still prevents a later model dispatch, and no date is extended to finish a run.

The command loads the file after the protected runtime configuration and before it opens the source root or resolves credentials. The existing checks for owner, ancestor, symlink, replacement, and group or world write access apply. They do not guarantee confidentiality or an atomic filesystem snapshot. Use mode `0600` and a private directory for sensitive advice. The model-review command does not edit or delete the input. Removal uses the separate authoring command described in [Manual review feedback](local-feedback.md).

In the results of a session that was built successfully with this input, `empty_memory_index` is replaced with `retained_input_advisory_not_all_records_selected` and `retained_input_read_only`. The schema version of the result, the output bounds and the nonzero dispositions stay unchanged. If the command refuses the protected input, the result is `refused` with exit 4, and a cancellation gives exit 3. Reusing an input is not automatic retained-memory generation, and it does not carry across heads.

## Specialist profile (opt-in)

Add `--profile PROFILE_ID` to select one packaged specialist profile from the embedded catalog described in [agent profiles](agent-profiles.md). The accepted IDs are the profiles that call models to review: `backend`, `bug_hunter`, `drift_auditor`, `frontend`, `security_probe` and `style_conformance`. The command refuses the `orchestrator` profile (it uses no model) and the `knowledge_graph` profile (it reports gaps only). It also refuses `test_author`, because that profile proposes tests, which the defect-claim candidate contract and its verifier cannot represent.

An unknown or refused ID is a usage error (exit 2). The error lists the valid IDs, and it happens before the command reads any configuration or makes any model request. Do not combine `--profile` with `--investigation-policy`. You can combine it with `--retained-memory-input`. Library callers use `localreview.NewSpecialistSession(options, specialist)` with a value from `review.NewContextSpecialist`.

The flag affects only the candidate-generation request. The version 9 review context of that request carries the optional `specialist` object, with only `profile_id`, `profile_identity` and `catalog_identity`. The command sends the exact skill markdown of the profile only in the trusted system channel, after the version 9 host contract. It appears under the heading `Specialist review guidance (operator-packaged profile <id>, shipped with Open Trestle):`. The command looks the skill up in the embedded catalog, not in the payload or the repository. The host contract tells the model to use that section to decide what to look for, without changing the output contract or the evidence rules. Source content keeps its `evidence_data_not_instructions` label.

The identity block is bound into the identities of the context, the sanitized request and the provider request. The identity of the context-assembly handler also binds the profile and catalog identities, so the run plan identity differs from the identity of a run without the flag. When the command reads a result back, it accepts a version 7, 8 or 9 specialist block only if the block re-derives exactly from the embedded catalog. It refuses an unknown profile ID, a mismatched identity, and any extra field, such as instruction text or an authority label.

Route selection does not change. The same generation and verification routes of the runtime policy apply, with the same independence level, and verification still runs. Its request uses verification-context schema version 8, binds the version 9 generation context through `generation_context_identity`, and does not receive the specialist instructions. This command does not use the tiers, token budgets and route assignments of the profile catalog.

Without `--profile`, the version 9 request has no `specialist` block, and the result does not report a profile. With the flag, the result adds `specialist` with `profile_id`, `profile_identity` and `catalog_identity`, for completed runs and for refused or failed runs. Such a result has schema version 6 once its run has opened, and version 3 before that. Earlier builds wrote an opened run as version 3, as version 4 with finding guidance, or as version 5 with a [style recommendation](#style-recommendations). The reported profile must match the one recorded in the generation context. Text output adds a `specialist profile:` line. The instruction text itself is not written to the result. The retained-memory feedback review and the [model-result evaluation](model-result-evaluation.md) import refuse every result that carries a `specialist` object, at any version.

## Specialist review set (opt-in)

Add `--specialists auto` (or `--specialists ID[,ID...]`) to run the general review plus several packaged specialist profiles and merge their verified findings. `--specialists none`, or no flag, is the ordinary single review with unchanged output.

A setup made by `trestle init` or `trestle setup bootstrap init` saves `--specialists auto` in its review command, unless you gave it `--specialists none`. So `trestle review` runs the set. `trestle review --specialists none` runs the single review once, and `--profile ID` replaces the saved set with one specialist. Setups that were saved earlier have no `--specialists` flag and keep the single review.

`--profile` remains the form for a single specialist. You cannot combine it with `--specialists`, and neither can you combine `--investigation-policy` with `--specialists`. The IDs are the ones that `--profile` accepts. An unknown ID is a usage error (exit 2) that lists the valid IDs.

### How the command selects specialists

With `auto`, the command works as follows:

- It derives the change features from the change model and the semantic-impact profile that the general review recorded, after that review has run. It derives the declared style from the root-level style configuration files of the base tree, as the general review recorded them, not from the head (see [declared style in local reviews](agent-profiles.md#declared-style-in-local-reviews)). No model is called for the selection, and no Git object is read again.
- A base style that governs a changed language activates `style_conformance`.
- The command calls the routing planner. It keeps the activated, planned profiles that may steer defect review, in descending priority, with ties broken by profile ID.
- It records the other profiles in `selection.dropped`, with a reason. The reason is `not_applicable` (the profile is model-free, only reports gaps, is `test_author`, or has no model call for this change), `max_specialists` (the limit cut it), or a planner omission such as `tier_unassigned`. Inactive profiles are listed in `selection.inactive`.
- If the features are unavailable, for example because the general review did not reach analysis, then `selection.status` is `features_unavailable`, and no specialist runs. `selection.reason` names the task of the general review that failed. In text output it reads `status=features_unavailable (general review failed at <task>)`. If the general review recorded its change and analysis and failed later, the command still derives the features summary from those artifacts, so languages and file classes are reported even when the plan is unavailable.

With an explicit list, the specialists run in the order that you give. The command does not cut the list. A list that is longer than `--max-specialists` is a usage error.

`--max-specialists N` (1 to 6, default 3) bounds how many specialists run. It needs an active `--specialists` value. It is not a spending limit on its own. Every member is a full run, bounded by the per-run `max_cost` of the runtime policy, so the spending of the set can reach (1 + N) × that `max_cost` (the general review plus N specialists).

### Routes, concurrency and time bounds

Every member uses the one generation and verification route pair of the runtime policy, with its independence level. The command does not apply a route assignment for each profile, and `selection.route_assignment` says so. The planner requires an assignments document, so the command builds a minimal one. It maps every tier to the generation route that the general review actually recorded, and every verifier tier to the recorded verification route. It does not derive the route selection again. It records that basis in `selection.plan`. If the general review recorded no route pair, `selection.status` is `plan_unavailable`, and no specialist runs. The tier and route choices in the plan are informational.

The general review runs first. Each selected specialist then runs as its own session and run, with its own run identity, the same specialist generation request as `--profile`, and its own verification. The verifier does not receive the profile instructions.

Specialists run concurrently, at most three at a time, when all of these hold:

- every route is remote, so that no route is in this machine's zone and no model service is on loopback (a local server such as Ollama serializes requests, so concurrent members would only share the time of one member);
- no limited API key could reach its limit with its recorded spending plus the worst case of the wave.

Otherwise the specialists run one by one, and `bounds.sequential_reason` says why: `local_model_route`, `loopback_model_service`, `spending_limit_could_be_passed` or `at_most_one_specialist`. `bounds.specialist_concurrency` is the number that could run at once. The limitations name `specialists_concurrent_bounded` or `sequential_members_no_parallelism`.

Members are independent sessions, each with its own objects root, gateway and route state. Their spending checks and ledger entries are serialized. A provider's own rate limits still apply to concurrent requests, and a member that those limits refuse fails like any other member.

The general review shares the `--timeout` window with configuration loading, and each specialist gets a fresh `--timeout` window. Model work is therefore bounded by (1 + the number of specialist waves) × `--timeout` (`bounds.max_model_wall_time_milliseconds`), plus at most `bounds.member_cleanup_bound_milliseconds` of bounded close and readback for each member. The command lists members in selection order, whichever finishes first. No further wave starts once the invocation is canceled, or once a launched member's run did not succeed (it was refused, failed or canceled, or the source could not be read). Members that are already running in that wave finish. Members that did not start appear with `launched: false` and a `not_launched_reason`. Nothing is retried.

### Review set output

The output is the `open-trestle/local-git-model-review-set` schema version 1 (JSON), not the result of a single review. It has these fields:

- `selection`: the mode, the status, a features summary, the plan identities, the selected and dropped profiles with reasons, and the inactive profiles. The features summary has the identity, the changed file count, the languages, the file classes, the security signals, the semantic gap count, the public API changes and the reference fan-out. It also has `style_configuration_unread` when the style configuration files of the base could not be used for routing.
- `members`: one entry per member (`general`, then the profile IDs). Each entry has the status, the CI disposition, the run status, and the failure. When the run did not succeed, it also has `failure_task` and `failure_detail`. It has `context_shortfall` only with `failure_detail` `route_context_insufficient`. It has the run, scope, plan and context identities, the route record identities, the independence, the diagnostic set identity, the usage and cost, the verification counts and the limitations. It also has the [`token_usage`](#token-usage) of the member's result, which is absent when the result reports none, as for a member that never ran.
- `walkthrough`: the [walkthrough](#walkthrough) of the general member, once for the whole set.
- `findings`: the merged verified findings in [rank order](#rank). They are merged with the shared [duplicate rule](#duplicates), where the members are the origins. Each finding has its `rank`, `pre_existing` (when every contributor is pre-existing), `unproven_origin` (when every contributor is on unchanged lines and at least one is of [unproven origin](#pre-existing-findings)), the location of the representative, and every contributor with its own finding identity, severity and range. Only members whose run succeeded contribute. The comparison of wording can still keep apart findings that a person would merge (`deduplication_is_heuristic`).
- `summary`, `bounds`, `limitations` and `comprehensive_clearance: false`.
- `style_recommendations`, `style_withheld`, `style_configuration_unread` and `style_advice_unavailable`: the [style advice](#style-recommendations) of the general review. They appear once for the set, not for each member. The fields are absent when the general review has no advice. Text output adds the same `style:` lines before the clearance line, and the SARIF of the set adds the same run property and notes as a single review. The advice does not change the status, the CI disposition or the exit code of the set.

The status and CI disposition of the set are:

| Set | `status` | `ci_disposition` | Default exit |
|---|---|---|---|
| A member did not complete and an introduced merged finding is error severity (verified high or critical) | most serious member status (`failed`, `refused`, `canceled`, `incomplete`) | `blocked` | 4 |
| A member did not complete, no error-severity merged finding | most serious member status | `failed` → `error`, `refused` → `blocked`, otherwise `inconclusive` | 1, 4 or 3 |
| Every member completed, merged findings not empty, one of them introduced and medium, high or critical | `findings` | `blocked` | 4 |
| Every member completed, every merged finding low severity or [pre-existing](#pre-existing-findings) ([advisory](#advisory-results)) | `findings` | `inconclusive` | 3 |
| Every member completed with no candidates | `no_candidates` | `inconclusive` | 3 |
| Every member completed, otherwise | `incomplete` | `inconclusive` | 3 |

`complete` is false whenever a member did not complete. An incomplete set never demotes the verified high or critical finding of a completed member.

Text output is written for people. It starts with `status:` and `ci:`, then lists the reviewers that ran (`reviewers: general, bug_hunter, backend (3 of 3 ran)`). For each member whose run did not succeed, it adds a `not finished:` line with the failure and a `hint:` line. For each selected member that was not started, it adds a `not run:` line with the reason.

After that come the walkthrough of the whole set and the merged confirmed findings in rank order. Each finding has a `confirmed by:` line that names the members whose verifier confirmed it, and an `also reported as:` line when other wordings were merged into it. Then come the pre-existing findings, the hidden count, an `incomplete:` line when a member did not finish, the source coverage when source was omitted, the token total over the members, the style advice, and `comprehensive clearance: false`. This is the output of the offline fixture that the tests use:

```text
status: findings
ci: blocked
reviewers: general, bug_hunter, backend (3 of 3 ran)
walkthrough:
verified: secret scan: 6 model requests from 3 reviewers scanned before sending (876 bytes, 0 secret matches)
verified: static check static_debug_output: passed (1 file checked, 0 matches)
verified: pattern hygiene: 0 added suppressions, 0 added workaround comments, 0 spreading anti-patterns
verified: style detection: ran (1 recommendation, 0 withheld)
verified: semantic impact: 1 changed declaration, 0 public API changes, 1 reference (0 from tests), 0 gaps
verified: independent verifier (distinct_provider): 3 of 3 candidates from 3 reviewers confirmed, 0 rejected, 0 inconclusive
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
confirmed by: general, bug_hunter, backend
tokens: input=600 output=600 cached_input=0 over 6 route attempts (3 reviewers)
style: no declared Go style for 1 changed file; consider gofmt and Effective Go, and commit its configuration
comprehensive clearance: false
```

A member that did not finish reads, for example:

```text
not finished: bug_hunter (failed: internal (task candidates): model_output_invalid)
hint: bug_hunter: the model's answer was not a valid review document (...)
not run: backend (stopped after bug_hunter did not finish (failed))
```

`--verbose` (text only) adds the internals after the reviewers line:

- `complete:`;
- the selection trace (`selection:`, `change features:`, `selected:`, `dropped:` and `route assignment:`);
- `members run:`;
- one `member: NAME status=... run=... verified_findings=N` line for each member, with `failure=` and a `member hint:` line for a member that did not succeed;
- the `findings:` summary by severity and category, and `files covered:`;
- the `limitations:` list before the clearance line.

The JSON output carries every one of these fields with or without the flag.

`--format markdown` renders the set as a pull request summary with the members that ran and, for each finding, the members that confirmed it. The SARIF output is one run whose results are the merged findings in rank order, each with a `trestleContributors` property. When some members did not complete, the results still list the verified findings of the completed members, and an error notification says that the set is not a clean result, even when it lists no finding. If the report of the general member could not be read, the set records the limitation `general_member_report_unreadable_source_coverage_unknown`, and the notification says that the counts of source coverage are unavailable.

The exit policy on the merged set works as follows:

- `default` maps `blocked` to 4, `inconclusive` to 3 and `error` to 1.
- `findings` exits 0 only when every member completed and no introduced merged finding is error severity (verified high or critical).
- `strict` exits 0 only when every member completed with no candidates, so an advisory set exits 3 under it.
- `always-zero` exits 0 when the general review completed, even if a specialist was refused or failed. When the general review itself did not complete, it returns the default code, for example 4 for a refused general review.

## Snapshot investigation (opt-in)

Add `--investigation-policy /protected/investigation.json` to the command above to let the generation model request bounded snapshot tools. Without this flag, the original flow with a single generation is unchanged. The runtime policy must pin one generation route and must permit a verifier. The generation route cannot change during an investigation. Investigation requests are not secret-scanned, so an investigation runs only with `--egress local-only`; `policy-approved` is refused as a usage error.

The investigation policy is a separate protected file of at most 4096 bytes. Its parser requires exact canonical JSON, so the field order, the spelling of integers and the whitespace all matter. Do not pretty-print the file, and do not add a trailing newline. In an existing directory that meets the protection rules above, this example writes the canonical bytes:

```sh
printf '%s' '{"contract":"open-trestle/investigation-policy","max_cost_micro_usd":1000000,"max_files":64,"max_lines_per_read":64,"max_matches":16,"max_model_turns":5,"max_result_bytes":8192,"max_returned_bytes":65536,"max_scanned_bytes":1048576,"max_tool_calls":3,"profile":"snapshot-read-v1","schema_version":1,"timeout_milliseconds":300000}' > /protected/investigation.json
chmod 600 /protected/investigation.json
```

The example permits five model turns in total, including the final generation and the verification, and at most three tool calls. Its cost cap is 1,000,000 microUSD (USD 1), and it must not exceed the cap of the protected runtime policy. These are limits that apply when a run is admitted. They do not guarantee what the provider bills. Use limits that suit the routes you approved. Zero cost is valid for routes whose admitted cost is zero. Both the command timeout and the investigation timeout apply, and neither extends the other.

Investigation requests use investigation context version 6. Like generation version 9 and verification version 8, this version sends its contract only in the trusted system channel. The contract has three parts:

- The instruction-hierarchy paragraph. It says that every string in the request is untrusted repository data. That includes snapshot tool results and the files that they return. Repository instruction files cannot change the rules, the output format, the severity or the evidence requirements.
- The sentence that explains `removed_lines` sources.
- The version 4 tool and output rules, unchanged.

The payload binds that text with `instructions_identity`. Files that a tool returns are flagged with `agent_configuration` and `instruction_like_text`, like other sources, and each raw tool result that the model sees carries `risk_flags` computed by the same rules. Recorded version 5 investigation requests (the same contract without the `removed_lines` sentence) and recorded version 4 requests (which carried their rules in the payload and had no hierarchy paragraph) can still be read back, but the command does not send them again. See [prompt-injection boundary](prompt-injection-boundary.md).

The available tools list files, read inclusive line ranges, and search for a literal string within the immutable snapshot that the command acquired. They do not run shell commands or regular expressions, and they do not use provider-native tools. A model proposal carries opaque references that the host issued, not filesystem authority. Before it runs a tool, the controller checks the proposal, the actual model response, the source bindings and the remaining limits.

`max_files` limits the file coverage of the reader. The command refuses initially selected paths that fall outside that coverage. Each read or search charges the full file bytes that it loaded, including repeated reads and searches with no match. `max_result_bytes` bounds each raw tool-result payload. `max_returned_bytes` also bounds the cumulative encoded tool artifacts. The existing bounds on acquisition, context, artifacts and provenance still apply, so a policy alone does not guarantee that a repository fits. This mode requires supported Git objects under the selected object-store profile, and it uses an empty memory index.

The local graph still has nine tasks and no publication task. One owned account covers all generation and verification turns, and tool use does not reset it. If the effects on the model are unknown, if persistence fails, or if the usage is uncertain, the run stops without an automatic replay. A fresh command is new paid work, not a recovery. Library callers can opt in with `localreview.NewInvestigationSession(options, policy)`. Each admitted run gets a fresh bridge and acquisition owner.

Each model turn reserves the larger of two values: `estimated_input_tokens`, and the request payload bytes plus the trusted system channel bytes plus 256 framing bytes. This is the same estimate as in a single-generation review. A turn whose routes use [`local_structured_output`](#chat-completions-transport) also reserves the bytes of the serialized `response_format`.

Under estimate version 2, the turn record stores the system channel bytes that it reserved. A turn with structured output also stores its `response_format_bytes`, and a standard turn omits that member and keeps its encoding and identity. Whenever the command reads a retained turn back, it measures both counts again from the turn's own recorded request, using the contract version that the request records. It refuses a record whose counts the request does not support. Turn records written under estimate version 1 counted the payload alone. They read back with that formula and are never estimated again.

Results of an opted-in run use schema version 6 once the run has opened, and version 2 before that. Earlier builds wrote version 2, or version 5 with [style advice](#style-recommendations). The result includes all retained turns, with their request, route, audit and tool-result identities, not only the final two model calls. Each turn also carries the `input_tokens`, `output_tokens` and `cached_input_tokens` that the provider reported, and `token_usage` sums the turns by role (see [Token usage](#token-usage)). A known observed cost stays visible when the total usage is unknown.

When the run ends in failure, an actual scoped diagnostic set can remain as historical data with `diagnostics_not_terminal_success`. It grants no readiness or success. If the whole optional set cannot fit, the command omits it with `diagnostics_omitted_output_limit` and does not truncate it partially. The JSON and text limits and the nonzero exit codes below still apply. The sealed result bytes remain readable after a successful Close, and they keep no live authority to execute.

## Execution and ownership

The foreground session uses the real handlers for source, change, analysis, memory, context, generation, verification and readiness. Its local graph has nine tasks and no publication task. The artifact store, the audit ledger, the diagnostic store, the journal, the coordinator, the Runner, LocalControl and the finalizer are all private to the process. Without retained advisory input, the memory index is empty, and the result reports that as a limitation. Retained input changes only this ordinary retrieval source.

Context assembly, generation and verification have one attempt each. The default deterministic tasks have three attempts with a retry delay of one second. Leases last 30 seconds. A lease is nominally renewed every 10 seconds, and a short configured timeout clamps that interval once, to at most half of the timeout. The command does not extend the parent deadline. Interrupts and cancellation by the caller reach source acquisition and the HTTP work for the model.

The command registers every handler that it actually starts before the goroutine of that handler starts. If the command already knows about a cancellation when a task is claimed, it suppresses the handler. A worker cancels its work and waits up to two seconds for cleanup before it returns. `Runner.Wait(ctx)` can check a later drain. Work that does not cooperate returns `ErrWorkerDrain`, and the command does not kill it by force.

For library callers, `localreview.NewSession` takes ownership of the already opened `*os.Root` only on success. `Close(ctx)` cancels work, and it closes the root only after a safe drain. If a drain fails, the session keeps ownership for a later explicit Close. There is no cleanup daemon. The CLI renders its result only after a successful close, and a failure to drain or close overrides the terminal disposition.

A session serializes admission. It refuses scopes that are duplicate, relabeled or already claimed, and it refuses concurrent work in different scopes. Each explicit CLI invocation creates fresh identities, and all state is ephemeral. Repeating a command starts new model work. It is not durable deduplication, and it does not resume anything.

## Deletion-only changes

A supported diff can contain deletions without any changed head lines, for example a removed guard. The change model records such a file as `no_changed_head_lines`, and it does not invent a changed range.

The analysis then compares the exact base and head files. For each deletion point, it binds up to 8 unchanged head lines on each side as an item of deterministic evidence, and overlapping windows merge. These items enter the context packet as `changed_hunk` sources, so the model reviews the code that now sits where the lines were removed. The analysis also records each deletion point as an `analysis_deleted_lines` source omission. Its lines are the head lines on either side of the removed lines (one line at the start or end of the file). The omission is how the packet says that lines were deleted there. It counts as an unsupported source omission.

The removed base lines themselves reach the model as `removed_lines` sources. The analysis binds the removed lines of each deletion point to the exact base file (deterministic evidence schema version 7). The context handler reloads that file from the base snapshot reference whose digest the change entry names. It rebuilds the identity and the slice binding from the bytes, and it adds one `removed_lines` source for each deletion point.

The `path` of such a source is the file, and its `start_line` and `end_line` are base line numbers, not head lines. Like every other source, it is `repository_controlled` data with `risk_flags` computed by the same rules, so an injection payload in deleted text is flagged.

The source of a deletion point also carries `head_line`, which is the head line beside which the lines were removed (the first line of its `analysis_deleted_lines` omission). When the command reads a result back, it refuses a `head_line` on any other stage, and it refuses one outside every `changed_hunk` source of the same file. The contracts for generation (context versions 8 and 9), verification (versions 7 and 8) and investigation (version 6) each tell the model that `removed_lines` sources are deleted base lines, and how to report an issue in the removed code on them. The verifier receives the same sources.

### Base-side findings

A finding about code that still exists is located on head lines, as before. A finding about the removed code itself may be located in the `removed_lines` source that holds it. This is a base-side finding. Its `start_line` and `end_line` are base line numbers inside that source, and it records the `head_line` of the source (none for an emptied or removed file).

Base line numbers and head line numbers are different coordinate spaces. Evidence from base lines never covers a head location, and evidence from head lines never covers a base-side location. Only cited `removed_lines` evidence can verify a base-side finding. The `repository_context_anchor_omitted` count again covers only `repository_context` anchors, which the command still drops. Investigation turns accept base-side findings too.

Every recorded format names the side explicitly, so reading a result back can never turn base lines into head lines:

- Candidate-batch encoding v2, verified-finding-set v2 and verification-context v7 record `"side":"base"` and `head_line`.
- Other formats gain a version that is used only when a base side is present. These are candidate-batch encoding v3 and verified-finding-set v3 (uncategorized, from investigation), verification-batch v2, model-generation-input v4 (unsanitized, with `removed_lines` evidence marked `"side":"base"`) and v5 (an investigation input with such evidence), and verified diagnostic set v8 (`schemas/diagnostics/verified-diagnostic-set-v8.schema.json`), which the final set v7 may embed in place of v5.

Each output shows a base-side finding without presenting its numbers as head lines:

| Output | Base-side finding |
|---|---|
| Text result and review set | `source: path removed base lines a-b (beside head line h)` |
| JSON result | the recorded diagnostic set, with `side` and `head_line` |
| SARIF | a result at the head line beside the deletion point, with `(removed base lines a-b)` in the message and `trestleSide`, `trestleBaseStartLine` and `trestleBaseEndLine` properties; with no head line (an emptied or removed file), a run-level notification instead of a result |
| GitHub | the review summary only, labelled `` `path` removed base lines a-b ``; never an inline comment |
| Web console and terminal | the location is labelled as removed base lines |
| Language server | a file-level diagnostic whose message starts `Base lines a-b (removed code):`; a removed file has no open head document |
| Retained-memory feedback | matches head findings only |

Review sets never merge a base-side finding with a head finding.

### Bounds and removed files

Removed text is bounded to 64 lines and 8 KiB for each deletion point, and to 32 KiB for each file. The command does not truncate text that goes past a bound. Instead it records the removed text of that point whole as an `analysis_removed_lines_limit` omission, whose lines are the removed base lines. Removed text is omitted with the usual reason, at its base lines, when it is not valid UTF-8, when it is on an excluded or unauthorized path, or when it goes past the candidate limit. The command supplies the removed text of a deletion point only when a selected `changed_hunk` of its file holds the `head_line`. Otherwise the text becomes a `packet_budget` omission at its base lines.

A file whose head is now empty, and a removed file, keep their whole-entry omission (`analysis_no_changed_head_lines` or `analysis_removed_file`), so their review is never full clearance. The command also binds and supplies their removed base text, with no `head_line`. It does so in consecutive chunks that are aligned to lines, with at most 64 lines and 8 KiB each, up to 32 KiB for each file, covering the base file from line 1. The rest of the file, starting at the first line that does not fit, is one `analysis_removed_lines_limit` omission at its base lines. A line is never cut.

This text uses only the analysis budget that the changed files left over, and only the bytes that it binds count, so removing large files never takes budget from a changed file. The command reads removed files within a separate 64 MiB bound. It does not read a removed file that goes past that bound, and the whole removed text of that file becomes one `analysis_removed_lines_limit` omission with no lines.

This text needs no neighboring head lines, so a change that only removes files is reviewed from it. Its review snapshot has no head range, and its packet holds only removed text. If the text of a removed file cannot be supplied, for example because the content is binary and is not bound, nothing is left to review. Such a change is still refused with `all_sources_omitted`.

The whole-entry `no_changed_head_lines` gap also remains, without removed text, when a file that still has head lines cannot get context for its deletion points. That happens when the diff is unsupported or over its limits, or when the evidence limits are reached.

A file over the 1 MiB diff bound is an `analysis_resource_limit` omission instead, if it was removed, emptied, or added without a reviewable range. A removed or emptied file of this kind also adds an `analysis_removed_lines_limit` omission with no lines, because the command does not read its text. The command still reviews the rest of the change.

Investigation mode reviews such a change the same way. Its first turn holds the removed text alone, with no head range, and its snapshot tools can still list and read the head snapshot. Its generation input then records only `removed_lines` evidence, as model-generation-input version 5.

## Ranked findings and the walkthrough

The command decides which findings survive, after verification. No model ranks, merges or classifies findings. The result of a completed direct run (schema version 6, in place) adds five members:

- `rank`: every distinct verified finding in rank order, as `{"rank": N, "finding_identity": ID, "merged_finding_identities": [ID, ...]}`. The identities are diagnostic finding identities, and the merged list (absent when empty) names the duplicates that were merged into the finding. Every diagnostic finding appears exactly once. The JSON result still carries every finding in `diagnostics`.
- `pre_existing`: the diagnostic finding identities that the command classified as [pre-existing](#pre-existing-findings), in diagnostic order. It is absent when there are none.
- `unproven_origin`: the diagnostic finding identities on unchanged lines whose origin the command could not prove (see [pre-existing findings](#pre-existing-findings)), in diagnostic order. It is absent when there are none. No finding is in both lists.
- `declaration_anchors`: an entry for each finding that is held by a changed Go declaration of the semantic-impact profile of the run, in diagnostic order, as `{"finding_identity": ID, "start_line": N, "end_line": M}`. The lines are those of the declaration on the finding's side (see [duplicates](#duplicates)). The member is absent when no finding is anchored.
- `walkthrough`: the [walkthrough](#walkthrough), present once the change model was recorded.

Results without verified findings carry no `rank`, `pre_existing`, `unproven_origin` or `declaration_anchors`.

### Duplicates

One function decides duplicates wherever several verified findings can describe one defect: within one run (including an investigation run), across the members of a [specialist review set](#specialist-review-set-opt-in), and across repeated runs of the same change (`localreview.DeduplicateFindings`). It makes two passes.

The first pass is strict. It merges two findings when all of these hold:

- They have the same path and side. Base and head line numbers never merge.
- The line range of the finding overlaps the range of the group representative.
- They have the same or a compatible category. The compatible categories form families: correctness, concurrency, performance and reliability; security alone; maintainability, style, documentation and testing. A finding without a category is compatible with any category.
- Their defect statements are nearly identical. The command lowercases the title and claim into runs of letters, digits and underscores, drops function words, and reduces a plural `s` or `ies`. At least four fifths of the combined words of the two statements must be shared. Neither statement may hold a symbol that the other lacks: a word of at most two characters, a word with a digit or underscore, or a word with a capital letter after its first character. So `a / b` and `a / c`, or `limit 10` and `limit 100`, stay apart.

A second pass, anchored on the location, merges paraphrases of one defect at one place that share less wording, for example "Avg may divide by zero" and "Avg panics on an empty slice" when the claims both say that `len(xs)` is zero. It merges the groups of the first pass when all of these hold for their representatives:

- They have the same path and side.
- Their line ranges overlap.
- Their categories are in the same family, and the family is not security. Security findings merge only by the strict rule, and so does a finding without a category.
- Both findings are inside the same changed declaration. For a head finding, this is the narrowest added or changed Go declaration of the semantic-impact profile of the run that holds all of the finding's lines. For a base finding, it is the removed declaration that holds the finding's lines (`declaration_anchors`). When no changed declaration holds either finding, both must lie within one range of at most 5 lines instead. An anchored finding never merges this way with an unanchored finding or with a finding in another declaration.
- Their defect statements share at least half of their combined words, and neither holds a symbol that the other lacks (the same normalization as the first pass).

The place alone does not merge findings. Two different defects on one line, such as a division by zero and an integer truncation, stay two findings, and so do two wordings that share less than half of their words, even when a person would read them as one defect. The command compares groups in the order of their creation, and each group joins the first earlier group that it matches. Only the representatives decide.

Only the range and the statement of the representative decide a match, so a finding never joins through a finding that the group already absorbed. The representative is the strongest verified finding. The command prefers the most severe finding, then the one that cites the most distinct evidence, then a finding on changed lines over a pre-existing one, then the narrowest range, then the earliest. The representative is reported at its own location.

A merged finding never hides another wording. Text and Markdown list the other titles on an `also reported as:` line (a review set names the member that reported each). The JSON of a set finding has a `merged[]` list with every other contributor, its `member`, `finding_identity`, `title` and `claim`, and the `rule` that merged it (`near_identical`, `same_declaration` or `same_lines`).

Without its profile, the anchors cannot be derived again from a result. So `localreview.ParseCompletedResult` checks that each anchor names a distinct finding in diagnostic order and contains its lines, and it recomputes `rank` with them. It also accepts a `rank` that the second pass produced without the wording requirement, as results recorded before that requirement have. A merge never relaxes a CI disposition or an exit code. A single review decides them from every finding, and a merged set finding blocks whenever one of its contributors would.

### Rank

The command orders distinct findings by these keys, in this order:

1. The final severity: verified high and critical, then medium, then low, then hints.
2. The verification confidence: the number of origins whose verifier confirmed the defect, then the strongest verification independence (distinct provider, distinct model, distinct route).
3. The strength of the evidence: the number of distinct evidence items, then a narrower range.
4. The location, the category and the identity.

Text and Markdown list the confirmed high, critical and medium findings, and they count the rest, for example `hidden: 1 lower-severity finding not shown; add --all to list every finding (the JSON output lists all)`. When no confirmed finding is high, critical or medium, the output lists the lower-severity findings instead, at most 10 in rank order, and counts the rest the same way. The first review in `trestle init` shows the same lists. `--all` lists every finding. JSON and SARIF always carry every finding.

### Pre-existing findings

A verified finding is on unchanged lines when both of these hold:

- The finding is on head lines, either in an unchanged file (for example a direct reference, or a caller of a changed function) or in a modified file whose lines are known. It overlaps no changed line and no deletion window. A deletion window is the 8 unchanged head lines on each side of a block of removed lines, taken from a fresh bounded diff of the recorded base and head files.
- None of its cited evidence is a changed hunk (including the context around a deletion) or removed lines.

Unchanged lines do not prove that the change did not cause the defect: a changed function can break an unchanged caller. So a finding on unchanged lines is pre-existing only when all of these also hold:

- It is in an unchanged Go file.
- The semantic-impact profile of the run has no coverage gap: every changed file was analysed as Go and every head Go file was read.
- No changed declaration is a method or an `init` function, which code can reach without naming them.
- No code outside the changed declarations names a changed declaration. References are matched by name, so this also rules out callers that reach the change through unchanged code.

Any other finding on unchanged lines has an unproven origin. It is listed in `unproven_origin`, it stays with the confirmed findings with an `origin: unproven` line in text and Markdown (`trestleUnprovenOrigin` in SARIF), and it blocks CI like an introduced finding. A caller of a changed function, the usual finding on unchanged lines, is of unproven origin.

A finding on removed base lines, in an added file, or in a file that the diff cannot represent is introduced, so an uncertain finding keeps blocking. A file that the diff cannot represent has binary or non-UTF-8 content, or goes past the bounds of the diff. Only a direct run classifies findings, and an investigation run classifies none.

Pre-existing findings get their own section in the text and Markdown output, and they never block CI (see [advisory results](#advisory-results)).

The command derives the class from the change model, the context and the semantic-impact profile of the run itself, which a result does not carry. `localreview.ParseCompletedResult` therefore treats a recorded `pre_existing` list as advisory. It checks that the list names distinct diagnostic findings in order, and it recomputes `rank` from the findings of the result. The list cannot relax the `ci_disposition`, and it refuses a result whose disposition the class relaxed. No exit policy applies the list of a parsed result. The recorded `unproven_origin` list is checked the same way and is shown as recorded, since it never relaxes anything.

The model-result evaluation import reads a result with `localreview.ObserveCompletedResult` instead. It accepts the same results, and also a version 6 result whose disposition its recorded `pre_existing` list relaxed: `status` `findings`, `ci_disposition` `inconclusive`, and every medium, high or critical finding listed as pre-existing. It returns only the metadata that evaluation records, so the relaxation is observed and never trusted for a gate.

### Advisory results

Only a medium, high or critical finding that the change introduced blocks CI. A completed review is advisory when its confirmed findings are all low severity (diagnostic severity `information`), all pre-existing, or a mix of the two. An advisory review keeps `status` `findings` and has `ci_disposition` `inconclusive`, like a run that could not reach a verdict, and its findings are still listed. One introduced medium, high or critical finding makes the result `blocked`.

SARIF keeps the level of each result (`note` for low), and `trestleCiDisposition` reports the disposition. The exit-code policies keep their meaning:

| Policy | Advisory (every finding low severity or pre-existing) | An introduced medium finding, none higher | An introduced high or critical finding |
| --- | --- | --- | --- |
| `default` | 3 (inconclusive) | 4 | 4 |
| `findings` | 0 (no introduced high or critical finding) | 0 | 4 |
| `strict` | 3 (there were candidates) | 4 | 4 |
| `always-zero` | 0 | 0 | 0 |

`strict` still fails the step on every finding of any severity. It exits 0 only when there were no candidates at all.

A review set follows the same rule over its merged findings. A merged finding is pre-existing only when every contributor is, and it has the severity of its representative. It is of unproven origin when every contributor is on unchanged lines and at least one is of unproven origin. A set whose merged findings are all low severity or pre-existing has the status `findings` and the disposition `inconclusive`. An incomplete set never demotes an introduced high or critical finding.

`localreview.ParseCompletedResult` derives the disposition again from the severities that a result records, and it refuses any other disposition. A version 6 result whose verified findings are all low severity must be `inconclusive`. A version 6 result with a medium, high or critical finding must be `blocked`, whatever its `pre_existing` list says, because that class cannot be derived again. Results of versions 1, 4 and 5 must carry the readiness disposition (`blocked` when a finding was verified). A relaxation that a result asserts about itself is not trusted: only `localreview.ObserveCompletedResult` reads one, as described under [pre-existing findings](#pre-existing-findings).

### Walkthrough

The command builds the walkthrough from the artifacts that the run recorded. It has four parts, in this order:

1. What was verified (`walkthrough.verified`). It has these entries:
   - `secret_scan`: `scanned`, with the request count, the scanned bytes, the matches and the redacted bytes from the receipts; `not_run` when no model request was prepared; or `unavailable` when a receipt could not be read. Local-only requests are scanned too.
   - `static_checks`: the key, the state, the checked files and the matches of each deterministic check.
   - `style_detection`: `ran`, with the counts of recommendations and withheld items, or `unavailable`.
   - `semantic_impact`: the changed declarations, the public API changes, the references, the references from tests and the gaps, or `unavailable`.
   - `pattern_hygiene`: see [pattern hygiene](#pattern-hygiene). It is `ran` with its counts and items, or `unavailable` when the run recorded no version 9 generation context. It is absent only in walkthroughs that were recorded before it existed.
   - `verifier`: the candidates, and the verified, rejected and inconclusive counts, and the independence. It is absent when no verified set was recorded.
2. A summary of the change for each file (`walkthrough.files`). Each entry has the path of the changed file and the change, which is `added`, `modified`, `removed`, or `renamed` (with `renamed_from`, for a removed file whose exact content is an added file). It has `added_lines` and `removed_lines` from a fresh bounded diff, and these are absent when the diff cannot count them. For Go files, it also has the added, removed and changed declarations with their kind (method names carry their receiver, such as `(*Calc).Divide`) and any `semantic_gap`.
3. Missing verification (`walkthrough.missing_verification`). This lists the added or changed functions and methods, outside test files, that no test file references. It comes from the affected-test candidates of the semantic-impact profile. It is informational and does not change the status, the CI disposition or the exit code. References are matches of identifiers, so a function that is not listed may be referenced only by a test of another function with the same name. `missing_verification_incomplete` is set when the profile did not read every Go file.
4. The stated intent (`walkthrough.stated_intent`). This is what the author of the change says that it does, taken from the commit messages that the generation context carried (see [commit messages as stated intent](#commit-messages-as-stated-intent)). It lists at most 8 commit subjects (first lines), oldest first, with control and format characters replaced and each subject cut at 120 characters. It is labelled `author_stated_unverified`, and it has `commits`, `subjects_not_listed`, `truncated`, `instruction_like` and `range_incomplete`. It does not change the status, the CI disposition or the exit code. Text output quotes each subject, and Markdown puts each in a code span, so a subject cannot open a link, a heading or a mention, and cannot move a terminal cursor.

The JSON lists at most 64 files, 16 declarations for each file (128 in all) and 32 missing-verification notes, and it counts the rest (`files_not_listed`, `declarations_not_listed`, `missing_verification_not_listed`). Text and Markdown list at most 32 files. If the result would exceed its output bound with the walkthrough, the command leaves the walkthrough out and records `walkthrough_omitted_output_limit` in the result. An investigation run has no walkthrough.

The `walkthrough` of a review set describes the whole set. Every member reviews the same change, so these parts are shared and come from the first completed member, which is the general review: the summary for each file, the deterministic checks, the style detection and the semantic-impact summary. The missing-verification notes are those of the completed members, with duplicates removed.

The secret scan and the verifier ran once for each member. So `verified.secret_scan` is the total over the completed members (requests, scanned bytes, matches and redacted bytes). It is `scanned` when every member scanned or prepared no request, and `unavailable` when the account of a member could not be read. The totals then cover the members that did scan. `verified.verifier` totals the counts of candidates, confirmed, rejected and inconclusive findings of the members before duplicates are merged, with the weakest independence among them. `walkthrough.verified_by_member` lists the own `secret_scan` and `verifier` of each completed member, in member order. When no member completed, the first member with a walkthrough describes the set alone. Text and Markdown name the reviewers that the totals cover:

```text
verified: secret scan: 6 model requests from 3 reviewers scanned before sending (876 bytes, 0 secret matches)
verified: independent verifier (distinct_provider): 3 of 3 candidates from 3 reviewers confirmed, 0 rejected, 0 inconclusive
```

Text output shows the walkthrough, then the confirmed findings in rank order, then the pre-existing findings, then the hidden count, then the coverage, the tokens and the style advice. This is the output of the offline fixture that the tests use:

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

The list of `limitations:` tokens is internal. `--verbose` (text only) prints it before the clearance line, and the JSON and SARIF output always carry it. If the policy of a run did not require zero data retention on an OpenRouter route, the output shows that fact by default on a `zero data retention:` line. A merged finding shows `merged duplicates: N` and, when the merged wordings differ, `also reported as:` with their titles.

### Commit messages as stated intent

A direct review reads the commit messages of its range, `base..head`. This is the set of commits that are reachable from the head and not from the base, as `git log base..head` lists them. The review reads them from the same verified Git objects that source acquisition read, and it runs no `git` command for them. The walk paints both sides starting with the newest commit time, as the merge-base walk of Git does, so a feature branch that merged its default branch keeps the shared history out of the range. The walk reads at most 1,024 commit objects and keeps at most 4 KiB of each message. If it could not separate a range completely (because of the read bound, or because a parent is missing from a shallow checkout), the range is marked `range_incomplete`. Every commit that is listed is still in the range.

The messages enter the generation context (version 9) as its `stated_intent` object, oldest first, labelled `author_stated_unverified`. The object holds at most 16 commits, 2 KiB of each message and 16 KiB in all. The command cuts a message on a character boundary and marks it `truncated` with its full `message_bytes`. Commits past a bound are counted in `commits_omitted`. A message that is not UTF-8 text keeps no text and is marked `unsupported_content`.

The text counts toward the source budget of 128 KiB of the packet. It fills what the selected sources leave, so changed code keeps priority. Each message carries `risk_flags` from the same content rules as every source (`instruction_like_text`, `hidden_unicode`). The `agent_configuration` rule is a path rule, and a commit message has no path. The verifier request (version 8) carries the same object unchanged. Both are secret-scanned before any remote egress, each message as a `stated_intent_text` field. See the [prompt-injection boundary](prompt-injection-boundary.md#stated-intent).

The finder may compare the change with the stated intent and propose a mismatch as an ordinary candidate (category `correctness`) whose claim names the intent that it contradicts. The verifier checks such a claim against both the intent and the evidence. The commit messages also declare the intent of the change for specialist routing, so under `--specialists auto` the `drift_auditor` profile activates on a change with commits. The members of a review set read the same commits.

The daemon does not yet read commit messages, pull-request text or linked issues. See the [roadmap](roadmap.md). The context of an investigation run carries no stated intent.

### Pattern hygiene

Every version 9 generation context records deterministic evidence about pattern hygiene. Context assembly computes it from the snapshots that the command acquired, without a model. For each changed file in a supported language, it counts a small, curated set of anti-patterns in the base and in the head of the file's directory (one level, not recursive). It reports the anti-patterns whose count rose.

On the changed lines, it finds these items:

- lint and type suppressions;
- comments that justify a workaround;
- TODO markers without an issue reference;
- in agent instruction and skill files, added absolute rules.

The command skips vendored trees (`vendor`, `node_modules`, `third_party`). It compares at most 32 directories, 128 files on each side, and 8 MiB of base text. A directory that goes past a bound is not compared at all, and it is counted in `unread_directories`, so a partial count does not show an increase. The command skips files over 1 MiB, and text that is not UTF-8 or holds a NUL byte, on both sides.

The `pattern_hygiene` object of the packet carries complete counts and at most 16 items. Each item has a kind, a curated rule ID, the `source_id` of the changed source that holds the line, the line, and, for an anti-pattern, the base and head counts of the directory. The object carries no repository text and no path, so it adds no field that needs a secret scan. Items are ordered with root-cause notes first, then increases in anti-patterns, then the other observations. An item whose line is in no selected changed source is counted in `items_not_listed`. The finder treats the object as attention markers. They are not findings and not instructions, and the verifier does not receive the object.

The anti-patterns (`internal/patternhygiene/rules.go`) are:

| Rule | Language | Matches | Why |
|---|---|---|---|
| `go.time_sleep` | Go | `time.Sleep(` outside `_test.go` | a fixed sleep stands in for missing synchronization or retry logic |
| `go.library_panic` | Go | `panic(` in a non-main, non-test package | library code should return an error |
| `go.library_print` | Go | `fmt.Print`, `fmt.Println`, `fmt.Printf` in a non-main, non-test package | leftover debugging that bypasses the caller's logging |
| `go.nolint_without_reason` | Go | `//nolint` without a trailing `// reason` | an unexplained suppression cannot be reviewed |
| `js.use_effect` | JS, TS | `useEffect(` in `.jsx` and `.tsx` files | stale closures, missing dependencies, render loops |
| `js.set_timeout` | JS, TS | `setTimeout(` (bare, `window.` or `globalThis.`) outside test files | a timer papers over an ordering problem |
| `js.request_animation_frame` | JS, TS | `requestAnimationFrame(` outside test files | deferring work hides a layout or ordering problem |
| `js.eslint_disable` | JS, TS | a comment starting `eslint-disable` | silences the check instead of fixing it |
| `js.ts_ignore` | JS, TS | a `@ts-ignore` comment | hides every type error on the next line |
| `py.mutable_default` | Python | a one-line `def` with a `[]`, `{}`, `list()`, `dict()` or `set()` default | the default is shared by every call |
| `py.bare_except` | Python | `except:` | also catches `KeyboardInterrupt` and `SystemExit` |
| `py.type_ignore` | Python | a `# type: ignore` comment | silences the type checker for the line |
| `py.noqa_without_code` | Python | `# noqa` without `: CODE` | silences every check on the line |

The observations about added lines are:

- Suppressions: `//nolint`, `eslint-disable`, `@ts-ignore`, `# type: ignore` and `# noqa`, whether or not they give a reason.
- Workaround comments: `workaround`, `hack`, `for now`, `temporary fix` and the like, `temporarily disable` and the like, "because ... doesn't", and "to avoid ... we".
- `TODO`, `FIXME` and `XXX` with no reference such as `#123`, `ABC-123`, `gh-123`, `issue 123` or a URL.
- In `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `SKILL.md`, `.cursor/rules/**`, `.github/copilot-instructions.md`, `.trestle/review-instructions.md` and Markdown under a `skills` directory: added lines with `NEVER`, `ALWAYS` or `MUST NOT` in capitals, or with never, always or must not in bold. The review treats those files as code, not as instructions.

A suppression on a workaround comment, or on the line next to one, becomes a `root_cause_not_fixed` note: the change silences a check and explains why, instead of fixing the cause.

The matching has guards against false positives. It is lexical, over a line lexer that blanks string literals and separates comments. The lexer tracks block comments, Go raw strings, JavaScript template literals and Python triple-quoted strings, so a pattern inside a string or a comment does not match as code. The Go library rules need a `package` clause other than `main`. These cases do not match:

- "temporary" alone ("a temporary file") is not a workaround.
- "because" needs a negation.
- TODO markers must be uppercase words followed by `:`, `(`, a space or the end of the line, so `XXX-XXX` and "todos" do not match.
- A `noqa` must start a comment.
- Lowercase directives in prose are not flagged.

A moved occurrence does not raise the count of a directory. These checks are not a linter. The list is short, and it prefers a missed match to a false one.

The `verified.pattern_hygiene` entry of the walkthrough reports the counts and the placed items, each with `origin` `deterministic`. A `root_cause_not_fixed` item is a deterministic finding of severity `low`, labelled as such, and it does not change the status, the CI disposition or the exit code. The model's own candidates about pattern hygiene go through verification like any other candidate. Text and Markdown show one summary line, then each listed increase in anti-patterns and each root-cause note, and then the stated intent after the verified lines:

```text
walkthrough:
verified: secret scan: 2 model requests scanned before sending (806 bytes, 0 secret matches)
verified: static check static_debug_output: passed (2 files checked, 0 matches)
verified: pattern hygiene: 1 added suppression, 1 added workaround comment, 1 spreading anti-pattern, 1 new anti-pattern
verified: pattern hygiene note (deterministic, low): retry.go line 5 adds a suppression beside a workaround comment; the root cause is not fixed
verified: pattern hygiene: retry.go line 6 adds go.time_sleep (time.Sleep( in non-test Go code; its directory had 1, now 2)
verified: pattern hygiene: retry.go line 5 adds go.nolint_without_reason (//nolint without a trailing // reason; new in its directory)
verified: style detection: ran (0 recommendations, 0 withheld)
verified: semantic impact: 2 changed declarations, 0 public API changes, 1 reference (0 from tests), 0 gaps
verified: independent verifier (distinct_provider): 1 of 1 candidate confirmed, 0 rejected, 0 inconclusive
stated intent (author-stated, unverified): "feat: retry the upload"; "fix: tidy" (1 flagged as instruction-like text, treated as data)
file: a.go modified +1 -1; changed function Changed
file: retry.go added +8 -0; added function retry
```

Markdown adds a `### Stated intent` section after "What was verified". Each subject is in a code span under the line "Author-stated and unverified: what the commit messages say the change does, not evidence."

### Markdown output

`--format markdown` writes a pull request summary comment. It has these parts:

- a `## Open Trestle review` heading with the status, the CI disposition and the run status;
- `### What was verified`;
- `### Changes`;
- `### Missing verification`, marked informational;
- `### Confirmed findings`, as a numbered list in rank order (a review set adds the members that confirmed each finding);
- `### Pre-existing findings`;
- the hidden count;
- a footer that states that comprehensive clearance is false and that titles, claims and fix text are untrusted model output.

The command escapes titles, claims, fix text, paths and declaration names. They cannot open emphasis, a link, an image, a heading, a table cell or an HTML tag. They cannot mention anyone, and they never become an autolink: a zero-width space breaks every scheme colon such as `https:` or `mailto:`, every `www.` host and every `@`. The renderer writes no links of its own. The GitHub publisher of the daemon builds its own review body from the publication plan that was scanned for content. It does not use this renderer, and it applies the same autolink defusal to the text that it renders.

## Results and limits

A run that did not succeed adds two text lines after `run:`, for example:

```text
status: refused
ci: blocked
run: failed
failure: policy (task context)
hint: usually no changed source could be supplied to the model (every source was omitted, unsupported, or not authorized); see the context task's source omissions
```

`failure:` gives the failure class of the run, the first plan task that failed, and, when one was observed, a detail. `hint:` is a fixed one-line explanation for each class (`policy`, `resource_limit`, `transient`, `invalid_input`, `canceled`, `dependency`, `internal`), refined for some pairs of a class and a task. It describes what the class usually means, and it is not a diagnosis. A run that succeeded prints neither line.

### Route context too small

Every request reserves a byte-based upper bound on its input tokens, plus the output allowance. The input bound covers the payload, the trusted system channel and 256 framing bytes, plus the serialized `response_format` on a connection with structured output. A route whose declared `max_context_tokens` is smaller is not eligible, so a small model server does not truncate the prompt.

When that leaves no eligible route for the generation, the verification or an investigation turn, the run is refused with the failure `policy`. The JSON result then adds `"failure_detail": "route_context_insufficient"` and a `context_shortfall` object. The object has `required_tokens`, `estimated_input_tokens`, `max_output_tokens` and `declared_context_tokens` (the largest declared context among the routes that are too small). A member of a review set carries the same object. Both are absent in every other case. Text output reads as follows, with the counts in place of N, I, O and D:

```text
failure: policy (task context): route_context_insufficient
hint: the review needs up to N tokens (a byte-based upper bound: I input plus O output) but the route declares max_context_tokens D; raise max_context_tokens on the route and the model server's context length to at least N (docs/named-local-runtimes.md#context-length)
```

Raise the declared context of the route and the context length of the server together. See [named local runtimes](named-local-runtimes.md#context-length).

### Exhausted model output

The adapter classifies a model response as the route failure `output_exhausted`, not as a malformed response, when the response stops at the output token limit without a complete answer. The limit is `finish_reason: length`, or a Responses `incomplete` result for `max_output_tokens`. In this case the response has no answer text, or its answer text is not one complete JSON value, because the model had not finished its document. Reasoning models do this when they spend all or most of the output allowance on their reasoning trace.

The run failure stays `internal`. The JSON result adds `"failure_detail": "model_output_exhausted"`, and the field is absent otherwise. Such a reply is a completed provider response. So the failed attempt keeps the usage that it reported, under the same checks and profile rules as the usage of a successful reply (the OpenCode console profile withholds native usage from both), and its cost settles from that usage as for a successful attempt. An exhausted reply that reported no usage, or usage that those checks refuse, keeps unknown usage, and the whole reservation of the attempt stays held. Text output reads:

```text
failure: internal (task verification): model_output_exhausted
hint: the model used its whole output allowance, usually on reasoning, before finishing its answer; choose a non-reasoning model for this role or raise the review output allowance (setup bootstrap init --max-output-tokens)
```

The command returns unchanged a response that stops at the limit with a refusal, or with one complete JSON value. The document parser then refuses any answer that did not stop normally, and the run fails with `internal` and without this detail.

The allowance for the output of each request is the `max_output_tokens` of the runtime policy. Bootstrap writes 4096, or 16384 for OpenRouter, within what every pinned endpoint allows ([what setup reads](openrouter-zdr-profile.md#what-setup-reads)). It is separate from the declared output capacity of each route (`--output-tokens`). `trestle setup bootstrap init --max-output-tokens N` writes a larger allowance, from 4096 up to the declared `--output-tokens`. It works for local and remote providers, and the `trestle init` wizard accepts it as a flag. For priced routes, the cost reservation for each request uses the same allowance and must fit `--max-cost-micro-usd`.

The built-in HTTP client gives each request a deadline of two minutes for every 4096 tokens of its output allowance, with a minimum of two minutes and a maximum of five. A 16384-token allowance therefore gets five minutes. The `--timeout` of the review still ends the request earlier. See [OpenAI provider](openai-provider.md).

The JSON uses `open-trestle/local-git-model-review-result`. Every run that opened writes schema version 6. Version 6 keeps every field of versions 1 to 5 and adds [`token_usage`](#token-usage), except for the investigation fallback that [Token usage](#token-usage) names.

A result that reports no opened run (`run_status` `not_opened` or `unknown`) carries no token usage. It keeps version 1 (version 2 with `--investigation-policy`, version 3 with `--profile`). The exception is a [spending-limit refusal](#spending-limits), which is version 6, because `failure_detail` exists only there. Earlier builds wrote an opened run as version 1, as version 2 with `--investigation-policy`, as version 3 with `--profile`, as version 4 with finding guidance, or as version 5 with [style recommendations](#style-recommendations). A result of version 1 to 5 carries no `token_usage`.

When at least one verified finding carries a category, the result adds `finding_guidance`. It has one entry for each categorized finding, in diagnostic order. Each entry has `finding_identity` (the `source_identity` of the diagnostic finding), `category`, and, when the generator offered one, `fix` with `fix_authority: unverified_model_guidance`. The result keeps the `specialist` object of a `--profile` run. Text output adds `category:` and `fix:` lines after each such finding.

The verifier checked the claim of the finding, not its category or its fix. The category is the advisory label of the generator. The fix is model text that is printed and not applied, and it is not part of the diagnostic set. SARIF carries it only as a labeled result property. The model-result evaluation import and the retained-memory feedback review accept version 4 and version 6 results without a specialist, and they ignore the guidance.

### Provider refusals

When a provider answers a model request with an HTTP refusal, the command classifies it by the status alone. It discards the error body unread. Every OpenAI-compatible request profile uses the same mapping:

| HTTP status | Route failure | Run failure | Retried | `failure_detail` |
|---|---|---|---|---|
| 400, 405, 415, 422 | `request_rejected` | `policy` | no | `provider_request_rejected` |
| 401 | `authentication` | `policy` | no | `provider_authentication_failed` |
| 402 | `payment_required` | `policy` | no | `provider_payment_required` |
| 403 | `authorization` | `policy` | no | `provider_authorization_denied` |
| 404 | `model_unavailable` | `policy` | no | `provider_model_unavailable` |
| 410 | `model_retired` | `policy` | no | `provider_model_retired` |
| 429 | `rate_limited` | `transient` | twice on the same route, inside the task attempt | `provider_rate_limited` |
| 503 with a `Retry-After` in seconds | `rate_limited` | `transient` | as 429 | `provider_rate_limited` |
| 408, 504 | `timeout` | `transient` | no | none |
| 413 | `budget_exhausted` | `policy` | no | none |
| other 5xx | `provider_server` | `transient` | no | none |
| 200 with a reply the adapter refuses, or a status no other class names (for example 409) | `invalid_response` | `internal` | no | `provider_response_invalid` |

A `policy` run is `refused` with the CI disposition `blocked` and exit code 4, so a refusal that the provider repeats on every request is attempted once. A `transient` run is `failed` with `error` and exit code 1.

Generation and verification keep one task attempt each. A 429 means that the provider refused the request before processing it, so the model handler retries it on the same route, at most twice, inside that attempt. A 503 that names a `Retry-After` in seconds is the same refusal and is handled the same way. A 503 without one, or with an HTTP date or zero, stays a `provider_server` failure and is not retried.

Each retry waits for the `Retry-After` of the provider, but at least the fixed retry delay of the task (one second), which also applies to a 429 without `Retry-After`. If the `Retry-After` is beyond 15 minutes, or would end after the `--timeout` deadline of the review, the command does not wait, and the task fails at once.

Each retry is its own route attempt. The audit ledger claims, completes and settles it. The command claims it no sooner than its delay after the refusal, and it takes over the cost reservation of the refused attempt, so the reservation is never made again or exceeded. The provider processed nothing, so a rate-limited attempt records known zero usage and settles at zero cost. A review that needed a retry keeps the token usage of that stage, and the cost of the run stays known when the final attempt reports usage. No other failure is assumed to cost nothing. When the second retry is rate-limited too, the review fails as `transient` with `provider_rate_limited`.

The command records the detail only when the most recent model request that the provider answered was refused that way, and that refusal is the recorded failure of the run. A credential that could not be read before sending records none, and neither does a rate limit that a later attempt outlived. Text output names the failing task, the detail and a fixed hint, for example:

```text
failure: policy (task candidates): provider_payment_required
hint: the provider refused the request for billing: add credit or a subscription to the provider account, or choose another route
```

```text
failure: policy (task verification): provider_model_retired
hint: the provider no longer serves this model: choose a model the provider lists as available and re-run setup
```

A provider can reject the request itself as invalid. It does so with HTTP 400 or 422 (for example for an unknown model ID, which OpenRouter answers with 400, or for a parameter that the model or endpoint does not accept, such as structured output or the requested output allowance), or with 405 or 415 (an endpoint that does not take the method or the media type). The command records `provider_request_rejected`. The same request is rejected every time, so it is not retried, and the run is refused with exit code 4:

```text
failure: policy (task candidates): provider_request_rejected
hint: the provider rejected the request as invalid, for example an unknown model ID or a parameter the model or endpoint does not accept: check the model ID, the endpoint and its transport, and that the model and endpoint accept structured output and the requested output allowance; then re-run setup
```

A provider can answer with HTTP 200 and a reply that the adapter refuses. Such a reply is malformed or truncated JSON, an empty or oversized body, a Chat Completions reply with an unrecognized field (for OpenRouter, in the answer rather than in its routing metadata), a model other than the route's, or another document that the strict parser does not accept. A provider can also answer with a status that no route failure class names (for example 409; see [OpenAI provider](openai-provider.md)). In both cases the run keeps the `internal` failure. The run is `failed` with `error` and exit code 1, and it records `failure_detail` `provider_response_invalid`. The detail names neither the reply nor any of its fields:

```text
failure: internal (task candidates): provider_response_invalid
hint: the provider answered, but its reply did not match what Open Trestle accepts, for example malformed or truncated output, an unrecognized field or an unexpected HTTP status: run the review again; if it repeats, choose another model or route and report it
```

A reply that stopped at the output limit (`model_output_exhausted`, above), and a request that the adapter could not build or send, record no such detail.

A reply that the adapter accepted and that stopped normally can still have an answer that the review then refuses. The command records `failure_detail` `model_output_invalid` with the same `internal` run failure. This covers an answer that is not one JSON document (for example JSON wrapped in raw chat-template tokens such as `<|channel|>`, or with a raw control character inside a string), a refusal, a document of the wrong shape, and a document that the review rules refuse (for example a location or evidence that the request does not allow, or a verdict for a candidate that it did not name). The command repairs nothing.

There is one exception. On an OpenRouter or Ollama Cloud sign-in route, the command removes a single outer Markdown code fence (with no language or with `json`) around the whole answer, before it applies the same strict checks. Some endpoints that list structured output still fence their JSON. The command refuses any other wrapper, such as raw chat-template tokens. The detail names neither the answer nor any of its fields:

```text
failure: internal (task candidates): model_output_invalid
hint: the model's answer was not a valid review document (for example malformed JSON, the wrong shape or a refusal): run the review again; if it repeats, choose another model
```

A complete document in a reply that stopped at the output limit or at a content filter, and a host input that fails its own check, record no detail.

A member of a review set carries the same `failure_detail` and `member hint:` line. The other hints are:

- 404: "the provider does not serve this model at this endpoint: check the model name and endpoint, choose a model the provider lists as available, and re-run setup".
- 401: "the provider did not accept the credential: check the API key the route names (for ollama-signin, run `ollama signin`), then retry".
- 403: "the provider refused this account access to the model or endpoint: check the account's access, or choose another route".
- 429: "the provider rate-limited the request on its last attempt: wait and run the review again, or choose another route".

On an OpenRouter route, a 404 records `provider_no_allowed_endpoint` instead. Its hint says that a model without zero-data-retention endpoints is refused when the setup or the OpenRouter account or key requires zero data retention (see [OpenRouter zero data retention](openrouter-zdr-profile.md#when-openrouter-refuses-a-request)). A result whose policy has an OpenRouter route that does not require zero data retention lists the limitation `openrouter_zero_data_retention_not_required`. `failure_detail` takes these values in result schema version 6.

A daemon run is classified the same way. Its generation or verification task records the detail as its failure reason, which has no content, in task completion v3, the v7 `task_failed` event and receipt v3. The token is the same `provider_*` token. `provider_request_rejected` appears only with the failure `policy`, and `provider_response_invalid` and `model_output_invalid` appear only with `internal`.

`trestle runs status` prints the detail on stderr, for example `runs status: task candidates failed: provider_payment_required (the provider refused the request for billing)`, and a `hint:` line with the action. The TUI prints a `Reason` line and a `Hint` line, the web console prints a labeled reason and hint, and the ACP review-state message has a `Task failure` line. A daemon run retries a rate limit the same way, and not past the execution deadline of the task.

At startup, the daemon checks the model audit of a failed run, for a generation that was rejected for the shape of its document or for an exhausted model lease. These startup proofs accept the same shape before and after the retention of the run lapses: at most two refused attempts, each claimed, completed without a response and settled, then the final attempt. Each retry claim names the selection, the refused outcome and its retry decision. While the artifacts of the run are retained, each retry claim must also carry the identity that the gateway grants for that lineage from the authorization of the input. Any other audit shape stays quarantined at startup.

### Spending limits

An API key that a remote route uses can have a [spending limit](spending-limits.md). When the spend recorded in the current period is at or over that limit, the command refuses the review before it starts. It refuses before it opens the objects folder, before it reads any credential for model dispatch, and before it sends any request. The result is version 6 with `status` `refused`, `ci_disposition` `blocked`, `run_status` `not_opened`, `failure` `policy` and `failure_detail` `spending_limit_reached`, without `token_usage`, and the exit code is 4. Text output reads:

```text
failure: policy: spending_limit_reached
hint: the spend recorded for an API key this review uses has reached its spending limit for the current period, so the review was not started and nothing was sent: run trestle usage to see it, then raise or clear the limit (trestle usage set, trestle usage clear) or wait for the next period; the figures are Open Trestle's upper-bound estimate at the highest pinned price, not a bill, and the limit is best effort, so your provider's own limit is the guarantee
```

A review whose worst case could pass a limit runs with a warning. After a run that sent at least one request, the command appends one entry to the local usage ledger. The entry is the settled `actual_cost_micro_usd` when `usage_known` is true. Otherwise it is the total over every request that the session saw sent, each at its settled cost or, when its usage is unknown, at the cost that was reserved for it. A crossed alert percentage prints one line.

These lines go to standard error, with a note that the figures are an upper-bound estimate at the highest pinned price and not a bill, and that the limit is best effort. Text output also ends with the state of each limited key.

A review set warns once, before its first member, for every review that it may run (the general review and up to `--max-specialists` specialists). It checks each member before the member starts, and it runs specialists concurrently only when no limited key could reach its limit during the wave. A member of a review set that is refused at the limit carries the same detail and `member hint:` line, and it stops the set.

Results do not carry spending figures. See [spending limits](spending-limits.md).

### Token usage

A version 6 result reports `token_usage`. This is the input, output and cached-input tokens that the provider reported, summed over every route attempt that the run claimed, with `generation` and `verification` objects of the same shape. A completed review whose two attempts each reported 100 input and 100 output tokens reads:

```json
"token_usage":{"known":true,"route_attempts":2,"input_tokens":200,"output_tokens":200,"cached_input_tokens":0,"generation":{"known":true,"route_attempts":1,"input_tokens":100,"output_tokens":100,"cached_input_tokens":0},"verification":{"known":true,"route_attempts":1,"input_tokens":100,"output_tokens":100,"cached_input_tokens":0}}
```

The fields mean the following:

- `route_attempts` is the number of claimed attempts that were summed. A direct review claims one generation attempt and one verification attempt, plus one for each retry on the same route after a [rate limit](#provider-refusals) (at most two for each stage). A run with `--investigation-policy` claims one for each turn.
- `input_tokens` includes `cached_input_tokens`, as providers report them. The counts are the report of the provider, not a tokenization by Open Trestle, and they carry no content.
- `known` is true only when every summed attempt reported usage. Otherwise it is false, and the three counts are absent, never zero, for example `{"known":false,"route_attempts":1}`. This happens when the provider sent no usage, when the response was refused before its usage was accepted, or when no adapter result was observed for a claimed attempt. Among the failed dispatches, an [exhausted reply](#exhausted-model-output) can carry usage, and a rate limit (429, or 503 with a `Retry-After`) records known zero usage. Any other HTTP error, a transport failure, or a reply that the adapter refuses as invalid counts as unknown.
- For a successful attempt, the command reads the usage from the route execution that the run recorded. For any other claimed attempt, it reads the usage from the adapter result that the session observed for it in the same process. A generation that was dispatched but whose response was refused as malformed therefore still counts the tokens that it reported.
- In a run with `--investigation-policy`, each recorded turn counts under its role, and each entry of `investigation.turns` carries its own `input_tokens`, `output_tokens` and `cached_input_tokens`. A recorded turn always has known usage, because its cost is known. A claimed turn without a turn record has no known stage, so both stage objects are then unknown, while the total can still be known.
- `usage_known` and `actual_cost_micro_usd` cover the same claimed attempts. `actual_cost_micro_usd` is the sum of their settled actual costs, and `usage_known` is true only when every attempt has a known settlement. A recorded execution contributes its reconciliation. Any other attempt contributes the actual cost that its reconciliation derives from the observed usage (the same pricing calculation), and only when the run recorded that reconciliation. So a failed attempt that reported usage and was settled from it, such as an exhausted reply, keeps the cost known. In a direct review, `usage_known` equals `token_usage.known`, unless an attempt that reported usage was never settled. A run with `--investigation-policy` also requires the sum to equal the settled total of the route owner (`investigation.known_cost_micro_usd`).

Text output adds one line before any `style:` line and `limitations:`:

```text
tokens: input=200 output=200 cached_input=0 over 2 route attempts
tokens: unknown over 2 route attempts (not every attempt reported usage)
```

A result without `token_usage` reports no token use. This is a result that never opened a run. It is also the fallback that the command writes when reading back or closing a run with `--investigation-policy` failed before its usage was read, which keeps version 2 or 5. SARIF does not carry token usage.

The model-result evaluation import accepts a completed version 6 result only when its `token_usage` has exactly one generation attempt and one verification attempt, each a usage report that an adapter could return, with counts that sum to the totals and with `known` equal to `usage_known`. The retained-memory feedback review accepts version 6 and ignores the counts. A member of a [review set](#specialist-review-set-opt-in) carries the `token_usage` of its own result.

### Style recommendations

When a changed language has a style detector, but the base tree of the review declares no style that governs it, the result recommends a standard style. The command reads the base tree as it does for [`--specialists auto`](agent-profiles.md#declared-style-in-local-reviews): root-level style configuration files only, not the head. A style configuration that a change adds therefore does not silence the recommendation for that change. EditorConfig alone does not count, because it covers only whitespace basics. The recommendations come from a fixed table, not from a model:

| Changed language | Recommendation |
| --- | --- |
| Go | gofmt and Effective Go (in practice `go.mod` always declares it) |
| Python | PEP 8, enforced with Ruff or Black |
| JavaScript, TypeScript, Vue, Svelte | Prettier with ESLint |
| CSS, HTML, JSON, YAML, Markdown | Prettier |
| C, C++ | Google C++ Style through clang-format (`BasedOnStyle: Google`) |
| Rust | rustfmt |
| Ruby | RuboCop and the community Ruby Style Guide |

Java, Kotlin, C#, PHP, Scala, Swift, shell, SQL and TOML get no recommendation. Open Trestle has no style detector for them, so it cannot tell whether such a repository declares a style.

The command counts changed files for each language. As in specialist routing, it does not count vendored and generated files, removed files, or the dependency lock files that package managers generate (`package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lock`, `Cargo.lock`, `Gemfile.lock`, `poetry.lock`, `uv.lock`, `Pipfile.lock`, `composer.lock` and `go.sum`). Text output adds one line for each language before the `comprehensive clearance: false` line, for example:

```text
style: no declared Python style for 3 changed files; consider PEP 8, enforced with Ruff or Black, and commit its configuration
```

JSON keeps every other field (including `finding_guidance` and the `specialist` object of a `--profile` run). It adds `style_recommendations` in version 6, as it did in version 5. This has one entry for each language, in the order of the language tokens. Each entry has `language` (the routing token, such as `python` or `cpp`), `changed_files`, and `recommendation` (the text from the table). The recommendations use exactly the base style configuration files that the change-features document of the routing carries.

A recognized base style configuration file can be unreadable. This happens when it is over 64 KiB, is not valid UTF-8, is beyond the first 256, or is past the 1 MiB change-features bound. The declared style is then unknown only for the languages that this file could govern, by any style that its name can declare. An unread `pyproject.toml` affects Python, an unread `package.json` affects the languages that Prettier governs, and an unread `.editorconfig` affects none. The command lists those languages in `style_withheld` (`language`, `changed_files`) and does not recommend them. Every other language is still recommended, and `style_configuration_unread` gives the number of unread files. Text reads, for example:

```text
style: no declared TypeScript style for 1 changed file; consider Prettier with ESLint, and commit its configuration
style: declared Python style unknown for 1 changed file; a base style configuration file that may declare it was not read, so no recommendation is made
style: 1 base style configuration file was not read (over 64 KiB, not valid UTF-8, beyond 256 files, or past the 1 MiB change-features bound)
```

A result without any of these fields has no style advice.

A recommendation is advice only. It is not a finding, and it does not block. It does not change `status`, `ci_disposition`, the exit code under any [exit-code policy](#exit-code-policy), the source coverage or `comprehensive_clearance`. SARIF carries it at run level only, as the `trestleStyleAdvice` property and as `note` notifications (see [SARIF output](#sarif-output)), not as a result with a location. A result with `--investigation-policy` and advice keeps its `investigation` object. A review with `--specialists` reports the advice of the general review once (see [Specialist review set](#specialist-review-set-opt-in)).

A run that failed before it recorded its change model reviewed nothing, and it carries no style advice, as it carries no findings. When the recorded change model, its snapshots or a base style configuration file cannot be read back, the advice is reported as unavailable and is not left out. JSON adds `style_advice_unavailable: true` (with no other style field), and text reads `style: advice unavailable; the recorded change or base style configuration could not be read back`.

The model-result evaluation import and the retained-memory feedback review accept version 5 and version 6, and they otherwise ignore the advice. Both refuse advice that no review records, using one validator, `agentprofile.RecordedStyleAdvice.Validate`. They refuse a language without a style detector, a recommendation other than its table text, languages that are out of order, repeated, or both recommended and withheld, a withheld language without an unread count, and an unavailable marker beside other advice.

Two optional counts report advisory accounting of the repository context, without changing `status`, `ci_disposition` or source coverage:

- `instruction_context_omitted` counts base-tree instruction files that were not supplied as `repository_context`. A file may be changed or deleted in the head, truncated, oversized, unauthorized, or over budget. The count comes with the `instruction_context_omitted` limitation, and SARIF carries it as `trestleInstructionContextOmittedCount`. These are not source omissions, so they do not make a review `incomplete`.
- `repository_context_anchor_candidates_omitted` (with the limitation of the same name) counts the model candidates that the command dropped because they were located in an instruction file and not in reviewed code. From generation context version 8, it also counts candidates located in the `removed_lines` source of a deletion point. The rest of the batch is kept.

Both fields are absent when they are zero.

`agent_configuration_sources` and `instruction_like_sources` count the sources of the generation context that were flagged as repository AI material (agent instruction files, skills, prompts, agent configuration) or as instruction-like text. Text output adds `ai material in review context: agent_configuration=N instruction_like=M (reviewed as code, never followed)`, and SARIF adds `trestleAgentConfigurationSourceCount` and `trestleInstructionLikeSourceCount`. They are attention signals only. They add no limitation and never change `status`, `ci_disposition` or coverage. Both are absent when zero. See the [prompt-injection boundary](prompt-injection-boundary.md).

The receipt also includes the actual lineage of tasks and the journal, the identities of the model route, context and request when they are available, the audit subjects, and the existing canonical diagnostics. The command adds no prompts, source artifacts, credential values or configuration paths to the receipt. Text includes the locations of findings and the declared limitations. The JSON is at most 256 KiB, and the text is at most 64 KiB. The command builds the output before it writes. An error in encoding or a short write fails the command and does not truncate a set of findings.

The exit codes are in the [exit table](#exit-codes) at the top of this page. By default there is no exit-0 branch, and `--exit-code-policy` is the explicit opt-in (see [Exit-code policy](#exit-code-policy)). Unknown final usage after an incomplete model dispatch is not reported as a known zero cost. The receipt reports an aggregate cost only when every claimed attempt has a known settlement (see [Token usage](#token-usage)).

The default capacity for artifacts is 4096 objects, and library callers may choose 1 to 16384. This is a bound on the count, not a promise about total resident memory. The existing limits for source, context, provider, journal and diagnostics also apply. A session permits at most 1024 issued preparations. The command creates no background admission and no persistent storage.

## Non-Go files and repository instruction files

Model review reviews changed text outside `.go` files, and it sees the instruction files of the repository itself. Non-Go hunks that are valid UTF-8 are sent as changed hunks, and semantic analysis is recorded as unsupported for them. The command omits lock files, vendored files, minified files and binary files, with a named reason.

The command adds the root `AGENTS.md`, `CLAUDE.md`, `.github/copilot-instructions.md` and `.trestle/review-instructions.md` of the base tree as bounded advisory context (8 KiB per file, 16 KiB in total, with truncation recorded). It does this only when the head holds a byte-identical copy. The head tree is never their source. A change in the head to one of these files is reviewed as a changed hunk, and the base copy is then omitted as `repository_instruction_changed`. A file that is absent from the base adds nothing. These files are repository data, and they cannot override the review instructions (see the [prompt-injection boundary](prompt-injection-boundary.md)). The exact rules are in `docs/context-assembly-handler.md`.
