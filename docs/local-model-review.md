# Local model review

`trestle local-git model-review` is an explicit request for model calls. It does not
change `local-git review`, which remains deterministic. This command cannot publish
a forge review or create a required check. For private source, prefer a local model
or a provider whose zero-data-retention terms and account settings you have
verified. Route-policy checks and `store: false` cannot prove how a provider
retains or uses data. `--egress policy-approved` can send sanitized, scanned
selected source to an approved remote route (see Authority and egress below and
[remote model review](remote-model-review.md)).

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

Use separate flag/value pairs. Repeated flags, equals-form flags, missing values,
unknown flags, and equal revisions are refused. SHA-1 and SHA-256 full commit
digests are supported. The timeout must be between one second and 15 minutes.
JSON is the default; `--format text` selects a short human-readable summary.
`--object-store` is optional. Its only accepted values are `loose-only` and
`loose-and-pack-index-v1`. When it is absent, the command keeps the historical
loose-object-only behavior. There are no publish, resume, state, or existing-run
identity flags.

## Ordinary checkout source selection

Instead of the object-root and three revision flags, select two immutable commits
from an ordinary local checkout:

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

`--base` and `--head` are both required. Each accepts `HEAD`, an exact full
lowercase commit digest, or a full `refs/heads/...` or `refs/tags/...` name.
There is no default base, inferred merge base, short branch name, revision
expression, index review or dirty-worktree review. Annotated tags must resolve
to commits. Equal selected commits refuse. Do not combine checkout selection
with `--objects-root`, revision flags or `--object-store`.

This explicit source form requires installed Git supporting `--no-lazy-fetch`.
Git resolves the shared object directory (including linked worktrees), object
format and selected commit IDs. The existing immutable reader then authenticates
those exact objects using `loose-and-pack-index-v1`; its pack, alternates, missing
object, symlink and gitlink restrictions still apply. Ref changes after selection
do not relabel acquired evidence. Concurrent object removal can make a review
incomplete. No atomic checkout snapshot or origin authentication is claimed.

Preparation runs no shell, fetch, checkout, filter, textconv, hook, credential
helper or maintenance command. It clears inherited Git overrides and global/system
configuration, disables lazy fetching, replacements and transports, and bounds
metadata output and execution time. Repository configuration and includes remain
ordinary same-user metadata reads; do not point it at an untrusted checkout if
those reads are not permitted. No provider credential is resolved by preparation.
The subsequent model review still uses the explicit protected policy and egress
checks. This convenience form is foreground-only; it does not enroll a checkout
as a durable daemon source root or grant publication authority.

## Headless CI use

`trestle ci --format=json|sarif PATH` reviews a local fixture file through the
deterministic fixture path. It does not select an arbitrary checkout or invoke
models. For noninteractive model-backed review of a checkout, use the existing
foreground command below. It needs no terminal prompt and creates no durable
run or publication effect.

Prepare both commits in the checkout before this command. Set `BASE_COMMIT` and
`HEAD_COMMIT` to distinct full lowercase commit digests for the intended review;
there is no inferred merge base or fetch. Set tenant and repository IDs to the
scope approved by your operator. Provision the protected route inventory, runtime
policy and any required credential references separately. They must bind the
approved generation and independent-verification pair; this command does not
approve them or choose defaults. Use the supported configuration preparation
steps below rather than hand-constructing identities.

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

Replace the example paths and identity labels with approved values. The repository
identity fields describe the selected repository; they do not authenticate an
origin or trigger a network request. Checkout mode must not be combined with
object-root, revision-digest or object-store flags. The CI runner needs the
supported installed Git version and permission to read the selected objects.
No repository hooks, credential helpers, fetch, source writer or publisher is
run by this command. The explicitly selected model routes are contacted only
through their existing policy and credential boundaries. This example uses
`local-only`, which refuses remote routes.

Capture stdout as one terminal JSON receipt and retain the process exit status.
The receipt uses `open-trestle/local-git-model-review-result`, schema version 6
for every run that opened, which adds [token usage](#token-usage) to the fields
of versions 1 to 5, and version 1 for a request that never opened a run (see
[Results and limits](#results-and-limits)); inspect `status`, `ci_disposition`,
`run_status`, `limitations` and `diagnostics` together. A succeeded run means the pipeline finished, not that the repository
is clear. Verified findings use `ci_disposition: blocked`; no candidates,
incomplete evidence or abstention remain `inconclusive`. Refusal and failure
remain distinct terminal statuses. The [exit table](#results-and-limits) below
is authoritative: exit 4 covers findings or policy/resource refusal, 3 covers
no-candidate/incomplete/canceled outcomes, 2 is invalid intent, and 1 is failure.
By default there is no exit-0 branch, and no policy yields a comprehensive-clearance
result. The opt-in [exit-code policy](#exit-code-policy) can map a completed review
to 0 for CI.
Do not mask a nonzero status or treat an empty finding list as CI approval.

`--format` selects `json` (default), `text` or `sarif`. For a separately admitted
daemon run, `runs status --format json|sarif` retrieves the canonical result;
successful retrieval is not a review-pass decision. No export creates publication
permission. This headless example remains ephemeral and cannot resume an older
run. It does not establish model quality or live provider qualification.

### SARIF output

`--format sarif` writes one newline-terminated SARIF 2.1.0 document instead of the
JSON receipt, built from the same sealed result and the same SARIF types as the
other Open Trestle exports. It carries only independently verified findings:

| SARIF | Source |
| --- | --- |
| `ruleId` | `open-trestle/<category>` from the generator's advisory category, or `open-trestle/uncategorized` |
| `level` | verified severity: high and critical are `error`, medium is `warning`, low is `note` |
| `message.text` | `title: claim`, the text the verifier checked |
| `locations[0].physicalLocation` | repository-relative path and start/end line |
| `fingerprints` | `openTrestleVerifiedFindingId/v1`, the run-specific finding identity |
| `partialFingerprints` | `openTrestleFindingFingerprint/v1` (bound to the reviewed snapshot) and `openTrestleContentHash/v1` (path, category, title and claim only) |
| `properties` | `trestleCategory`, `trestleSeverity` (`error`, `warning` or `information`; the diagnostic severity, so high and critical are not distinguished), `trestleVerificationIndependence`, evidence IDs |
| `properties.trestleFixGuidance` | the generator's fix text, with `trestleFixAuthority: unverified_model_guidance` |
| run `properties` | `trestleModelReviewStatus`, `trestleCiDisposition`, `trestleRunStatus`, `trestleFailure`, sorted `trestleLimitations`, candidate/verified/rejected/inconclusive counts, source coverage and omissions, and `trestleComprehensiveClearance: false` |
| run `properties.trestleStyleAdvice` | the [style advice](#style-recommendations): `recommendations` (`language`, `changedFiles`, `recommendation`), `withheld`, `configurationUnread` and `unavailable`, absent when there is none; each advice line is also a `note` in `invocations[0].toolExecutionNotifications`, never a result |

Fix guidance is a result property, not a SARIF `fixes[]` entry, because the SARIF
schema requires every fix to contain machine-applicable `artifactChanges` and this
text is unverified prose that nothing applies. The verifier checked the claim, not
the category or the fix. `openTrestleContentHash/v1` stays equal across pushes when
the same path, category, title and claim recur, which lets code scanning match an
alert between runs; the model may word the same problem differently, so matching
is best effort. Results, rules, limitations and omissions are sorted, so identical
input yields identical bytes.

A run that was refused, could not read the change, was canceled or failed is still
valid SARIF: it has zero `results`, `invocations[0].executionSuccessful: false`
and one `error` notification that states the status and failure. An empty result
list from a run that completed with no candidates or with coverage gaps carries
`executionSuccessful: true` and a `note` or `warning` notification; none of these
is a clearance.

### Exit-code policy

By default the exit status follows the table in [Results and limits](#results-and-limits)
and is never 0. A CI step that must pass on a completed review without blocking
findings can opt in with `--exit-code-policy`. The flag changes only the process
exit status; the JSON, text or SARIF output, its `status`, `ci_disposition` and
`comprehensive_clearance: false` are identical under every policy. Exit 0 under
any policy is a pipeline decision, not a statement that the change is clear.

| Policy | Exit 0 when | Otherwise |
| --- | --- | --- |
| `default` (the behavior when the flag is absent) | never | 4, 3, 2 or 1 as in the table |
| `findings` | the run succeeded and no verified finding has high or critical severity (including no candidates, medium or low findings only, and a completed run with coverage gaps) | the default code: 4 for a verified high or critical finding or a policy/resource refusal, 3 when the change could not be read or finished or was canceled, 1 for an internal failure |
| `strict` | the run succeeded with no candidates at all, so no finding of any severity and no verification gap | the default code, so any verified finding is 4 and any coverage gap is 3 |
| `always-zero` | a valid result was written, including a refused or failed run | 1 only if the result could not be written; 2 for invalid usage |

A `findings` run whose diagnostics cannot be read back but whose status is
`findings` is treated as blocking. `always-zero` is advisory-only: pair it with
SARIF or the JSON status, because a green step then says nothing about whether the
review ran. Invalid usage (2) and output write failure (1) are never masked.

### Shallow and pull-request checkouts

Checkout mode reads only the objects of the two named commits. It does not
fetch and does not deepen a shallow clone. When a selected base or head cannot be
resolved, the run is `incomplete` with no model call, and stderr says why. In a
shallow checkout the message names the missing revision and the commands to run:
`git fetch --no-tags --depth=N origin <sha>` (N must reach the base) or, in GitHub
Actions, `actions/checkout` with `fetch-depth: 0`. A shallow clone that does hold
both commits reviews normally. A partial clone (`--filter=...`) can resolve the
commits but lack file contents; those are not fetched on demand, the run is
`incomplete`, and stderr suggests re-checking out without a filter. For a pull
request use `github.event.pull_request.base.sha` and `head.sha` as the pinned
commits. See [GitHub pull-request review](github-pr-review.md) and the
[example workflow](../examples/github-actions/README.md).

## Runtime policy route-pair boundary

The existing `local-git model-review` command and historical runtime policy v1 keep their current behavior. A single entry in `preferred_route_record_identities` is a ranking hint, not an exact verifier grant. Runtime policy v2 adds required `verification_route_record_identity`, which must name one record in the bound inventory and differ from the generation pin. The preliminary local generation route-pair resolver uses only that explicit grant, requires local-only zones with logging disabled, and checks both routes against eligibility and configured independence. Preferred-route hints cannot substitute for the grant or redirect the pair. Neither a schema-valid v2 document nor a preflight pair authorizes an actual model request. Generation and verification need separate eligibility checks for their actual sanitized requests, exact record pins, and no fallback before dispatch. The foreground `local-git model-review` command retains its historical behavior. The opt-in durable full-review daemon resolves the explicit v2 pair before constructing its generation worker; its generation and verification handlers still require separate authorization for each sanitized request. Preflight resolution alone is not dispatch authority.

## Object store profile

The default profile is `loose-only`. It reads only loose Git commit, tree, and
blob objects under the supplied `objects` root.

`--object-store loose-and-pack-index-v1` is an explicit opt-in for a narrow packed
Git subset. It still uses loose objects when present, and it may read `.pack` and
version-2 `.idx` pairs from `objects/pack` only when a loose object is genuinely
absent. The selected `--revision-algorithm` binds the packed reader to SHA-1 or
SHA-256 object names for that session.

The packed subset has deliberate limits:

- Acquired object types are commit, tree, and blob. Unused tag objects may exist
  in a pack, but tags are not acquired. A selected tag or a delta chain that
  resolves to a tag is refused.
- OFS_DELTA and REF_DELTA bases must be in the same pack. Thin packs with
  external bases are refused.
- Duplicate object IDs across admitted packs are refused. Repacking during a run
  can make the source invalid or incomplete.
- Multi-pack-index, promisor objects and alternates are unsupported by this
  reader. Refs and linked worktrees require the explicit checkout selection
  above; there is no Git subprocess fallback during object acquisition.
- The command validates selected bytes and bounded pack/index structure, but it
  does not claim an atomic repository snapshot. It also does not grant extra
  filesystem permissions or comprehensive source clearance.

Provider routes and credentials still come only from the supplied inventory,
policy, and the existing credential resolver. The object-store option adds no
provider configuration or credential defaults.

## Authority and egress

Supply both the existing route-inventory and runtime-policy JSON contracts. The
policy must bind the decoded inventory identity. Both files must pass the existing
`internal/fileauthority` owner, ancestor, mode, symlink, and replacement checks.
The loader checks bounded stable content and rechecks the pair after decoding.
Inventory input is limited to 8 MiB; policy input is limited to 1 MiB. Unsupported
ownership platforms fail closed. There is no environment-based policy fallback.

`local-only` requires local routes and canonical numeric loopback endpoints. The
existing local transport disables proxies and confines dialing. `policy-approved`
still applies the protected inventory and policy, and the direct review uses the
standard runtime generation and independent-verification handlers. They admit a
`private_remote` route, or a `brokered_remote` route with a current OpenRouter ZDR,
OpenCode Go or OpenCode Console declaration or an API-observed OpenRouter ZDR
witness (which has no window), only after separate Betterleaks scans,
a fresh zero-finding residual scan, artifact reload, and a handler-sealed dispatch
proof. A binary without injected scanner digests, or without the installed
scanner, therefore refuses remote requests before credential retrieval. Use the
packaged binary and installed scanner described in
[remote model review](remote-model-review.md), whose bootstrap writes the protected
remote configuration. Investigation and retained-memory requests remain local-only. Route approval, data classification,
logging restrictions, provider independence, capacity, and per-request cost budgets
remain in force. Provider credentials use only explicit protected-policy environment
references, through the existing credential resolver.

Repository and audit labels are host-supplied scope labels, not proof of Git
origin, forge authentication, or permission to publish. The opened source root is
bound to its session. Only the requested immutable Git commits are acquired. The
object-root path never invokes Git or falls back to the mutable worktree.
Explicit checkout selection invokes only the bounded metadata commands above. Without the
packed opt-in, pack-only repositories remain unsupported. With the packed opt-in,
only the narrow pack/index subset above is supported. Alternates, worktree
pointer files supplied as object roots, symlink/gitlink source entries, unavailable objects, and other
unsupported Git layouts do not produce comprehensive clearance.

## Chat Completions transport

In runtime policy v2, set a protected connection's `implementation` to
`openai_chat_completions` to select Chat Completions instead of
`openai_responses`. The endpoint remains the API base, for example
`http://127.0.0.1:8080/v1`. Changing implementation changes the policy and adapter
identities; recompute bindings and obtain any required exact approvals.

Chat sends `POST /v1/chat/completions` for that base, with the exact model
selector, a trusted system message, the authorized user payload, `max_tokens`,
and `stream:false`. It uses the same bearer credential resolver, request bounds,
locality checks, sanitization proofs and audit path as Responses. It does not
send tools or claim provider retention settings. Responses keeps its existing
wire format and identity. Neither transport activates or approves a route.

Only bounded text/refusal output from one assistant choice is accepted. The
returned model selector must match exactly. Tool calls, streaming and unsupported
fields fail closed. Model-specific `developer` roles or
`max_completion_tokens` profiles are not inferred. A compatible wire response
is not evidence of model quality, privacy terms or live server readiness. Test
your exact server and model before approving the route. The existing local
credential requirement remains; this transport does not add anonymous access.

For an explicitly opted-in local connection, set `local_structured_output: true`
in an explicitly versioned protected v6 JSON policy as a JSON boolean. It is supported only with
`openai_chat_completions`, a canonical numeric-loopback endpoint and no request
profile. Both bearer and explicit local no-auth configurations are supported.
Within v6, omitting the field or setting it to false produces the same bound
bytes and policy identity. Explicit v6 retains its own versioned identity; it
does not migrate historical v1/v2 policies. Versions 1 through 5 reject the
field even when false. Historical v1/v2 templates without the option still bind
to v2 with unchanged bytes and identities. V6 is generic only: named request
profiles and brokered, OpenCode Go or Console authorities are not accepted.

When enabled, Chat also sends `response_format` with `type: json_schema`,
`strict: true`, the fixed name `open_trestle_review` and the exact host-pinned
candidate, verifier or investigation schema validated from the authorized inner
request. It does not accept a caller-selected schema or change temperature.
True changes the policy, adapter and catalog identities; bind the changed
protected policy and obtain fresh exact approvals where required.

Dispatch refuses, before credential retrieval or HTTP, an approved reservation
below the larger of the normal host byte-based request estimate and the inner
payload bytes plus the trusted system channel bytes plus the serialized
`response_format` object (including its field wrapper) plus 256 framing bytes.
Route planning counts the same `response_format` bytes, which are
deterministic from the pinned schema, whenever a planning step's candidate
routes include a connection with this option: the generation and verification
route authorizers, the local generation route plan and each investigation turn
reserve the payload, the system channel and the schema framing, so
`estimated_input_tokens` need not carry that margin. A step reserves once for
all of its candidate routes, so a route without the option planned in the same
step is reserved the same way; an investigation decides per role, from the
pinned generation route and from the verification routes. Such an authorizer
binds `input_transport: local_structured_output` into its identity (the
verification authorizer moves to identity version 3 for it), and such an
investigation binds its role transports into the route owner and pipeline
profile identities (version 2 of each); without the option every estimate and
identity is unchanged. This estimate is conservative byte accounting,
not exact tokenization. Set a justified reservation that fits the route's
approved context capacity; no budget is increased after authorization.

Server support for these schema keywords is not assumed. Unsupported requests
fail through the existing transport and strict response checks, without a
simplified schema, retry or fallback. Schema transport does not establish
factual accuracy or qualify a model. Candidate coverage, evidence, usage,
tool-call and authorization checks remain unchanged.

## Local Responses configuration bootstrap

The files in [`examples/local-model-review/`](../examples/local-model-review/) are
illustrative bootstrap configurations, not measured live-readiness evidence. They
name a loopback OpenAI Responses-style endpoint at `http://127.0.0.1:11434/v1`.
At dispatch time the adapter sends `POST /v1/responses` with JSON containing
`model`, one user `input` item of type `input_text`, `max_output_tokens`, and
`store:false`. It sends `Authorization: Bearer <credential>`, `Content-Type:
application/json`, and `Accept: application/json`. The response must be a bounded
OpenAI Responses object with `object:"response"`, the selected model, status
`completed` or the supported `incomplete` reasons, and assistant `output_text` or
`refusal` content. OpenAI-compatible local servers vary; do not assume every
local server implements this protocol.

Before use, edit `routes.json` for your actual local server, model, capabilities,
content-logging posture, status, health, quota, pricing, and evidence manifest.
The example deliberately uses unknown or pending declarations where the repository
cannot measure reality. Any example declaration is illustrative operator input,
not empirical certification. Replace the credential reference with an environment
name that exists in your protected runtime environment; do not put credentials in
these JSON files.

The example `review_policy_identity` is a synthetic label, not a provenance or
quality certificate. Replace it with the stable identity used by your review
policy.

Then compute and bind the inventory identity with the native command:

```sh
trestle config inventory-identity \
  --route-inventory /protected/routes.json
```

The `decoded` result reports structural inventory and route-record identities
only. It does not establish policy binding, live health, quality, or execution
authorization. Use `config validate` separately to check the pair.

For a daemon generation/verifier pair, prepare a policy template and bind its
identities with the supported offline command:

```sh
trestle config bind \
  --route-inventory /protected/routes.json \
  --runtime-policy-template /protected/runtime-policy.template.json \
  --generation-adapter local-generation \
  --verification-adapter local-verification
```

Each adapter must select exactly one local record, and the adapters must differ.
The selected pair must satisfy the template's verification independence level;
this static check does not require live health or approval.
The command emits one runtime-policy-v2 JSON document for a historical v1/v2
template, or runtime-policy-v6 for an explicit v6 template. It never upgrades a
historical template to v6 or adds the schema option. It does not write
files, read credentials, contact a provider, approve routes, or change setup state.
Save the output as a new protected file before validation. No output file is
opened by the command, so the operator controls its path, permissions and any
replacement.

Empty, omitted or all-zero binding identities are placeholders. Existing nonzero
inventory, generation-pin and verifier identities must match the selected records.
Other policy values, including constraints, independence and connections, are
preserved. A v1 template cannot contain the verifier field; v2 and v6 templates
may omit it before binding. Only an explicit v6 template may contain
`local_structured_output`. Null values, unknown or duplicate fields, conflicting
bindings and ambiguous adapter selections are refused. Inputs must pass the
protected-file checks described above. Pending routes remain pending and cannot
be executed merely because binding and validation succeed.

For a historical v1 policy, copy the reported `inventory_identity` into
`runtime-policy.json` after editing the inventory. The shipped example pair is
already structurally bound. Leave `preferred_route_record_identities` empty unless
you intentionally pin or prefer records reported by the same inventory command.

After binding, validate the pair without provider calls:

```sh
trestle config validate \
  --route-inventory /protected/routes.json \
  --runtime-policy /protected/runtime-policy.json
```

Only after validation should you run `trestle local-git model-review` with the
same protected files. Identity and validation do not call the provider and do not
prove reachability, health, quality, policy conformance under live load, or review
quality. The model-review command is the explicit provider-call boundary and still
uses conservative non-zero exits for refused, canceled, failed, or inconclusive
runs. It cannot publish results.

## Retained advisory input (opt-in)

For an ordinary `local-only` review, add
`--retained-memory-input /protected/operator-feedback.json`. Do not combine it
with `--investigation-policy` or `--egress policy-approved`. Omitting the flag
keeps the empty memory index. The command does not discover nearby memory files.

The input is a read-only, operator-attested advisory snapshot. It contains only
`human_feedback` records with `user_controlled` taint. It is not acquired source
evidence, authenticated human authorship, or permission to publish. The normal
changed-path retrieval step selects records; loading a record does not guarantee
that a model sees it. Both generation and independent verification receive the
selected advice through the existing context pipeline.

Use the `open-trestle/retained-memory-input` schema version 1 envelope implemented
in [`runtimeconfig/retained_memory_input.go`](../runtimeconfig/retained_memory_input.go)
and its protected loader. This is not a free-form notes file. The loader checks
record identities, operator-note references, declared scope, repository identity,
and runtime-policy identity. The authoring command can build this contract from
an explicitly selected protected feedback file. It does not run review, resolve
credentials, call providers, or update other memory stores.

The example below authors path/text preferences for an explicit head. For
feedback on verified findings, use `--review-input` with a protected completed
foreground result instead of the two revision flags. That mode derives the head
and finding identities; it does not establish human adjudication. See
[Manual review feedback](local-feedback.md) for decision selectors, later opt-in
reuse, and exact-input removal with `--remove-input`. Removal requires the
matching review, scope and policy; it does not revoke copies or change past
results.

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

For this explicit-head example, all flags except `--format` are required. The
authoring command accepts only `--egress local-only`. `--timeout` must be one
second to 15 minutes. `--valid-for`
must use whole milliseconds, exceed the timeout, and be at most seven days. The
command samples the clock once after protected configuration and feedback load,
then sets each record's `observed_at` and `valid_from` to that millisecond.

The feedback file is a protected convenience JSON file, not the wire contract:

```json
[{"path":"src/file.go","text":"operator advisory text"}]
```

This path/text form is limited to 64 KiB, 1 to 16 records, exact `path` and
`text` keys, no unknown or duplicate keys, no comments, no trailing tokens, no
nested values, and no null,
boolean, or numeric values. Paths must be clean repository-relative printable
paths, not `.`, `..`, absolute, backslash-containing, or duplicated. Text must be
non-empty after trimming and may contain newline and tab. Hidden controls and
Unicode format characters are refused. The emitted `allowed_paths` sort ascending,
and records sort by `record_identity`.

The retained-memory JSON is written only to `--output`. The output parent must
already exist. The command refuses to create directories, overwrite, truncate, or
replace a file. Stdout is a content-free receipt with identities, counts, and
expiry only; it omits the output path and all advice text. Stderr uses stable
reason classes. If failure occurs after exclusive output creation, a partial or
complete output file may remain and is not removed automatically.

The scope must match the tenant and logical repository, actor `local-reviewer`,
visibility `exact`, and the single path prefix `.`. Its ref-set is the requested
head's versioned `RevisionIdentity.Identity()`, not the raw Git commit digest or
the new run ID. A file for a different head or runtime policy is refused rather
than relabeled. A later invocation reopens the same file and builds a fresh index;
it does not resume the previous run.

Limits include 64 KiB of raw input, 16 records and 16 allowed paths, 4096 bytes per
canonical record, 1024 bytes of text per record, 8192 total text bytes, and 32768
decoded string bytes including repeated keys and values. Records must have a
bounded validity window of at most seven days. Each must be fresh at admission
and expire strictly after the full configured review timeout. Even an unselected
record can cause this admission check to fail. Context expiry still prevents a
later model dispatch; no date is extended to finish a run.

The file is loaded after protected runtime configuration and before opening the
source root or resolving credentials. Existing owner, ancestor, symlink,
replacement, and group/world-write checks apply. These are integrity checks, not
a guarantee of confidentiality or an atomic filesystem snapshot. Use mode `0600`
and a suitable private directory for sensitive advice. The model-review command
never edits, curates, migrates, or deletes the input. Explicit removal uses the
separate authoring command described in [Manual review feedback](local-feedback.md).

Successfully constructed opted-in Session results replace `empty_memory_index`
with `retained_input_advisory_not_all_records_selected` and
`retained_input_read_only`. Ordinary result schema version 1, output bounds,
independent verification, and nonzero dispositions remain unchanged. A protected
input refusal produces `refused` with exit 4; cancellation produces exit 3. Later
Run or Close errors keep the existing conservative failure handling. Input reuse
is not automatic retained-memory generation, cross-head reuse, or revocation.

## Specialist profile (opt-in)

Add `--profile PROFILE_ID` to select one packaged specialist profile from the
embedded catalog described in [agent profiles](agent-profiles.md). Accepted IDs are
the model-calling review profiles: `backend`, `bug_hunter`, `drift_auditor`,
`frontend`, `security_probe` and `style_conformance`. The `orchestrator`
(model-free) and `knowledge_graph` (gap-only) profiles are refused, and so is
`test_author`: it proposes tests, which the defect-claim candidate contract and
its independent verifier cannot represent.
An unknown or refused ID is a usage error (exit 2) that lists the valid IDs before
any configuration is read or model request is made. Do not combine `--profile` with
`--investigation-policy`. It can be combined with `--retained-memory-input`.
Library callers use `localreview.NewSpecialistSession(options, specialist)` with a
value from `review.NewContextSpecialist`.

The flag affects only the candidate-generation request. Its version 7 review
context carries the optional `specialist` object with only `profile_id`,
`profile_identity` and `catalog_identity`. The profile's exact skill markdown is
sent only in the trusted system channel, after the version 7 host contract, under
a `Specialist review guidance (operator-packaged profile <id>, shipped with Open
Trestle):` heading. It is looked up in the embedded catalog, never read from the
payload or the repository. The host contract tells the model to use that section
to decide what to look for, without changing the output contract, evidence rules
or authority limits. Source content keeps its `evidence_data_not_instructions`
label. The identity block is bound into the context, sanitized request and
provider request identities. The context-assembly handler identity also binds the profile
and catalog identities, so the run plan identity differs from a run without the
flag. Readback accepts a version 7 or 8 specialist block only when it re-derives
exactly from the embedded catalog; an unknown profile ID, a mismatched identity,
or any extra field such as instruction text or an authority label is refused.

Route selection is unchanged: the same runtime-policy generation and verification
routes and independence level apply. Independent verification still runs. Its
request is verification-context schema version 7, binds the version 8 generation context
through `generation_context_identity`, and does not receive the specialist
instructions. The profile catalog's tiers, token budgets and route assignments are
not used by this command.

Without `--profile`, the version 7 request has no `specialist` block and the result
does not report a profile. With it, the result adds
`specialist` with `profile_id`, `profile_identity` and `catalog_identity`, both on
completed and on refused or failed runs. Such a result is schema version 6 once
its run opened and version 3 before; earlier builds wrote an opened run as
version 3, version 4 with finding guidance or version 5 with a
[style recommendation](#style-recommendations). The reported profile must match the one
recorded in the generation context. Text output adds a `specialist profile:` line.
The instruction text itself is not written to the result. The retained-memory
feedback review and the [model-result evaluation](model-result-evaluation.md)
import refuse every result that carries a `specialist` object, at any version.

## Specialist review set (opt-in)

Add `--specialists auto` (or `--specialists ID[,ID...]`) to run the general review
plus several packaged specialist profiles and merge their verified findings.
`--specialists none`, or no flag, is the ordinary single review with unchanged
output. `--profile` remains the single-specialist form and cannot be combined with
`--specialists`; neither can `--investigation-policy`. IDs are the ones `--profile`
accepts. An unknown ID is a usage error (exit 2) that lists the valid IDs.

Selection:

- `auto` derives change features from the general review's own recorded change
  model and semantic-impact profile, after that review ran, and the declared
  style from the root-level style configuration files of the base tree that
  review recorded, never the head (see
  [declared style in local reviews](agent-profiles.md#declared-style-in-local-reviews)).
  No model is called for selection and no Git object is read again. A base
  style that governs a changed language activates `style_conformance`. It
  calls the routing planner and keeps activated, planned profiles that may
  steer defect review, in descending
  priority (ties by profile ID). The rest are recorded in `selection.dropped`
  with a reason: `not_applicable` (model-free, gap-only, `test_author`, or no
  model call for this change), `max_specialists` (cut by the limit), or a planner
  omission such as `tier_unassigned`. Inactive profiles are listed in
  `selection.inactive`. If features are unavailable (for example the general
  review did not reach analysis), `selection.status` is `features_unavailable`,
  `selection.reason` names the general review's failed task (text:
  `status=features_unavailable (general review failed at <task>)`), and no
  specialist runs. When the general review recorded its change and analysis but
  failed later, the features summary is still derived from those artifacts, so
  languages and file classes are reported even if the plan is unavailable.
- An explicit list runs in the given order. It is never cut: a list longer than
  `--max-specialists` is a usage error.
- `--max-specialists N` (1 to 6, default 3) bounds how many specialists run. It
  needs an active `--specialists` value. It is not a spend cap on its own: every
  member is a full run bounded by the runtime policy's per-run `max_cost`, so the
  set's spend can reach (1 + N) × that `max_cost` (the general review plus N
  specialists).

Routes: every member uses the runtime policy's one generation and verification
route pair and its independence level. Per-profile route assignment is not
applied, and `selection.route_assignment` says so. The planner requires an
assignments document, so the command builds a minimal one that maps every tier to
the generation route the general review actually recorded and every verifier
tier to its recorded verification route (route selection is not re-derived), and
records that basis in `selection.plan`. If the general review recorded no route
pair, `selection.status` is `plan_unavailable` and no specialist runs. The plan's
tier and route choice is informational.

Execution is sequential: the general review first, then each selected specialist
as its own session and run with its own run identity, the same specialist
generation request as `--profile`, and its own independent verification (the
verifier never receives the profile instructions). The general review shares the
`--timeout` window with configuration loading, and each specialist gets a fresh
`--timeout` window, so model work is bounded by members × `--timeout`
(`bounds.max_model_wall_time_milliseconds`), plus at most
`bounds.member_cleanup_bound_milliseconds` of bounded close and readback per
member. No further member starts once the invocation is canceled or a launched
member's run did not succeed (refused, failed, canceled, or the source could not
be read); such members appear with `launched: false` and a `not_launched_reason`.
Nothing is retried.

Output is the `open-trestle/local-git-model-review-set` schema version 1 (JSON),
not the single-review result:

- `selection`: mode, status, features summary (identity, changed file count,
  languages, file classes, security signals, semantic gap count, public API
  changes, reference fan-out, and `style_configuration_unread` when base style
  configuration files could not be used for routing), plan identities,
  selected and dropped profiles with reasons, inactive profiles.
- `members`: one entry per member (`general`, then profile IDs) with status, CI
  disposition, run status, failure, `failure_task` and `failure_detail` (when the
  run did not succeed), `context_shortfall` (only with `failure_detail`
  `route_context_insufficient`), run, scope, plan and context identities,
  route record identities, independence, diagnostic set identity, usage and cost,
  the member result's [`token_usage`](#token-usage) (absent when the member's
  result reports none, as for a member that never ran), verification counts and
  limitations.
- `findings`: merged verified findings. Each group has one representative: its
  first finding in run order, replaced by a later member's finding of higher
  severity. A finding joins a group when it comes from a different member than
  the representative, has the same path and category, its line range overlaps
  the representative's range, and the words of its title and claim overlap the
  representative's by at least 0.3 (Jaccard over the words of at least three
  letters or digits, without common stopwords). Only the representative's range
  and words count, so a finding cannot join a group through a finding the group
  already absorbed, and a member's own findings are never compared with each
  other, because one member may report two distinct issues in one changed hunk.
  The group reports the representative (the most severe finding; ties: the
  earliest member), the narrowest contributing range, and every contributor
  with its own finding identity, severity and range. Matching is deterministic.
  Only members whose run succeeded contribute. The rule is a heuristic
  (`deduplication_is_heuristic`).
- `summary`, `bounds`, `limitations` and `comprehensive_clearance: false`.
- `style_recommendations`, `style_withheld`, `style_configuration_unread` and
  `style_advice_unavailable`: the general review's
  [style advice](#style-recommendations), once for the set
  and never per member, because every member reviews the same change against
  the same base tree. The fields are absent when the general review has no
  advice, so such a set keeps its earlier bytes. Text output adds the same `style:` lines
  before `limitations:`, and set SARIF the same run property and notes as a
  single review. The advice never changes the set's status, CI disposition or
  exit code.

Set status and CI disposition:

| Set | `status` | `ci_disposition` | Default exit |
|---|---|---|---|
| A member did not complete and a merged finding is error severity (verified high or critical) | most serious member status (`failed`, `refused`, `canceled`, `incomplete`) | `blocked` | 4 |
| A member did not complete, no error-severity merged finding | most serious member status | `failed` → `error`, `refused` → `blocked`, otherwise `inconclusive` | 1, 4 or 3 |
| Every member completed, merged findings not empty | `findings` | `blocked` | 4 |
| Every member completed with no candidates | `no_candidates` | `inconclusive` | 3 |
| Every member completed, otherwise | `incomplete` | `inconclusive` | 3 |

`complete` is false whenever a member did not complete. An incomplete set never
demotes a completed member's verified high or critical finding.

Text output starts with a summary (status, selection, dropped profiles, members
run, findings by severity and category, files analyzed/selected/omitted by the
general review), then the merged findings with a `contributors:` line. A member
whose run did not succeed shows its failure on its line, for example
`member: bug_hunter status=failed run=failed verified_findings=0 failure=internal
(task candidates)`, followed by `member hint: bug_hunter: ...`. SARIF
output is one run whose results are the merged findings, each with a
`trestleContributors` property; when some members did not complete, the results
still list the completed members' verified findings and an error notification
says the set is not a clean result, even when it lists no finding. If the
general member's report could not be read, the set records the limitation
`general_member_report_unreadable_source_coverage_unknown` and the notification
says that source coverage counts are unavailable.

Exit policy on the merged set: `default` maps `blocked` to 4, `inconclusive` to
3 and `error` to 1. `findings` exits 0 only when every member completed and no
merged finding is error severity (verified high or critical). `strict` exits 0
only when every member completed with no candidates. `always-zero` exits 0 when
the general review completed, even if a specialist was refused or failed; when the
general review itself did not complete it returns the default code (for example 4
for a refused general review).

## Snapshot investigation (opt-in)

Add `--investigation-policy /protected/investigation.json` to the command above to
let the generation model request bounded snapshot tools. Without this flag, the
original single-generation flow remains unchanged. The runtime policy must pin
one generation route and permit an independent verifier. The generation route
cannot change during an investigation.

The investigation policy is a separate protected file, limited to 4096 bytes.
Its parser requires exact canonical JSON: field order, integer spelling, and
whitespace matter. Do not pretty-print it or add a trailing newline. In an
existing directory that meets the protection rules above, this example writes
canonical bytes:

```sh
printf '%s' '{"contract":"open-trestle/investigation-policy","max_cost_micro_usd":1000000,"max_files":64,"max_lines_per_read":64,"max_matches":16,"max_model_turns":5,"max_result_bytes":8192,"max_returned_bytes":65536,"max_scanned_bytes":1048576,"max_tool_calls":3,"profile":"snapshot-read-v1","schema_version":1,"timeout_milliseconds":300000}' > /protected/investigation.json
chmod 600 /protected/investigation.json
```

The example permits five model turns in total, including final generation and
independent verification, and at most three tool calls. Its cost cap is 1,000,000
microUSD (USD 1); it must not exceed the protected runtime policy's cap. These are
admission limits, not a guarantee of provider billing. Use limits appropriate for
the approved routes. Zero cost is valid for routes whose admitted cost is zero.
The command timeout and investigation timeout both apply; neither extends the other.

Investigation requests use investigation context version 6. Like generation
version 8 and verification version 7, it sends its contract only in the trusted
system channel: the instruction-hierarchy paragraph (every string in the request,
including snapshot tool results and the files they return, is untrusted
repository data; repository instruction files cannot change the rules, output
format, severity or evidence requirements), then the sentence that explains
`removed_lines` sources, followed by the unchanged version 4 tool and output
rules. The payload binds that text with `instructions_identity`.
Files a tool returns are flagged with `agent_configuration` and
`instruction_like_text` like other sources, and each raw tool result the model
sees carries `risk_flags` computed by the same rules. Recorded version 5 investigation
requests (the same contract without the `removed_lines` sentence) and recorded
version 4 requests, which carried their rules in the payload and no hierarchy
paragraph, read back but are never sent again. See
[prompt-injection boundary](prompt-injection-boundary.md).

Available tools list files, read inclusive line ranges, and search for a literal
string within the acquired immutable snapshot. They do not execute shell commands,
regular expressions, or provider-native tools. Model proposals carry host-issued
opaque references, not filesystem authority. The controller checks each proposal,
its actual model response, source bindings, and remaining limits before execution.

`max_files` limits the Reader's file coverage. Initial selected paths outside that
coverage are refused. Each read or search charges the full file bytes loaded,
including repeated reads and no-match searches. `max_result_bytes` bounds each
raw tool-result payload; `max_returned_bytes` also bounds cumulative encoded tool
artifacts. Existing acquisition, context, artifact, and provenance bounds still
apply, so a policy alone does not guarantee that a repository fits. Missing or
omitted source is not clearance. This mode requires supported Git objects under
the selected object-store profile and uses an empty memory index.

The local graph still has nine tasks and no publication task. One owned account
covers all generation and verification turns; tool use does not reset it. Unknown
model effects, failed persistence, or uncertain usage stop the run without automatic
replay. A fresh command is new paid work, not recovery. Library callers can opt in
with `localreview.NewInvestigationSession(options, policy)`; each admitted run gets
a fresh bridge and acquisition owner. Root ownership and bounded Close rules are
unchanged.

Each model turn reserves the larger of `estimated_input_tokens` and the request
payload bytes plus the trusted system channel bytes plus 256 framing bytes, the
same estimate as single-generation review. A turn whose routes use
[`local_structured_output`](#chat-completions-transport) also reserves the
serialized `response_format` bytes. The turn record stores the system channel
bytes it reserved for under estimate version 2, and a structured-output turn
also stores its `response_format_bytes`; a standard turn omits that member and
keeps its encoding and identity. Every readback of a retained turn re-measures
both counts from the turn's own recorded request, using the contract version
that request records, and refuses a record whose counts its request does not
support. Turn records written
under estimate version 1 counted the payload alone; they read back with that
formula and are never re-estimated.

Opted-in results use schema version 6 once the run opened and version 2 before;
earlier builds wrote version 2, or version 5 with
[style advice](#style-recommendations). They include all retained turns and their
request, route, audit, and tool-result identities, rather than only the final two
model calls. Each turn also carries its provider-reported `input_tokens`,
`output_tokens` and `cached_input_tokens`, and `token_usage` sums the turns by
role (see [Token usage](#token-usage)). Known observed cost remains visible when
total usage is unknown.
On terminal failure, an actual scoped diagnostic set may remain as historical data
with `diagnostics_not_terminal_success`. It grants no readiness or success. If the
whole optional set cannot fit, it is omitted with
`diagnostics_omitted_output_limit`; it is not partially truncated. JSON/text limits
and the nonzero exit dispositions below still apply. Sealed result bytes remain
readable after a successful Close without retaining live execution authority.

## Execution and ownership

The foreground session uses the real source, change, analysis, memory, context,
generation, independent verification, and readiness handlers. Its local graph has
nine tasks and no publication task. The artifact store, audit ledger, diagnostic
store, journal, coordinator, Runner, LocalControl, and finalizer are process-private.
Without retained advisory input, the memory index is empty and explicitly reported
as a limitation. Retained input changes only this ordinary retrieval source.

Context assembly, generation, and verification have one attempt each. Default
deterministic tasks have three attempts with a one-second retry delay. Leases are
30 seconds. Nominal renewal is 10 seconds; a short configured timeout clamps the
interval once to at most half that timeout. The parent deadline is never extended.
Interrupts and caller cancellation reach source acquisition and model HTTP work.

Every actual handler spawn is registered before its goroutine starts. Known
claim-time cancellation suppresses the handler. A worker cancels and waits up to
two seconds for cleanup before returning. `Runner.Wait(ctx)` can check a later
drain. Non-cooperative work returns `ErrWorkerDrain`; it is not force-killed.

For library callers, `localreview.NewSession` takes ownership of the already
opened `*os.Root` only on success. `Close(ctx)` cancels work and closes the root
only after safe drain. A failed drain retains ownership for a later explicit
Close. There is no cleanup daemon. The CLI renders its result only after a
successful close. Drain or close failure overrides the terminal disposition.

A session serializes admission and refuses duplicate, relabeled, or already
claimed scopes and concurrent different-scope work. Each explicit CLI invocation
creates fresh identities. All state is ephemeral. Repeating a command starts new
model work; it is not durable deduplication or resume.

## Deletion-only changes

A supported diff can contain deletions without any changed head lines, for example
a removed guard. The change model records such a file as `no_changed_head_lines`,
with no invented changed range.

Analysis then diffs the exact base and head files and, for each deletion point,
binds up to 8 unchanged head lines on each side of it (overlapping windows merge)
as a deterministic-evidence item. These items enter the context packet as
`changed_hunk` sources, so the model reviews the code that now sits where the
lines were removed. Each deletion point is also recorded as an
`analysis_deleted_lines` source omission whose lines are the head lines on either
side of the removed lines (one line at the start or end of the file). The
omission is how the packet says that lines were deleted there. That omission
counts as an unsupported source omission, so such a review is never comprehensive
clearance.

The removed base lines themselves reach the model as `removed_lines` sources.
Analysis binds the removed lines of each deletion point to the exact base file
(deterministic evidence schema version 7). The context handler reloads that file
from the base snapshot reference whose digest the change entry names, rebuilds
its identity and slice binding from the bytes, and adds one `removed_lines`
source per deletion point. The source's `path` is the file and its `start_line`
and `end_line` are base line numbers, not head lines. Like every other source it
is `repository_controlled` data with `risk_flags` computed by the same rules, so
an injection payload in deleted text is flagged and never followed. A
deletion point's source also carries `head_line`, the head line beside which the
lines were removed (the first line of its `analysis_deleted_lines` omission).
Readback refuses a `head_line` on any other stage, or one outside every
`changed_hunk` source of the same file. The generation (context version 8),
verification (version 7) and investigation (version 6) contracts each tell the
model that `removed_lines` sources are deleted base lines, and how to report an
issue in the removed code on them. The verifier receives the same sources.

### Base-side findings

A finding about code that still exists is located on head lines, as before. A
finding about the removed code itself may be located in the `removed_lines`
source that holds it: a base-side finding. Its `start_line` and `end_line` are
base line numbers inside that source, and it records the source's `head_line`
(none for an emptied or removed file). Base and head line numbers are different
coordinate spaces: base-line evidence never covers a head location, head-line
evidence never covers a base-side location, and only cited `removed_lines`
evidence can verify a base-side finding. The `repository_context_anchor_omitted`
count again covers only `repository_context` anchors, which are still dropped.
Investigation turns admit base-side findings too.

Every recorded format names the side explicitly, so readback can never turn base
lines into head lines:

- candidate-batch encoding v2, verified-finding-set v2 and verification-context
  v7 record `"side":"base"` and `head_line` (they exist only in this development
  candidate and were extended in place);
- formats that predate this candidate keep their bytes and gain a version used
  only when a base side is present: candidate-batch encoding v3 and
  verified-finding-set v3 (uncategorized, from investigation),
  verification-batch v2, model-generation-input v4 (unsanitized, with
  `removed_lines` evidence marked `"side":"base"`) and v5 (an investigation
  input with such evidence), and verified diagnostic set
  v8 (`schemas/diagnostics/verified-diagnostic-set-v8.schema.json`), which the
  final set v7 may embed in place of v5.

Each output shows a base-side finding without presenting its numbers as head
lines:

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

Removed text is bounded per deletion point (64 lines, 8 KiB) and per file
(32 KiB). Text past a bound is never truncated: that point's removed text is
recorded whole as an `analysis_removed_lines_limit` omission whose lines are the
removed base lines. Removed text that is not valid UTF-8 text, on an excluded or
unauthorized path, or past the candidate limit is omitted with the usual reason
at its base lines. A deletion point's removed text is supplied only when a
selected `changed_hunk` of its file holds its `head_line`; otherwise it is a
`packet_budget` omission at its base lines.

A file whose head is now empty, and a removed file, keep their whole-entry
omission (`analysis_no_changed_head_lines` or `analysis_removed_file`), so their
review is never full clearance. Their removed base text is also bound and
supplied, with no `head_line`: consecutive line-aligned chunks of at most 64
lines and 8 KiB each, up to 32 KiB per file, covering the base file from line 1.
The rest of the file, from the first line that does not fit, is one
`analysis_removed_lines_limit` omission at its base lines; a line is never cut.
This text uses only the analysis budget that the changed files left, and only
the bytes it binds count, so removing large files never takes budget from a
changed file. Removed files are read from a separate 64 MiB bound: a removed
file past it is not read, and its whole removed text is one
`analysis_removed_lines_limit` omission with no lines.
This text needs no head neighbor, so a change that only removes files is reviewed
from it: its review snapshot has no head range and its packet holds only removed
text. A removed file whose text cannot be supplied (for example binary content,
which is not bound) leaves nothing to review, and such a change still refuses with
`all_sources_omitted`, which is not a completed model review or clearance. The
whole-entry `no_changed_head_lines` gap also remains, without removed text, when
a file that still has head lines cannot get deletion-point context: the diff is
unsupported or over its limits, or the evidence limits are reached. A file over
the 1 MiB diff bound that is removed, emptied, or added without a reviewable
range is an `analysis_resource_limit` omission instead, and a removed or emptied
one adds an `analysis_removed_lines_limit` omission with no lines: its text is
not read. The rest of the change is still reviewed, and the review is not full
clearance.

Investigation mode reviews such a change the same way: its first turn holds the
removed text alone, with no head range, and its snapshot tools can still list
and read the head snapshot. Its generation input then records only `removed_lines` evidence, as
model-generation-input version 5.

## Results and limits

A run that did not succeed adds two text lines after `run:`, for example:

```text
status: refused
ci: blocked
run: failed
failure: policy (task context)
hint: usually no changed source could be supplied to the model (every source was omitted, unsupported, or not authorized); see the context task's source omissions
```

`failure:` is the run failure class, the first plan task that failed, and, when
one was observed, a detail. `hint:` is a fixed one-line explanation per class
(`policy`, `resource_limit`, `transient`, `invalid_input`, `canceled`,
`dependency`, `internal`), refined for some class and task pairs. It describes
what the class usually means; it is not a diagnosis. A succeeded run prints
neither line.

### Route context too small

Every request reserves a byte-based upper bound on its input tokens (payload,
trusted system channel and 256 framing bytes, plus the serialized
`response_format` on a structured-output connection) plus the output allowance.
A route whose declared `max_context_tokens` is smaller is not eligible, so a
small model server cannot silently truncate the prompt. When that leaves no
eligible route for the generation, verification or an investigation turn, the
run is refused with failure `policy` and the JSON result adds
`"failure_detail": "route_context_insufficient"` and a `context_shortfall`
object with `required_tokens`, `estimated_input_tokens`, `max_output_tokens`
and `declared_context_tokens` (the largest declared context among the routes
too small); a review set member carries the same object. Both are absent
otherwise. Text output reads, with the counts in
place of N, I, O and D:

```text
failure: policy (task context): route_context_insufficient
hint: the review needs up to N tokens (a byte-based upper bound: I input plus O output) but the route declares max_context_tokens D; raise max_context_tokens on the route and the model server's context length to at least N (docs/named-local-runtimes.md#context-length)
```

Raise the route's declared context and the server's context length together;
see [named local runtimes](named-local-runtimes.md#context-length).

### Exhausted model output

A model response that stops at the output token limit (`finish_reason: length`,
or a Responses `incomplete` result for `max_output_tokens`) without any answer
text is classified by the adapter as the route failure `output_exhausted`, not as
a malformed response. Reasoning models do this when they spend the whole output
allowance on their reasoning trace. The run failure stays `internal` (the run
failure set is closed), and the JSON result adds
`"failure_detail": "model_output_exhausted"`; the field is absent otherwise.
Such a reply is a completed provider response, so the failed attempt keeps the
usage it reported, under the same checks and profile rules as a successful
reply's usage (the OpenCode console profile withholds native usage from both),
and its cost settles from that usage exactly as a successful attempt's does. An
exhausted reply that reported no usage, or usage those checks refuse, keeps
unknown usage and the attempt's whole reservation stays held, as before. The
failure classification is unchanged. Text output reads:

```text
failure: internal (task verification): model_output_exhausted
hint: the model used its whole output allowance (reasoning) before answering; choose a non-reasoning model for this role or raise the review output allowance (setup bootstrap init --max-output-tokens)
```

A response that stops at the limit with partial text is still refused by the
strict document parser as before. The per-request output allowance is the runtime
policy's `max_output_tokens`, which bootstrap writes as 4096. It is separate from
each route's declared output capacity (`--output-tokens`). `trestle setup
bootstrap init --max-output-tokens N` (local and remote providers, and the `trestle
init` wizard as a flag) writes a larger allowance, from 4096 up to the declared
`--output-tokens`; for priced routes the per-request cost reservation uses the
same allowance and must fit `--max-cost-micro-usd`. Without the flag, the policy
bytes are unchanged.

JSON uses `open-trestle/local-git-model-review-result`. Every run that opened
writes schema version 6, which keeps every field of versions 1 to 5 and adds
[`token_usage`](#token-usage), except the investigation fallback that
[Token usage](#token-usage) names. A result that reports no opened run
(`run_status` `not_opened` or `unknown`) carries no token usage and keeps
version 1 (version 2 with `--investigation-policy`, version 3 with `--profile`). Earlier builds wrote
an opened run as version 1, version 2 with `--investigation-policy`, version 3
with `--profile`, version 4 with finding guidance or version 5 with
[style recommendations](#style-recommendations); those bytes read back
unchanged, and a version 1 to 5 result never carries `token_usage`. When at least
one verified finding carries a category, the result adds
`finding_guidance`: one entry per categorized finding, in diagnostic order, with
`finding_identity` (the diagnostic finding's `source_identity`), `category`, and,
when the generator offered one, `fix` with `fix_authority:
unverified_model_guidance`. The result keeps a `--profile` run's
`specialist` object. Text output adds `category:` and `fix:` lines after each such
finding. The verifier checked the finding's claim, not its category or fix: the
category is the generator's advisory label, and the fix is untrusted model text
that is printed, never applied, and is not part of the diagnostic set. SARIF carries it only as a labeled result property.
The model-result evaluation import and the retained-memory feedback review accept
version 4 and version 6 results without a specialist and ignore the guidance.

### Provider refusals

A provider that answers a model request with an HTTP refusal is classified by
the status alone; its error body is discarded unread and never reaches a
result, record or log. Every OpenAI-compatible request profile uses the same
mapping:

| HTTP status | Route failure | Run failure | Retried | `failure_detail` |
|---|---|---|---|---|
| 401 | `authentication` | `policy` | no | `provider_authentication_failed` |
| 402 | `payment_required` | `policy` | no | `provider_payment_required` |
| 403 | `authorization` | `policy` | no | `provider_authorization_denied` |
| 404 | `model_unavailable` | `policy` | no | `provider_model_unavailable` |
| 410 | `model_retired` | `policy` | no | `provider_model_retired` |
| 429 | `rate_limited` | `transient` | twice on the same route, inside the task attempt | `provider_rate_limited` |
| 503 with a `Retry-After` in seconds | `rate_limited` | `transient` | as 429 | `provider_rate_limited` |
| other 5xx | `provider_server` | `transient` | no | none |
| 200 with a reply the adapter refuses, or a status no other class names (for example 400) | `invalid_response` | `internal` | no | `provider_response_invalid` |

A `policy` run is `refused` with CI disposition `blocked` and exit code 4, so a
refusal the provider repeats on every request is attempted once. A `transient`
run is `failed` with `error` and exit code 1. Generation and verification keep
one task attempt, but a 429 means the provider refused the request before
processing it, so the model handler retries it on the same route at most twice
inside that attempt. A 503 that names a `Retry-After` in seconds is the same
refusal and is handled the same way; a 503 without one, or with an HTTP date or
zero, stays a `provider_server` failure and is not retried. Each retry waits
the provider's `Retry-After`, at least the task's fixed retry delay (one
second), which also applies to a 429 without `Retry-After`; a `Retry-After`
beyond 15 minutes, or one that would end after the
review's `--timeout` deadline, is not waited for and the task fails at once.
Each retry is its own route attempt, claimed, completed and settled in the
audit ledger and claimed no sooner than its delay after the refusal, and it takes over
the refused attempt's cost reservation, so the reservation is never made again
or exceeded. The provider processed nothing, so a rate-limited attempt records
known zero usage and settles at zero cost; a review that needed a retry keeps
that stage's token usage and the run's cost known when its final attempt
reports usage. No other failure is assumed to cost nothing. When the second
retry is rate-limited too, the review fails as
`transient` with `provider_rate_limited`. Before this
mapping, 402, 404 and 410 were `invalid_response`, so the run failed as a
retryable `internal` failure with no detail. The detail is recorded only when
the most recent model request the provider answered was refused that way and
that refusal is the recorded run failure: a credential that could not be read
before sending, or a rate limit a later attempt outlived, records none. Text
output names the failing task, the detail and a fixed hint, for example:

```text
failure: policy (task candidates): provider_payment_required
hint: the provider refused the request for billing: add credit or a subscription to the provider account, or choose another route
```

```text
failure: policy (task verification): provider_model_retired
hint: the provider no longer serves this model: choose a model the provider lists as available and re-run setup
```

A provider that answers HTTP 200 with a reply the adapter refuses (malformed
or truncated JSON, an empty or oversized body, a Chat Completions reply with
an unrecognized field, a model other than the route's, or another document the
strict parser does not accept), or with a status no route failure class names
(for example 400; see [OpenAI provider](openai-provider.md)), keeps the
`internal` run failure it always had, so the run is `failed` with `error` and
exit code 1, and records `failure_detail` `provider_response_invalid`. Before
this detail the text output read only `failure: internal (task candidates)`
with a hint that could not tell a refused reply from an internal bug. The
detail names neither the reply nor any of its fields:

```text
failure: internal (task candidates): provider_response_invalid
hint: the provider answered, but its reply did not match what Open Trestle accepts, for example malformed or truncated output, an unrecognized field or an unexpected HTTP status: run the review again; if it repeats, choose another model or route and report it
```

A reply the adapter accepted whose review document then fails its schema, a
reply that stopped at the output limit (`model_output_exhausted`, above), and a
request the adapter could not build or send record no such detail.

A review set member carries the same `failure_detail` and `member hint:` line.
The other hints are: 404 "the provider does not serve this model at this
endpoint: check the model name and endpoint, choose a model the provider lists
as available, and re-run setup"; 401 "the provider did not accept the
credential: check the API key the route names (for ollama-signin, run `ollama
signin`), then retry"; 403 "the provider refused this account access to the
model or endpoint: check the account's access, or choose another route"; 429
"the provider rate-limited the request on its last attempt: wait and run the
review again, or choose another route". On an OpenRouter route a 404 records
`provider_no_allowed_endpoint` instead, with a hint that a model without
zero-data-retention endpoints is refused when zero data retention is required
by the setup or by the OpenRouter account or key (see
[OpenRouter zero data retention](openrouter-zdr-profile.md#when-openrouter-refuses-a-request)).
A result whose policy has an OpenRouter route that does not require zero data
retention lists the limitation `openrouter_zero_data_retention_not_required`.
`failure_detail` takes these values in result schema version 6; a result
without a provider refusal or a refused reply keeps its bytes.
A daemon run is classified the same way, and its generation or verification
task records the detail as its content-free failure reason (the same
`provider_*` token, `provider_response_invalid` only with failure `internal`)
in task completion v3, the v7 `task_failed` event and receipt v3.
`trestle runs status` prints it on stderr, for example
`runs status: task candidates failed: provider_payment_required (the provider
refused the request for billing)` and a `hint:` line with the action; the TUI
prints a `Reason` and a `Hint` line, the web console a labeled reason and hint,
and the ACP review-state message a `Task failure` line. A daemon run retries a
rate limit the same way, never past the task's execution deadline. The daemon's
startup proofs of a failed run's model audit, for a generation rejected for
document shape or an exhausted model lease, accept the same shape before and
after the run's retention lapses: at most two refused attempts, each claimed,
completed without a response and settled, then the final attempt, each retry
claim naming the selection, the refused outcome and its retry decision. While
the run's artifacts are retained, each retry claim must also carry the identity
the gateway grants for that lineage from the input's authorization. Any other
audit shape stays quarantined at startup.

### Token usage

A version 6 result reports `token_usage`: the input, output and cached-input
tokens the provider reported, summed over every route attempt the run claimed,
with `generation` and `verification` objects of the same shape. A completed
review whose two attempts each reported 100 input and 100 output tokens reads:

```json
"token_usage":{"known":true,"route_attempts":2,"input_tokens":200,"output_tokens":200,"cached_input_tokens":0,"generation":{"known":true,"route_attempts":1,"input_tokens":100,"output_tokens":100,"cached_input_tokens":0},"verification":{"known":true,"route_attempts":1,"input_tokens":100,"output_tokens":100,"cached_input_tokens":0}}
```

- `route_attempts` is the number of claimed attempts summed. A direct review
  claims one generation and one verification attempt, plus one for each
  same-route retry after a [rate limit](#provider-refusals) (at most two per
  stage); an `--investigation-policy` run claims one per turn.
- `input_tokens` includes `cached_input_tokens`, as providers report them. The
  counts are the provider's report, not a tokenization by Open Trestle, and
  carry no content.
- `known` is true only when every summed attempt reported usage. Otherwise it is
  false and the three counts are absent, never zero, for example
  `{"known":false,"route_attempts":1}`. That happens when the provider sent no
  usage, the response was refused before its usage was accepted, or no adapter
  result was observed for a claimed attempt. Of the failed dispatches, an
  [exhausted reply](#exhausted-model-output) can carry usage and a rate limit
  (429, or 503 with a `Retry-After`) records known zero usage; any other HTTP
  error, a transport failure or a reply the adapter refuses as invalid counts
  as unknown.
- A successful attempt is read from the run's recorded route execution. Any
  other claimed attempt is read from the adapter result the session observed for
  it in the same process, so a generation that was dispatched but whose response
  was refused as malformed still counts the tokens it reported.
- In an `--investigation-policy` run each recorded turn counts under its role,
  and each entry of `investigation.turns` carries its own `input_tokens`,
  `output_tokens` and `cached_input_tokens` (a recorded turn always has known
  usage, because its cost is known). A claimed turn without a turn record has no
  known stage, so both stage objects are then unknown while the total can still
  be known.
- `usage_known` and `actual_cost_micro_usd` cover the same claimed attempts:
  `actual_cost_micro_usd` is the sum of their settled actual costs, and
  `usage_known` is true only when every one has a known settlement. A recorded
  execution contributes its reconciliation; any other attempt contributes the
  actual cost its reconciliation derives from the observed usage (the same
  pricing calculation), and only when the run recorded that reconciliation. So
  a failed attempt that reported usage and was settled from it, such as an
  exhausted reply, keeps the cost known. In a direct review `usage_known` equals
  `token_usage.known` unless an attempt that reported usage was never settled;
  an `--investigation-policy` run also requires the sum to equal the route
  owner's own settled total (`investigation.known_cost_micro_usd`).

Text output adds one line before any `style:` line and `limitations:`:

```text
tokens: input=200 output=200 cached_input=0 over 2 route attempts
tokens: unknown over 2 route attempts (not every attempt reported usage)
```

A result without `token_usage` reports no token use. That is a result that never
opened a run, and the fallback written when readback or closure of an
`--investigation-policy` run failed before its usage was read, which keeps
version 2 or 5. SARIF does not carry token usage. The model-result evaluation
import accepts a completed version 6 result only when its `token_usage` has
exactly one generation and one verification attempt, each a usage report an
adapter could return, whose counts sum to the totals, with `known` equal to
`usage_known`; the retained-memory feedback review accepts version 6 and ignores
the counts. A [review set](#specialist-review-set-opt-in) member carries its own
result's `token_usage`.

### Style recommendations

When a changed language has a style detector but the review's base tree declares
no style that governs it, the result recommends a standard style. The base tree
is read as for [`--specialists auto`](agent-profiles.md#declared-style-in-local-reviews):
root-level style configuration files only, never the head, so a style
configuration that a change adds does not silence the recommendation for that
change. EditorConfig alone does not count, because it covers only whitespace
basics. The recommendations come from a fixed table, not from a model:

| Changed language | Recommendation |
| --- | --- |
| Go | gofmt and Effective Go (in practice `go.mod` always declares it) |
| Python | PEP 8, enforced with Ruff or Black |
| JavaScript, TypeScript, Vue, Svelte | Prettier with ESLint |
| CSS, HTML, JSON, YAML, Markdown | Prettier |
| C, C++ | Google C++ Style through clang-format (`BasedOnStyle: Google`) |
| Rust | rustfmt |
| Ruby | RuboCop and the community Ruby Style Guide |

Java, Kotlin, C#, PHP, Scala, Swift, shell, SQL and TOML get no recommendation:
Open Trestle has no style detector for them, so it cannot tell whether such a
repository declares a style. Changed files are counted per language. Vendored
and generated files are not counted, as in specialist routing, and neither are
removed files or the dependency lock files package managers generate
(`package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`,
`bun.lock`, `Cargo.lock`, `Gemfile.lock`, `poetry.lock`, `uv.lock`,
`Pipfile.lock`, `composer.lock` and `go.sum`). Text output adds one line per
language before `limitations:`, for example:

```text
style: no declared Python style for 3 changed files; consider PEP 8, enforced with Ruff or Black, and commit its configuration
```

JSON keeps every other field (including `finding_guidance` and a `--profile`
run's `specialist` object) and adds, in version 6 as it did in version 5,
`style_recommendations`: one entry per language, in language-token order, with
`language` (the routing token, such as `python` or `cpp`), `changed_files`, and
`recommendation` (the table text). Recommendations use exactly the base style
configuration files that routing's change-features document carries. If a
recognized base style configuration file could not be read (over 64 KiB, not
valid UTF-8, beyond the first 256, or past the 1 MiB change-features bound), the
declared style is unknown only for the languages that file could govern, by any
style its name can declare: an unread `pyproject.toml` affects Python, an unread
`package.json` the languages Prettier governs, and an unread `.editorconfig`
none. Those languages are listed in `style_withheld` (`language`,
`changed_files`) instead of being recommended, every other language is still
recommended, and `style_configuration_unread` gives the number of unread files.
Text reads, for example:

```text
style: no declared TypeScript style for 1 changed file; consider Prettier with ESLint, and commit its configuration
style: declared Python style unknown for 1 changed file; a base style configuration file that may declare it was not read, so no recommendation is made
style: 1 base style configuration file was not read (over 64 KiB, not valid UTF-8, beyond 256 files, or past the 1 MiB change-features bound)
```

A result without any of these fields has no style advice; in earlier builds it
kept version 1 or 4.

A recommendation is advice only. It is not a finding, never blocks, and never
changes `status`, `ci_disposition`, the exit code under any
[exit-code policy](#exit-code-policy), source coverage or
`comprehensive_clearance`. SARIF carries it at run level only, as the
`trestleStyleAdvice` property and `note` notifications (see
[SARIF output](#sarif-output)), never as a result with a location. An
`--investigation-policy` result with advice keeps its `investigation` object; in
earlier builds it was version 5, and version 2 without advice. A `--specialists` review set reports the general review's advice
once (see [Specialist review set](#specialist-review-set-opt-in)). A run that
failed before it recorded its change model reviewed nothing and carries no
style advice, as it carries no findings. When the recorded change model, its
snapshots or a base style configuration file cannot be read back, the advice is
reported as unavailable rather than left out: JSON adds
`style_advice_unavailable: true` (with no other style field) and text reads
`style: advice unavailable; the recorded change or base style configuration could not be read back`. The model-result evaluation import
and the retained-memory feedback review accept version 5 and version 6 and
otherwise ignore the advice, but both refuse advice that no review records (one validator,
`agentprofile.RecordedStyleAdvice.Validate`): a language without a style
detector, a recommendation other than its table text, languages out of order,
repeated or both recommended and withheld, a withheld language without an
unread count, or an unavailable marker beside other advice.

Two optional counts report advisory repository-context accounting without changing
`status`, `ci_disposition` or source coverage. `instruction_context_omitted` (with
the `instruction_context_omitted` limitation; SARIF
`trestleInstructionContextOmittedCount`) counts base-tree instruction files that
were not supplied as `repository_context`: changed or deleted in the head,
truncated, oversized, unauthorized or over budget. These are never source
omissions, so they never make a review `incomplete`.
`repository_context_anchor_candidates_omitted` (with the limitation of the same
name) counts model candidates dropped because they were located in an instruction
file rather than in reviewed code and, from generation context version 8, in the
`removed_lines` source of a deletion point; the rest of the batch is kept. Both
fields are absent when zero.

`agent_configuration_sources` and `instruction_like_sources` count
generation-context sources flagged as repository AI material (agent instruction
files, skills, prompts, agent configuration) or as instruction-like text. Text
output adds `ai material in review context: agent_configuration=N
instruction_like=M (reviewed as code, never followed)`, and SARIF adds
`trestleAgentConfigurationSourceCount` and `trestleInstructionLikeSourceCount`.
They are attention signals only: they add no limitation and never change
`status`, `ci_disposition` or coverage. Both are absent when zero. See the
[prompt-injection boundary](prompt-injection-boundary.md). It includes
actual task/journal lineage, model route/context/request identities when available,
audit subjects, and the existing canonical diagnostics. No prompts, source
artifacts, credential values, or configuration paths are added to the receipt.
Text includes finding locations and declared limitations. JSON is at most 256 KiB;
text is at most 64 KiB. Output is built before writing. Encoding/short-write errors
fail the command rather than silently truncating a finding set.

| Exit | Meaning |
| --- | --- |
| 2 | Invalid command intent or usage |
| 4 | Verified policy-selected findings, or policy/resource refusal |
| 3 | No candidates, incomplete evidence, unsupported source, or cancellation |
| 1 | Internal/malformed result, unsafe drain/close, or output failure |

By default there is no exit-0 branch; `--exit-code-policy` is the explicit opt-in
(see [Exit-code policy](#exit-code-policy)). No candidates is not proof that
the repository is clear. Source omissions, independent abstention, bounded source
selection, empty memory, lack of publication, and ephemeral state remain visible.
Unknown final usage after an incomplete model dispatch is not presented as a
known zero cost. The receipt reports aggregate cost only when every claimed
attempt has a known settlement (see [Token usage](#token-usage)).

The default artifact capacity is 4096 objects. Library callers may choose 1 to
16384. This is a count bound, not a total resident-memory promise. Existing source,
context, provider, journal, and diagnostic limits also apply. A session permits at
most 1024 issued preparations. No background admission or persistent storage is
created. Local fake-HTTP tests do not establish live provider conformance or
comprehensive model quality.

## Non-Go files and repository instruction files

Model review now reviews changed text outside `.go` and sees the repository's
own instruction files. Non-Go hunks that are valid UTF-8 are sent as changed
hunks, with semantic analysis recorded as unsupported for them; lock, vendored,
minified, and binary files are omitted with a named reason. The root
`AGENTS.md`, `CLAUDE.md`, `.github/copilot-instructions.md`, and
`.trestle/review-instructions.md` of the reviewed head tree are added as
bounded advisory context (8 KiB per file, 16 KiB total, truncation recorded).
They are untrusted repository data that cannot override the review
instructions. The exact rules are in `docs/context-assembly-handler.md`.
