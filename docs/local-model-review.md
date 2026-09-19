# Local model review

`trestle local-git model-review` is an explicit request for model calls. It does not
change `local-git review`, which remains deterministic. This command cannot publish
a forge review or create a required check.

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
- Multi-pack-index, promisor objects, alternates, refs, worktrees, and Git
  subprocess fallback are out of scope.
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
allows the existing general transport only under the protected inventory/policy.
It is not an unrestricted egress bypass. Route approval, data classification,
logging restrictions, provider independence, capacity, and per-request cost
budgets remain in force. Provider credentials use only explicit protected-policy
environment references, through the existing credential resolver.

Repository and audit labels are host-supplied scope labels, not proof of Git
origin, forge authentication, or permission to publish. The opened source root is
bound to its session. Only the requested immutable Git commits are acquired. The
command never shells out or falls back to the mutable worktree. Without the
packed opt-in, pack-only repositories remain unsupported. With the packed opt-in,
only the narrow pack/index subset above is supported. Alternates, worktree
pointer files, symlink/gitlink source entries, unavailable objects, and other
unsupported Git layouts do not produce comprehensive clearance.

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

Copy the reported `inventory_identity` into `runtime-policy.json` after editing
the inventory. The shipped example pair is already structurally bound.
Leave `preferred_route_record_identities` empty unless you intentionally pin or
prefer route record identities reported by the same command.

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
and runtime-policy identity. A narrow authoring command can build this contract
from an explicitly selected protected feedback file. It does not run review,
resolve credentials, call providers, ingest model output, curate memory, or update
other memory stores.

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

All flags except `--format` are required. The authoring command accepts only
`--egress local-only`. `--timeout` must be one second to 15 minutes. `--valid-for`
must use whole milliseconds, exceed the timeout, and be at most seven days. The
command samples the clock once after protected configuration and feedback load,
then sets each record's `observed_at` and `valid_from` to that millisecond.

The feedback file is a protected convenience JSON file, not the wire contract:

```json
[{"path":"src/file.go","text":"operator advisory text"}]
```

It is limited to 64 KiB, 1 to 16 records, exact `path` and `text` keys, no unknown
or duplicate keys, no comments, no trailing tokens, no nested values, and no null,
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
and a suitable private directory for sensitive advice. The command never edits,
curates, migrates, or deletes the input.

Successfully constructed opted-in Session results replace `empty_memory_index`
with `retained_input_advisory_not_all_records_selected` and
`retained_input_read_only`. Ordinary result schema version 1, output bounds,
independent verification, and nonzero dispositions remain unchanged. A protected
input refusal produces `refused` with exit 4; cancellation produces exit 3. Later
Run or Close errors keep the existing conservative failure handling. Input reuse
is not automatic retained-memory generation, cross-head reuse, or revocation.

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

Opted-in results use schema version 2. They include all retained turns and their
request, route, audit, and tool-result identities, rather than only the final two
model calls. Known observed cost remains visible when total usage is unknown.
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

## Results and limits

By default, JSON uses `open-trestle/local-git-model-review-result`, schema version 1. It includes
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

There is no exit-0 branch in this initial version. No candidates is not proof that
the repository is clear. Source omissions, independent abstention, bounded source
selection, empty memory, lack of publication, and ephemeral state remain visible.
Unknown final usage after an incomplete model dispatch is not presented as a
known zero cost. The initial receipt reports aggregate cost only when the recorded
successful model artifacts provide all claimed costs.

The default artifact capacity is 4096 objects. Library callers may choose 1 to
16384. This is a count bound, not a total resident-memory promise. Existing source,
context, provider, journal, and diagnostic limits also apply. A session permits at
most 1024 issued preparations. No background admission or persistent storage is
created. Local fake-HTTP tests do not establish live provider conformance or
comprehensive model quality.
