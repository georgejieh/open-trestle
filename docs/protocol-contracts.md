# Protocol contracts

Open Trestle publishes JSON Schema 2020-12 documents for people who implement its transports. This page lists those schemas and explains the rules that go with them. It is a reference for contributors and integrators.

The runtime parsers enforce the contracts, and passing a schema does not grant authority. Repository tests resolve every local fragment and every internal Open Trestle URN reference offline. An unknown target, a missing fragment, a malformed JSON Pointer or an external schema reference fails the test suite.

The setup-plan parsers replay the embedded checker catalog and the receipt chain before they accept readiness. They also require the following:

- canonical field order and encoding;
- identities that are recomputed from content;
- sorted collections;
- graph safety;
- valid state transitions;
- tenant lineage;
- a bounded byte size.

The runtime-status schemas constrain years to 1970 through 9999 and allow only valid Gregorian leap days. The runtime-status parsers also enforce calendar-valid UTC millisecond timestamps, the repository projection, unique and sorted handler kinds and components, backend compatibility, and conditional review, route, worker and publication rules that the schemas cannot express completely.

The executable review-context packet is generation context version 10, and the verification-context packet is version 9. Counted source omissions are part of their request identities and coverage equations.

Routing, policy, provider, and review schemas:

- `schemas/gateway/review-routing-input-v1.schema.json`
- `schemas/policy/provider-data-constraints-v1.schema.json`
- `schemas/provider/model-requirements-v1.schema.json`
- `schemas/provider/model-capabilities-v1.schema.json`
- `schemas/provider/route-reference-v1.schema.json`
- `schemas/provider/route-reference-v2.schema.json`
- `schemas/provider/route-capability-declaration-v1.schema.json`
- `schemas/review/model-candidate-batch-v1.schema.json`
- `schemas/review/model-candidate-batch-v2.schema.json`
- `schemas/review/model-investigation-output-v1.schema.json`
- `schemas/review/model-verification-batch-v1.schema.json`
- `schemas/review/local-git-inspect-result-v1.schema.json`
- `schemas/review/local-git-change-result-v1.schema.json`
- `schemas/review/local-git-change-result-v2.schema.json`
- `schemas/review/local-git-review-result-v1.schema.json`
- `schemas/review/local-git-review-result-v2.schema.json`
- `schemas/secret-scanner/secret-scan-request-v1.schema.json`
- `schemas/secret-scanner/secret-scan-response-v1.schema.json`

Route-reference schema v1 is the historical grammar for untagged models, and its bytes are unchanged. Schema v2 keeps the six-field wire shape and adds one optional final `:tag` in `model_id`. A tagged model ID requires an empty `model_version`. An untagged model ID keeps the existing behavior, which needs a nonempty version selector.

Values that look like `host:port` or like an opaque URI in a tagged ID are inert model text. They never act as an endpoint, a filesystem path or a credential. The runtime inventory and the durable route authorization v1 schemas already bound these fields broadly, and native route validation enforces the stricter grammar. The capability-declaration v1 schema still references the historical route-reference v1 subset. No schema version changes the route identity preimages (the exact bytes that identities are computed from).

Native Go tests exercise the selector semantics. The schema tests check structure and the unchanged v1 bytes, and they do not perform full JSON Schema semantic validation.

Candidate batch schema v1 keeps its bytes and is the output schema of recorded generation contexts before version 7. Schema v2 is the output schema of version 7, 8 and 9 generation contexts. In v2, every candidate adds two fields:

- A required, closed `category`: `correctness`, `security`, `concurrency`, `performance`, `reliability`, `maintainability`, `style`, `documentation` or `testing`.
- An optional `fix`, which is nonblank plain text of at most 256 characters. The schema sets this as `maxLength`. The host parser enforces the same 256-character bound plus a 1024-byte UTF-8 wire bound, which 256 characters can never exceed.

Both fields are advisory model output. The fix is never applied and is not verified. At runtime, a candidate whose `source_range` names a `repository_context` source is dropped and counted. From generation context version 8, a candidate may instead be located in a `removed_lines` source, as a base-side finding.

The investigation output schema uses a closed `oneOf`: the output is either a candidate batch or one host-defined snapshot tool call. A valid proposal is not permission to run a tool. Runtime parsing, the retained model response, the source bindings and the policy limits still decide what is accepted.

No JSON Schema is published for the `open-trestle/local-git-model-review-result` receipt of `trestle local-git model-review`, at any of its versions 1 through 6. The fields, versions and readback rules are documented in [local model review](local-model-review.md#results-and-limits). The strict native parser, `localreview.ParseCompletedResult`, is the authority. The versions differ as follows.

- Version 5 adds optional style advice to the version 4 fields, or to the `investigation` object of a version 2 investigation result. The advice fields are `style_recommendations`, `style_withheld`, `style_configuration_unread` and `style_advice_unavailable`.
- Version 6 keeps every earlier field. Open Trestle writes it for every run that opened, and for a review that was refused before it opened because a spending limit was reached (`failure_detail` `spending_limit_reached`, without `token_usage`). It adds `token_usage` and per-turn token counts on investigation turns. `token_usage` holds the provider-reported input, output and cached-input tokens, summed over the claimed route attempts, with generation and verification shares. The counts are absent unless every attempt reported usage.
- A completed direct version 6 result also carries these fields, added in place. `rank` lists every distinct verified finding in rank order, with the duplicates merged into it. `pre_existing` lists findings on unchanged lines that the change provably cannot reach. It is advisory on import, where the readiness `ci_disposition` is required; only the evaluation reader (`localreview.ObserveCompletedResult`) also accepts a disposition it relaxed. `unproven_origin` lists findings on unchanged lines that the change may have caused; they block. `declaration_anchors` gives the changed declaration that holds a finding and is used only to merge duplicates. `walkthrough` is the summary of the review.

Control-plane schemas:

- `schemas/controlplane/review-run-plan-v1.schema.json`
- `schemas/controlplane/local-deterministic-review-intent-v1.schema.json`
- `schemas/controlplane/local-full-review-intent-v1.schema.json`
- `schemas/controlplane/review-run-event-v1.schema.json`
- `schemas/controlplane/review-run-event-v2.schema.json`
- `schemas/controlplane/review-run-event-v3.schema.json`
- `schemas/controlplane/review-run-event-v4.schema.json`
- `schemas/controlplane/review-run-event-v5.schema.json`
- `schemas/controlplane/review-run-event-v6.schema.json`
- `schemas/controlplane/review-run-event-v7.schema.json`
- `schemas/controlplane/review-run-receipt-v1.schema.json`
- `schemas/controlplane/review-run-receipt-v2.schema.json`
- `schemas/controlplane/review-run-receipt-v3.schema.json`
- `schemas/controlplane/review-task-lease-v1.schema.json`
- `schemas/controlplane/review-task-completion-v1.schema.json`
- `schemas/controlplane/review-task-completion-v2.schema.json`
- `schemas/controlplane/review-task-completion-v3.schema.json`
- `schemas/controlplane/task-claim-request-v1.schema.json`
- `schemas/controlplane/task-completion-request-v1.schema.json`
- `schemas/controlplane/task-notification-v1.schema.json`
- `schemas/controlplane/task-notification-lease-v1.schema.json`
- `schemas/controlplane/task-notification-claim-request-v1.schema.json`
- `schemas/controlplane/api-response-v1.schema.json`
- `schemas/controlplane/runtime-status-response-v1.schema.json`
- `schemas/controlplane/run-progress-response-v1.schema.json`
- `schemas/controlplane/delivery-refusal-response-v1.schema.json`

The `run` member of the API response v1 envelope is the canonical receipt v1, v2 or v3, whichever the run's state needs. Like its `diagnostics` member, it names the embedded record's own version. The task completion request v1 likewise carries task completion v1, v2 or v3.

The run-progress response v1 is a separate read-only HTTP envelope with exactly `contract`, `schema_version`, `request_id`, `run` and `progress`. It references the canonical receipt v1, v2 or v3. Its four axes are `change`, `deterministic`, `context` and `verification`. Each axis has a bounded state, an optional immutable artifact identity and only its declared count fields.

The schema inventory contains 141 documents. The native client also validates the scope, the completed-task binding, the output identities other than context, the count equations and the checked-versus-applicable bounds. Schema validation cannot establish artifact lineage or consistency with the receipt head.

The delivery-refusal response v1 is another read-only envelope, with exactly `contract`, `schema_version`, `request_id` and `refusal`. The `refusal` member is the canonical `open-trestle/webhook-delivery-refusal` v1 record. It describes an accepted webhook delivery that intake refused instead of opening its run. It holds the tenant, repository, source, deduplication key, delivery and planner identities, the reason token and the refusal time. It carries no delivery content. Errors use the api-response envelope.

In the progress response, `not_run` and `unavailable` carry no counts, and absent counts mean unknown, not zero. Only a deterministic check that is evidenced as incomplete uses `partial`. The available context artifact identity is the packet that the source evidence proves. After v6 settlement it can differ from the receipt's sanitized generation-input output. The other available axis identities equal the outputs of their completed tasks.

To answer a progress request, the daemon uses at most ten indexed, scoped artifact loads and the existing canonical parsers. It checks that the receipt head has not changed, and returns `409 progress_changed` if it advanced. It writes no provisional diagnostics, grants no approval and performs no model or publication effect. `runs status --format progress` prints a single bound `{run, progress}` object rather than the HTTP envelope. See [read-only run progress](daemon-api.md#read-only-run-progress).

The local file-backed full-review context worker writes a v3 `context_abstention_prepared` event before it writes any abstention artifact. The bounded canonical artifact envelope holds omission metadata only. It holds no repository source bytes and no model claim. Before a v2 failed-task event links the result, recovery must verify the exact scope, plan, task, provenance, failure class and artifact identity. Old v1 no-output failures and v2 linked failures remain readable. The PostgreSQL journal's current 1 MiB event limit does not qualify v3, so local full review rejects nonlocal stores.

A failed source acquisition may record one closed, content-free reason:

- `no_merge_base`: the requested base and the head share no history.
- `nothing_to_review`: the head equals the requested base or is already contained in it.
- `merge_base_unavailable`: the forge did not report a usable merge base.

`NewSourceTaskFailureWithReason` binds the reason, the failure class, the plan and the task into a v3 task completion. The coordinator accepts it only for an `acquire_source` task of that plan, and records it in a v7 `task_failed` event with an empty output. Replay restores the reason on the task until a retry makes the task available again. A receipt with any task reason is receipt v3, whose task item adds `failure_reason`. The reason is never forge or repository text. Earlier event, completion and receipt versions keep their bytes and identities.

A context assembly task that is refused before any model effect records one of two route reasons. The reason goes on the same v3 completion, v7 `task_failed` event and v3 receipt.

- `route_context_insufficient` applies when the request's byte-based reservation exceeds the declared context of every candidate route. The reservation is an upper bound on the request's input tokens plus the output allowance.
- `no_eligible_route` applies to any other route refusal.

`NewContextTaskRefusal` binds the policy failure, the reason, the plan and the `assemble_context` task. `route_context_insufficient` always carries, and only it carries, a `context_shortfall` object with these fields:

- `required_tokens`, which equals `estimated_input_tokens` plus `max_output_tokens`;
- `estimated_input_tokens`;
- `max_output_tokens`;
- `declared_context_tokens`, the largest declared context among the routes that were too small, which is below the required tokens.

The counts are bound into the completion and event identities, and replay restores them. A source reason is accepted only for `acquire_source`, and a route reason only for `assemble_context`.

When the provider answers a candidate generation or verification attempt with a refusal, the task records one of seven provider reasons. They go on the same v3 completion, v7 `task_failed` event and v3 receipt, and are named from the HTTP status alone. Six have failure class `policy`:

- `provider_payment_required` (402);
- `provider_model_unavailable` (404);
- `provider_model_retired` (410);
- `provider_authentication_failed` (401);
- `provider_authorization_denied` (403);
- `provider_request_rejected`, which is the route failure `request_rejected`: 400 or 422 for an invalid request, such as an unknown model ID or an unsupported parameter, and 405 or 415 for a method or media type the endpoint does not take.

The seventh, `provider_rate_limited` (429), has failure `transient`.

The route failure class `request_rejected` is never retried and leaves another route eligible for fallback. No published record can carry it. The route execution record v1 and the investigation turn v1 hold successful attempts only, so it appears only in the completed-attempt record, which is not in any release and reads it in place.

Two more reasons have failure `internal`:

- `provider_response_invalid` is recorded when the provider answered with a reply that the adapter refused. This is the route failure `invalid_response` after the request was sent: a malformed, truncated or otherwise unaccepted 200, or a status that no other class names, such as 409. The reason names neither the reply nor its fields.
- `model_output_invalid` is recorded when the reply was accepted and stopped normally, but the review parser refused the answer as not a valid review document. That covers an answer that is not one JSON document, a refusal, the wrong shape, or a document that the review rules refuse. The reason names neither the answer nor its fields. A host input check, or a reply stopped at the output limit or by a content filter, records no such reason.

`NewModelTaskFailureWithReason` binds the reason, its one failure, the plan, and a `generate_candidates` or `verify_candidates` task. The completion, the event, replay and the receipt all refuse any other pairing.

A 429, or a 503 that names a `Retry-After` in seconds, is a `rate_limited` refusal with known zero usage. It reaches the task only after the model handler's same-route retries. Within the task's one attempt, `NewRateLimitedRetryAttemptAuthorization` grants each of at most two retries (`NewRateLimitRetryPolicy`) after a rate limit that settled at known zero usage (or, from an adapter that records none, unknown usage). Each retry is its own route attempt with the same request, route and terms. It takes over the refused attempt's reservation instead of reserving again, and `IsSameReservationRetryOf` recognizes that lineage when a generation result or rejection is read back. The task records `provider_rate_limited` when the last retry is also rate-limited or no retry is allowed.

The daemon's startup proofs read each refused attempt from the audit as a sequence of records. The sequence is a claim, a completed dispatch without a response and its reconciliation, and then a retry claim whose causal parents are the selection, the refused outcome and the retry decision. With the artifacts retained, `SameReservationRetryIdentity` derives the identity that each retry claim must carry, from the input's authorization and those recorded identities. No recorded format changes.

A v4 `context_packet_prepared` event stores only the packet's artifact metadata and these values:

- the exact identity and the creation and expiry times;
- the source root and snapshot;
- the upstream dependencies, scope, task and attempt;
- the exact lease identity, the original lease event identity and the lease token identity.

The file journal syncs this checkpoint to disk before a caller may put packet bytes. This first checkpoint cannot settle success, renew or reclaim the lease, or authorize dispatch.

Trusted recovery may terminally fail an expired packet-only preparation with a policy-class, no-output task failure that has no reason. Within the lease, its holder may instead settle the packet-only preparation as a recorded route refusal, no later than the lease expiry. That is the same no-output policy failure, carrying `route_context_insufficient` with its counts or `no_eligible_route`. Neither path can treat the preparatory packet as output.

This event does not implement the later sanitized-input checkpoint, and it does not verify packet bytes against immutable upstream sources. The v1, v2 and v3 event bytes remain unchanged.

Artifact schemas:

- `schemas/artifact/runtime-artifact-v1.schema.json`
- `schemas/artifact/context-abstention-v1.schema.json`
- `schemas/artifact/sanitized-model-request-v1.schema.json`
- `schemas/artifact/sanitized-egress-receipt-v1.schema.json`
- `schemas/artifact/artifact-deletion-authorization-v1.schema.json`
- `schemas/artifact/artifact-deletion-receipt-v1.schema.json`
- `schemas/artifact/source-acquisition-input-v1.schema.json`
- `schemas/artifact/source-acquisition-input-v2.schema.json`
- `schemas/artifact/source-acquisition-input-v3.schema.json`
- `schemas/artifact/source-file-v1.schema.json`
- `schemas/artifact/source-snapshot-v1.schema.json`
- `schemas/artifact/source-snapshot-v2.schema.json`
- `schemas/artifact/change-model-result-v1.schema.json`
- `schemas/artifact/deterministic-evidence-result-v1.schema.json`
- `schemas/artifact/deterministic-evidence-result-v2.schema.json`
- `schemas/artifact/deterministic-evidence-result-v3.schema.json`
- `schemas/artifact/deterministic-evidence-result-v4.schema.json`
- `schemas/artifact/deterministic-evidence-result-v5.schema.json`
- `schemas/artifact/deterministic-evidence-result-v6.schema.json`
- `schemas/artifact/deterministic-evidence-result-v7.schema.json`
- `schemas/artifact/semantic-impact-profile-v1.schema.json`
- `schemas/artifact/semantic-impact-profile-v2.schema.json`
- `schemas/artifact/memory-retrieval-result-v1.schema.json`
- `schemas/artifact/publication-readiness-result-v1.schema.json`
- `schemas/artifact/publication-readiness-result-v2.schema.json`
- `schemas/artifact/publication-content-scan-receipt-v1.schema.json`
- `schemas/artifact/publication-input-v1.schema.json`
- `schemas/artifact/publication-receipt-v1.schema.json`
- `schemas/artifact/route-attempt-authorization-v1.schema.json`
- `schemas/artifact/route-execution-record-v1.schema.json`
- `schemas/artifact/model-generation-input-v1.schema.json`
- `schemas/artifact/model-generation-input-v2.schema.json` (an investigation input)
- `schemas/artifact/model-generation-input-v3.schema.json` (a sanitized input)
- `schemas/artifact/model-generation-input-v4.schema.json` (an unsanitized input that records `removed_lines` evidence)
- `schemas/artifact/model-generation-input-v5.schema.json` (an investigation input that records `removed_lines` evidence, with an empty snapshot for a change that only removes files)
- `schemas/artifact/model-generation-result-v1.schema.json` (its `candidate_batch` is one of candidate-batch v1, v2 or v3)
- `schemas/artifact/candidate-batch-v1.schema.json`
- `schemas/artifact/candidate-batch-v2.schema.json` (categorized candidates, with any base-side location or evidence)
- `schemas/artifact/candidate-batch-v3.schema.json` (uncategorized candidates that record removed base lines)
- `schemas/artifact/verification-batch-v1.schema.json`
- `schemas/artifact/verification-batch-v2.schema.json` (verdicts that record removed base lines)
- `schemas/artifact/verified-finding-set-v1.schema.json`
- `schemas/artifact/verified-finding-set-v2.schema.json` (categorized findings, with any base-side location or evidence)
- `schemas/artifact/verified-finding-set-v3.schema.json` (uncategorized findings that record removed base lines)
- `schemas/artifact/model-verification-result-v1.schema.json` (its `verification_batch` is one of verification-batch v1 or v2, and its `verified_finding_set` one of verified-finding-set v1, v2 or v3)

Each of these versioned artifact schemas describes exactly one version, and later versions are separate files. The version 1 files of the candidate batch and the verified finding set are as first published. The generation input v1 file differs only in that it also accepts the identity of the v2 candidate schema, which a version 7 or later context requests.

Evaluation schemas:

- `schemas/evaluation/static-debug-evaluation-result-v1.schema.json`
- `schemas/evaluation/deterministic-corpus-candidate-result-v1.schema.json`
- `schemas/evaluation/deterministic-corpus-performance-observation-v1.schema.json`
- `schemas/evaluation/evaluation-adjudication-v1.schema.json`
- `schemas/evaluation/evaluation-adjudication-result-v1.schema.json`
- `schemas/evaluation/model-corpus-labels-v1.schema.json` (pending fixture-author labels for one model-review corpus case; version 1 admits no reviewer or review date)
- `schemas/evaluation/model-corpus-human-adjudication-v1.schema.json` (a human-authored, externally asserted review of one model-review corpus: its identity and manifest digest, a reviewer distinct from the fixture author, the review date, source-first and no-prior-run-output declarations, and one confirmed, revised or rejected decision per case in corpus order with each label digest)
- `schemas/evaluation/model-corpus-run-bundle-v1.schema.json` (the index of one model-review corpus driver batch: exact output file pins, exit, latency and copied status, usage, cost and token usage fields per run)
- `schemas/evaluation/model-corpus-score-v1.schema.json` (counts and integer ratio pairs from matching a run bundle to the pending labels, with latency, cost and token spreads across runs; every number is `labels_pending_human_review` and `release_evidence_eligible` is false)
- `schemas/evaluation/model-corpus-adjudicated-score-v1.schema.json` (the same counts, ratios and spreads over only the cases an imported human adjudication record confirms, every number `adjudicated_externally_asserted`, with revised and rejected cases listed with their reasons; `release_evidence_eligible` is true only when every case is confirmed and a complete bundle ran every case, and acceptance is not decided)

Runtime authority schemas:

- `schemas/runtime/runtime-route-inventory-v1.schema.json`
- `schemas/runtime/runtime-policy-v1.schema.json`
- `schemas/runtime/runtime-policy-v2.schema.json`
- `schemas/runtime/runtime-policy-v3.schema.json`
- `schemas/runtime/runtime-policy-v4.schema.json`
- `schemas/runtime/runtime-policy-v6.schema.json`
- `schemas/runtime/configuration-validation-result-v1.schema.json`
- `schemas/runtime/route-inventory-identity-result-v1.schema.json`
- `schemas/runtime/runtime-status-v1.schema.json`
- `schemas/runtime/postgres-admin-result-v1.schema.json`
- `schemas/runtime/postgres-rate-limit-admin-result-v1.schema.json`
- `schemas/runtime/postgres-replica-reconciliation-admin-result-v1.schema.json`
- `schemas/runtime/signed-bundle-admin-result-v1.schema.json`
- `schemas/runtime/signed-bundle-statement-admin-result-v1.schema.json`
- `schemas/runtime/kms-admin-result-v1.schema.json`
- `schemas/runtime/envelope-admin-result-v1.schema.json`
- `schemas/runtime/github-permission-admin-result-v1.schema.json`
- `schemas/runtime/github-permission-admin-result-v2.schema.json`
- `schemas/runtime/github-source-broker-v1.schema.json`
- `schemas/runtime/github-webhook-admin-result-v1.schema.json`

Spending schemas:

- `schemas/runtime/spending-limit-v1.schema.json`
- `schemas/runtime/usage-ledger-entry-v1.schema.json`

A spending limit v1 (`open-trestle/spending-limit`) is the local limit for one API key. It holds these fields:

- the provider ID;
- the key variable name and its credential reference identity, which is the same SHA-256 of `open-trestle/provider-credential-environment/` and the name that every runtime policy connection and setup witness records;
- a calendar `period` in UTC (`week` starting Monday, `month` or `year`);
- `limit_micro_usd`, in whole cents;
- ascending `alert_percents`.

A usage ledger entry v1 (`open-trestle/usage-ledger-entry`) records one review run that sent at least one request through a keyed route. It holds the time, the review run ID, the runtime policy identity, the keys and models used, the requests sent, `usage_known` and `cost_micro_usd`. The cost is the settled cost (`cost: settled_usage`). When usage was unknown, it is instead each such request at the cost reserved for it (`cost: reservation_upper_bound`). The entry always has `price_basis: route_max_price`.

`trestle` stores both in the private usage folder: `$XDG_STATE_HOME/open-trestle/usage`, by default `~/.local/state/open-trestle/usage`, with mode `0700` and files `0600`. They never hold a key, source, prompt or reply, and they are an upper-bound estimate, not a bill. The native parsers (`spending.ParseLimit` and `spending.ParseEntry`) additionally require the canonical encoding, the derived identities and sorted keys and models. A limit is best effort, and the provider's own limit is the guarantee. See [spending limits](spending-limits.md).

Runtime policy v3 adds the closed `openrouter_zdr_chat_v1` profile and the eight-field `brokered_route_authority`. Versions 1 and 2 keep their schema bytes and accepted identity preimages.

Native v3 validation requires a typed version 2 `openrouter_privacy` witness inside the existing immutable evidence manifest. A witness is a recorded statement of the provider's privacy terms for one route. This one holds:

- the exact full route and effective selector;
- the connection, profile and auth;
- the slug and the `all_slug_matches` scope;
- the account and credential reference, with the effective account's Safety Retention denial for Google and other providers;
- the tenant and repository;
- the source evidence;
- the explicit retention exceptions;
- the exact validity window.

A nonzero manifest digest alone is not privacy approval. The existing v3 schema bytes remain unchanged. The native parser and the common catalog enforce this requirement, and JSON Schema alone does not.

The binding follows a chain: the policy record identity and evidence digest, then the immutable manifest, then the typed witness. It also uses `account_policy_identity`, which is derived from the fixed versioned account subsection. There is no second policy approval list and no self-hash.

The named profile is refused at its next validation if any of these holds: typed evidence is missing or invalid, only the policy mismatches, or an arbitrary account digest is supplied. Generic opaque-manifest v1 and v2 admission is unchanged. Open Trestle does not rewrite or upgrade a setup receipt automatically. Renewed evidence changes the manifest, record, inventory and policy identities and needs fresh, exact setup approval. The daemon consumes protected configuration, not setup receipts.

See [the profile contract and offline account calculation](openrouter-zdr-profile.md#what-is-recorded).

Runtime policy v4 adds only the finite `opencode_go_chat_v1` Chat profile and its seven-field `opencode_go_authority`. Generic connections and the existing v3 OpenRouter profile remain supported in v4. The two named authority fields are mutually exclusive, including a null value in one of them. The historical v1, v2 and v3 schema bytes and accepted identity preimages remain unchanged.

Native validation binds the exact Go route and effective model selector, the immutable typed `opencode_go_privacy` evidence, the derived account and credential-reference identity, the tenant and repository, and the validity window. Structure alone cannot validate these bindings. The native schema tests inspect structure and the frozen legacy bytes, and they do not run a JSON Schema validator.

The setup checker supports an exact approved Go generation route and a distinct private direct verifier. Setup support grants no dispatch authority and implies no readiness. See [OpenCode Go profile](opencode-go-profile.md).

Runtime policy v6 is a generic policy with the v2 exact verifier grant and an optional boolean `local_structured_output`. When the option is true, the policy requires these three things:

- generic Chat Completions at a canonical numeric-loopback endpoint;
- bearer or explicit no-auth credentials;
- a local inventory namespace.

V6 excludes all named request-profile and authority fields. The values false and omitted have the same v6 binding bytes and identity, which differ from the v2 identity. Native versions 1 through 5 reject the option, including false, and the published v1 through v4 schema bytes remain unchanged. The binder preserves an explicit v6 policy. It keeps historical templates that have no option on v2 and leaves their binding bytes and identity preimages unchanged. Native validation enforces inventory locality. See [local Chat schema transport](local-model-review.md).

Runtime policy v7 carries only the closed `ollama_signin_chat_v1` profile. It is for a local Ollama daemon that relays Ollama Cloud models using the operator's `ollama signin` account. Every v7 connection must:

- name that profile;
- use Chat Completions;
- set `credential_mode` to `none` explicitly;
- use an endpoint of exactly `http://127.0.0.1:PORT/v1`;
- have no authority object and no `local_structured_output`.

Its adapter namespace must hold only approved `private_remote` routes with provider ID `ollama-signin`, no model version, disabled content logging and a model ID whose tag is `cloud` or ends in `-cloud`.

This is the only loopback endpoint that may belong to a non-local zone. With no profile, or with any other profile at any version, a loopback endpoint still binds only the local zone. Because the zone is `private_remote`, the sanitizer, the secret scanner and the sanitized-dispatch proof apply, and local-only egress refuses the route.

Native validation cannot see the daemon. `trestle setup bootstrap` checks that its `/api/tags` entries name `https://ollama.com` as `remote_host`. No v7 JSON Schema is published. See [Ollama signed in to Ollama Cloud](remote-model-review.md#ollama-signed-in-to-ollama-cloud).

Runtime policy v8 accepts generic connections and the `openrouter_zdr_chat_v2` profile. In that profile, `brokered_route_authority` has exactly `route_record_identity`, `evidence_manifest_digest`, `tenant_id`, `repository_id` and `provider_slugs`. The slugs are at most 32 distinct values and may be none. There is no account identity, single slug or validity window.

The route's record must carry an OpenRouter privacy witness of schema version 3, which setup records from OpenRouter's public API. The witness holds the route, the credential reference, the scope, `zero_data_retention: required_per_request`, the pinned slugs and their source. It may also hold an optional observation with both API addresses, the SHA-256 and time of each response and the pinned endpoint facts. The observation is labelled as reported by the API and not reviewed.

Every request sets `provider.zdr` and `require_parameters`. When slugs are pinned, the request sends `only` with them and `allow_fallbacks` true, so OpenRouter may retry only inside the pinned slugs. It sends no `order`. The v1 profile pins its one slug with `only` and `order` and allows no fallback.

Versions 3 to 7, the `openrouter_zdr_chat_v1` profile and witness version 2 keep their bytes and identities. No v8 JSON Schema is published. See [OpenRouter zero data retention](openrouter-zdr-profile.md).

Runtime policy v1 keeps its original wire and identity contract. Its `preferred_route_record_identities` are ordered ranking hints, not a verifier-route grant.

Runtime policy v2 requires `verification_route_record_identity`, an exact nonzero record identity in the bound route inventory. The policy binds that grant and the version into a distinct policy identity. The local route-pair resolver accepts only the v2 explicit grant plus a generation pin. It checks local eligibility and independence before it produces a preliminary pair, and it never derives verifier authority from the preferred-route list.

This startup pair is not authorization for an actual sanitized request, does not permit fallback and does not enable dispatch by itself. Previously stored v1 plans and policy identities remain readable. New full-local admission requires an explicit v2 verifier grant, and an unbound or ineligible pair fails startup before a run is admitted.

That failure is a refusal caused by the operator's configuration. It is not the explicit, durable abstention that is required when the verifier is lost or coverage has gaps after admission.

Three schemas cover GitHub source brokering: the source-broker descriptor v1, the configuration-only permission-admin result v2 and the integration-only check request v2. The descriptor keeps its native 20 fields, `single_host_exclusive` ownership and explicit booleans for token creation and demand renewal. Its schema date pattern is structural. Native source parsing validates the dates and normalizes any trailing endpoint slashes it accepts. Setup and admin separately require an API year of 2000 or later.

Setup schemas:

- `schemas/setup/setup-command-result-v1.schema.json`
- `schemas/setup/setup-plan-v1.schema.json`
- `schemas/setup/setup-check-receipt-v1.schema.json`
- `schemas/setup/setup-init-request-v1.schema.json`
- `schemas/setup/setup-check-request-v1.schema.json`
- `schemas/setup/setup-check-request-v2.schema.json`
- `schemas/setup/offline-bundle-signature-statement-v1.schema.json`
- `schemas/setup/setup-session-v1.schema.json`
- `schemas/setup/setup-check-result-v1.schema.json`
- `schemas/setup/setup-error-v1.schema.json`

Integration request v2 has exactly nine required fields: `contract`, `schema_version`, `plan_identity`, `key`, `confirmation`, `approve_integration_permission_authority_identity`, `approve_github_source_broker_authority_identity`, `allow_github_installation_token_creation` and `approved_by`. Consent must be boolean true, and `confirmation` is exactly `create GitHub installation token and run integration_permissions_validated`. Credential creation is an explicitly approved effect, not authority that a bearer token alone carries. The host cap and the request approvals remain independent.

Historical integration request v1 remains published but cannot be executed. Unrelated v1 requests keep their semantics. Current plans, receipts, sessions and results keep schema 1. An old Ready state remains readable and historical, and is not upgraded automatically into authority. Migration needs fresh protected state and a rerun of all nondeterministic checks, without importing old receipts.

The admin v2 output has exactly seven fields: the contract, the schema version, the `configuration_only` status, the `identity` operation, and `broker_authority_identity`, `setup_issuance_authority_identity` and `permission_authority_identity`. It grants no observed or executable authority. See [Setup planning](setup.md#github-integration-permissions) and [local setup API](daemon-api.md#local-setup-api).

Diagnostic schemas:

- `schemas/diagnostics/verified-diagnostic-set-v1.schema.json`
- `schemas/diagnostics/verified-diagnostic-set-v2.schema.json`
- `schemas/diagnostics/verified-diagnostic-set-v3.schema.json`
- `schemas/diagnostics/verified-diagnostic-set-v4.schema.json`
- `schemas/diagnostics/verified-diagnostic-set-v5.schema.json`
- `schemas/diagnostics/deterministic-diagnostic-set-v6.schema.json`
- `schemas/diagnostics/full-review-diagnostic-set-v7.schema.json`
- `schemas/diagnostics/verified-diagnostic-set-v8.schema.json`

Webhook schemas:

- `schemas/webhook/verified-delivery-v1.schema.json`
- `schemas/webhook/response-v1.schema.json`

The daemon API response carries exactly one of these: a run receipt, an immutable run plan, a task lease, a task-notification lease, a diagnostic set or a sanitized error. The diagnostic versions differ as follows.

- Versions 1 through 5 contain independently verified finding contracts.
- Version 8 is version 5 plus a recorded line side on each finding. It is written exactly when a verified finding is on removed base lines.
- Version 6 contains deterministic observations and does not present them as verified findings.
- Version 7 is a final-only full-review result with a terminal outcome and optional exact records: a version 6 deterministic record and a version 5 verified record (or, with a base-side finding, version 8). Absent verified evidence does not mean zero verified findings.

A failed version 7 result without verified evidence also carries `context_refusal` when its context task recorded a route refusal. It holds the `reason` (`route_context_insufficient` or `no_eligible_route`) and, for the former, the same `context_shortfall` counts as the task. These are bound into the set identity.

A version 7 result recorded after the run's evidence retention lapsed carries `evidence_expired: true`, has no `deterministic` or `verified` part and has an empty source. Its outcome is never `completed`, only what the run journal proves, and absent evidence means unknown, not clean.

Active task status stays in the unchanged run receipt. Evidence counts that are bound separately use the run-progress response, not a provisional diagnostic set. Nested contracts are referenced by their schema URNs.

Every schema has a stable, versioned `urn:open-trestle:schema:...` identity, rejects unknown object properties and declares explicit bounds. Repository tests compare the canonical top-level record shape and constants of the plan, receipt, event, lease and completion encoders with these documents.

A `review-task-lease` and a `task-notification-lease` contain bearer secrets, so they are suitable only for the authorized worker transport. Do not place either in logs, diagnostics, URLs, model context, audit events or public state. `review-run-receipt` and `review-run-event` are intentionally free of secrets.

The v5 `context_input_prepared` event advances the exact v4 packet checkpoint under the same task, attempt, lease and worker. Its public descriptor is made of claims about artifact envelopes and route and scanner identities. It is not proof of a scanner run, a route selection, a stored sanitized request or an authorization. It contains no recoverable request, receipt, input, authorization or repository bytes.

Neither this event nor a route-audit subject grants task success or model authority. Ordinary completion, lease renewal and expiry reclaim remain blocked. After the lease expires, trusted recovery may append a no-output policy failure. A distinct, owner-only v6 `context_input_settled` event can settle a recorded v5 preparation, but only after exact proof of the stored bytes, the audit and the scoped selection. Generic task completion cannot do so. Existing v1 through v4 encodings and v3 abstention behavior remain unchanged.

Consumers must treat all strings, tool descriptions, repository material and webhook fields as data, not instructions, even after structural validation (see the [prompt-injection boundary](prompt-injection-boundary.md)). A schema-valid document does not imply publication authority, provider access or policy approval. Those decisions require the corresponding policy and effect receipts.
