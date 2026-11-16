# Protocol contracts

Open Trestle publishes JSON Schema 2020-12 documents for transport implementers. Repository validation resolves every local fragment and internal Open Trestle URN reference offline; unknown targets, missing fragments, malformed JSON Pointers, and external schema references fail the test suite. Runtime parsers remain the enforcement authority. Setup-plan parsers replay the embedded checker catalog and receipt chain before accepting readiness. They additionally require canonical field order and encoding, content-addressed identity recomputation, sorted collections, graph safety, state-transition semantics, tenant lineage, and bounded byte size. Passing a schema alone never grants authority. Runtime-status schemas constrain years 1970 through 9999 and Gregorian leap days. Runtime-status parsers also enforce calendar-valid UTC millisecond timestamps, repository projection, unique sorted handler kinds and components, backend compatibility, and conditional review, route, worker, and publication rules that schemas cannot express completely. The executable review-context packet is generation context version 9 and the verification-context packet is version 8; counted source omissions are part of their request identities and coverage equations.

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

Route-reference schema v1 remains the historical untagged model grammar with unchanged bytes. Schema v2 preserves the six-field wire shape and adds one optional final `:tag` in `model_id`; tagged model IDs require empty `model_version`. Untagged model IDs retain the existing nonempty-version selector behavior. Host:port and opaque-URI-looking tagged values are inert model text, never endpoint, filesystem, or credential authority. The runtime inventory and durable route authorization v1 schemas already bound these fields broadly; native route validation enforces the stronger grammar. The capability-declaration v1 schema still references the historical route-reference v1 subset. No schema version changes route identity preimages. Native Go tests exercise selector semantics; schema tests check structure and unchanged v1 bytes, not full JSON Schema semantic validation.

Candidate batch schema v1 keeps its bytes and is the output schema of recorded generation contexts before version 7. Schema v2 is the output schema of version 7, 8 and 9 generation contexts: every candidate adds a required closed `category` (`correctness`, `security`, `concurrency`, `performance`, `reliability`, `maintainability`, `style`, `documentation`, `testing`) and an optional nonblank plain-text `fix` of at most 256 characters (the schema `maxLength`; the host parser enforces the same 256-character bound plus a 1024-byte UTF-8 wire bound, which 256 characters can never exceed). Both are advisory model output. The fix is never applied, carries no executable authority, and is not independently verified; runtime admission drops, and counts, a candidate whose `source_range` names a `repository_context` source. From generation context version 8 a candidate may instead be located in a `removed_lines` source, as a base-side finding.

The investigation output schema uses a closed `oneOf`: a candidate batch or one host-defined snapshot tool call. A valid proposal is not permission to execute a tool. Runtime parsing, the retained model response, source bindings, and policy limits still govern admission.

No JSON Schema is published for the `open-trestle/local-git-model-review-result` receipt of `trestle local-git model-review`, at any of its versions 1 through 6. Version 5 adds optional style advice, `style_recommendations`, `style_withheld`, `style_configuration_unread` and `style_advice_unavailable`, to the version 4 fields, or to the `investigation` object of a version 2 investigation result. Version 6, written for every run that opened and for a review refused before it opened because a spending limit is reached (`failure_detail` `spending_limit_reached`, without `token_usage`), keeps every earlier field and adds `token_usage` (provider-reported input, output and cached-input tokens summed over the claimed route attempts, with generation and verification shares, and the counts absent unless every attempt reported usage) and per-turn token counts on investigation turns. A completed direct version 6 result also carries, in place, `rank` (every distinct verified finding in rank order with the duplicates merged into it), `pre_existing` (findings on unchanged lines that cite no change evidence; advisory on import, where the readiness `ci_disposition` is required), `declaration_anchors` (the changed declaration that holds a finding, used only to merge duplicates) and `walkthrough`. The fields, versions, and readback rules are documented in [local model review](local-model-review.md#results-and-limits); the strict native parser (`localreview.ParseCompletedResult`) is the enforcement authority.

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

The API response v1 envelope's `run` member is the canonical receipt v1, v2, or v3, whichever the run's state needs; like its `diagnostics` member, it names the embedded record's own version. The task completion request v1 likewise carries task completion v1, v2, or v3. The run-progress response v1 is a separate read-only HTTP envelope with exactly `contract`, `schema_version`, `request_id`, `run`, and `progress`. It references the canonical receipt v1, v2, or v3. Its four axes are `change`, `deterministic`, `context`, and `verification`, each with a bounded state, optional immutable artifact identity, and only its declared count fields. The schema inventory contains 140 documents. The strict native client additionally validates scope, completed-task binding, exact non-context output identities, count equations, and checked-versus-applicable bounds. Schema validation cannot establish artifact lineage or receipt-head consistency.

The delivery-refusal response v1 is another read-only envelope, with exactly `contract`, `schema_version`, `request_id`, and `refusal`, the canonical `open-trestle/webhook-delivery-refusal` v1 record of an accepted webhook delivery that intake refused instead of opening its run: tenant, repository, source, deduplication key, delivery and planner identities, the reason token, and the refusal time. It carries no delivery content. Errors use the api-response envelope.

`not_run` and `unavailable` carry no counts; absent counts mean unknown, not zero. Only an evidenced incomplete deterministic check uses `partial`. The available context artifact identity is the source-proven context packet, which can differ from the receipt's sanitized generation-input output after v6 settlement. Other available axis identities equal their corresponding completed task outputs. The daemon uses at most ten indexed scoped artifact loads and existing canonical parsers, checks the unchanged receipt head, and returns `409 progress_changed` on advancement. It writes no provisional diagnostics, grants no approval, and performs no model or publication effect. `runs status --format progress` emits a single bound `{run, progress}` object rather than the HTTP envelope. See [read-only run progress](daemon-api.md#read-only-run-progress).

The local file-backed full-review context worker emits a v3 `context_abstention_prepared` event before writing any abstention artifact. Its bounded canonical artifact envelope contains omission metadata only, not repository source bytes or a model claim. Recovery must verify the exact scope, plan, task, provenance, failure class, and artifact identity before a v2 failed-task event links the result. Old v1 no-output failures and v2 linked failures remain readable. The PostgreSQL journal's current 1 MiB event limit does not qualify v3; local full review rejects nonlocal stores.

A failed source acquisition may record one closed, content-free reason: `no_merge_base` (the requested base and the head share no history), `nothing_to_review` (the head equals the requested base or is already contained in it), or `merge_base_unavailable` (the forge did not report a usable merge base). `NewSourceTaskFailureWithReason` binds the reason, failure class, plan, and task into a v3 task completion; the coordinator admits it only for an `acquire_source` task of that plan and records it in a v7 `task_failed` event with an empty output. Replay restores the reason on the task until a retry makes the task available again, and a receipt with any task reason is receipt v3, whose task item adds `failure_reason`. The reason is never forge or repository text. Earlier event, completion, and receipt versions keep their bytes and identities.

A context assembly task refused before any model effect records one of two route reasons on the same v3 completion, v7 `task_failed` event and v3 receipt: `route_context_insufficient`, when the request's byte-based reservation (an upper bound on its input tokens plus the output allowance) exceeds every candidate route's declared context, or `no_eligible_route` for any other route refusal. `NewContextTaskRefusal` binds the policy failure, reason, plan, and `assemble_context` task. `route_context_insufficient` always carries, and only it carries, a `context_shortfall` object with `required_tokens` (equal to `estimated_input_tokens` plus `max_output_tokens`), `estimated_input_tokens`, `max_output_tokens`, and `declared_context_tokens` (the largest declared context among the routes too small, below the required tokens). The counts are bound into the completion and event identities and restored by replay. A source reason is admitted only for `acquire_source` and a route reason only for `assemble_context`.

A candidate generation or verification attempt the provider answered with a refusal records one of seven provider reasons on the same v3 completion, v7 `task_failed` event and v3 receipt, named from the HTTP status alone: `provider_payment_required` (402), `provider_model_unavailable` (404), `provider_model_retired` (410), `provider_authentication_failed` (401), `provider_authorization_denied` (403) and `provider_request_rejected` (the route failure `request_rejected`: 400 or 422 for an invalid request, such as an unknown model ID or an unsupported parameter, and 405 or 415 for a method or media type the endpoint does not take), each with failure `policy`, and `provider_rate_limited` (429) with failure `transient`. The route failure class `request_rejected` is never retried and leaves another route eligible for fallback; no published record can carry it, because the route execution record v1 and the investigation turn v1 hold successful attempts only, so it appears only in the completed-attempt record that is not in any release, which reads it in place. An attempt the provider answered with a reply the adapter refused (the route failure `invalid_response` after the request was sent: a malformed, truncated or otherwise unaccepted 200, or a status no other class names, such as 409) records `provider_response_invalid` with failure `internal`; the reason names neither the reply nor its fields. An attempt whose reply was accepted and stopped normally, but whose answer the review parser refused as not a valid review document (not one JSON document, a refusal, the wrong shape, or a document the review rules refuse), records `model_output_invalid` with failure `internal`; it names neither the answer nor its fields, and a host input check or a reply stopped at the output limit or a content filter records none. `NewModelTaskFailureWithReason` binds the reason, its one failure, the plan, and a `generate_candidates` or `verify_candidates` task; any other pairing is refused by the completion, the event, replay and the receipt. A 429, or a 503 that names a `Retry-After` in seconds, is a `rate_limited` refusal with known zero usage and reaches the task only after the model handler's same-route retries: within the task's one attempt, `NewRateLimitedRetryAttemptAuthorization` grants each of at most two retries (`NewRateLimitRetryPolicy`) after a rate limit settled at known zero usage (or, from an adapter that records none, unknown usage) as its own route attempt with the same request, route and terms, taking over the refused attempt's reservation instead of reserving again, and `IsSameReservationRetryOf` recognizes that lineage when a generation result or rejection is read back. The task records `provider_rate_limited` when the last retry is rate-limited too or no retry is allowed. The daemon's startup proofs read each refused attempt from the audit as a claim, a completed dispatch without a response and its reconciliation, followed by a retry claim whose causal parents are the selection, the refused outcome and the retry decision; with the artifacts retained, `SameReservationRetryIdentity` derives the identity each retry claim must carry from the input's authorization and those recorded identities. No recorded format changes.

A v4 `context_packet_prepared` event stores only packet artifact metadata, exact identity, creation/expiry, source root/snapshot, upstream dependencies, scope, task, attempt, exact lease identity, original lease event identity, and lease token identity. The file journal fsyncs this checkpoint before a caller may put packet bytes. This first checkpoint cannot settle success, renew or reclaim the lease, or authorize dispatch. Trusted recovery may terminally fail an expired packet-only preparation with a policy-class, no-output task failure without a reason. Within the lease, its holder may instead settle the packet-only preparation as a recorded route refusal: the same no-output policy failure carrying `route_context_insufficient` with its counts or `no_eligible_route`, no later than the lease expiry. Neither can treat the preparatory packet as output. This does not implement the later sanitized-input checkpoint or verify packet bytes against immutable upstream sources. v1/v2/v3 event bytes remain unchanged.

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

Each of these versioned artifact schemas describes exactly one version, and later versions are separate files. The version 1 files of the candidate batch and verified finding set are as first published; the generation input v1 file differs only in also admitting the identity of the v2 candidate schema that a version 7 or later context requests.

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

A spending limit v1 (`open-trestle/spending-limit`) is one API key's local limit: the provider ID, the key variable name and its credential reference identity (the same SHA-256 of `open-trestle/provider-credential-environment/` and the name that every runtime policy connection and setup witness records), a calendar `period` in UTC (`week` from Monday, `month`, `year`), `limit_micro_usd` in whole cents and ascending `alert_percents`. A usage ledger entry v1 (`open-trestle/usage-ledger-entry`) is one review run that sent at least one request through a keyed route: its time, review run ID, runtime policy identity, the keys and models it used, the requests sent, `usage_known`, and `cost_micro_usd`, the settled cost (`cost: settled_usage`) or, when usage was unknown, each such request at the cost reserved for it (`cost: reservation_upper_bound`), always with `price_basis: route_max_price`. Both are stored by `trestle` in the private usage folder (`$XDG_STATE_HOME/open-trestle/usage`, by default `~/.local/state/open-trestle/usage`, mode `0700`, files `0600`), never hold a key, source, prompt or reply, and are an upper-bound estimate, not a bill; the native parsers (`spending.ParseLimit`, `spending.ParseEntry`) additionally require the canonical encoding, the derived identities and sorted keys and models. A limit is best effort, and the provider's own limit is the guarantee. See [spending limits](spending-limits.md).

Runtime policy v3 adds the closed `openrouter_zdr_chat_v1` profile and the eight-field `brokered_route_authority`. Versions 1 and 2 retain their schema bytes and accepted identity preimages. Native v3 validation requires a typed version 2 `openrouter_privacy` witness inside the existing immutable evidence manifest: exact full route/effective selector, connection/profile/auth, slug and `all_slug_matches` scope, account/credential-reference with effective-account Safety Retention denial for Google and other providers, tenant/repository, source evidence, explicit retention exceptions and exact validity window. A nonzero manifest digest alone is not privacy approval. The existing v3 schema bytes remain unchanged; this semantic requirement is enforced by the native parser and common catalog, not JSON Schema alone.

The binding follows policy record identity and evidence digest -> immutable manifest -> typed witness, plus `account_policy_identity` derived from the fixed versioned account subsection. There is no second policy approval list or self-hash. Missing or invalid typed evidence, a policy-only mismatch or an arbitrary account digest refuses the named profile at its next validation; generic opaque-manifest v1/v2 admission is unchanged. No automatic rewrite or setup receipt upgrade is allowed. Renewed evidence changes manifest/record/inventory/policy identities and requires fresh exact setup approval. The daemon consumes protected configuration, not setup receipts. Syntax and linkage cannot prove provider conduct, account ownership or unconditional non-retention. See [the profile contract and offline account calculation](openrouter-zdr-profile.md#typed-privacy-witness).

Runtime policy v4 adds only the finite `opencode_go_chat_v1` Chat profile and its seven-field `opencode_go_authority`. Generic connections and the existing v3 OpenRouter profile remain supported in v4; the two named authority fields are mutually exclusive, including null presence. Historical v1/v2/v3 schema bytes and accepted identity preimages remain unchanged. Native validation binds the exact Go route/effective model selector, immutable typed `opencode_go_privacy` evidence, derived account/credential-reference identity, tenant/repository and validity window. Structure alone cannot validate these bindings, evidence substance, account ownership, conservative pricing or provider conduct. The native schema tests inspect structure and frozen legacy bytes; they do not execute a JSON Schema validator. The setup checker supports an exact approved Go generation route and a distinct private direct verifier. Setup support grants no dispatch authority or implied readiness. See [OpenCode Go profile](opencode-go-profile.md).

Runtime policy v6 is a generic policy with the v2 exact verifier grant and an optional boolean `local_structured_output`. True requires generic Chat Completions at a canonical numeric-loopback endpoint, bearer or explicit no-auth credentials, and a local inventory namespace. V6 excludes all named request-profile and authority fields. False and omission have the same v6 binding bytes and identity, not the v2 identity. Native versions 1 through 5 reject the option, including false; published v1 through v4 schema bytes remain unchanged. The binder preserves explicit v6 and keeps historical option-free v1/v2 templates on v2 without changing their binding bytes or identity preimages. Native validation enforces inventory locality; schema checks do not prove route approval, server support or model quality. See [local Chat schema transport](local-model-review.md).

Runtime policy v7 carries only the closed `ollama_signin_chat_v1` profile, for a local Ollama daemon that relays Ollama Cloud models with the operator's `ollama signin` account. Every v7 connection must name that profile and must use Chat Completions, explicit `credential_mode` `none`, an endpoint of exactly `http://127.0.0.1:PORT/v1`, and no authority object or `local_structured_output`; its adapter namespace must hold only approved `private_remote` routes with provider ID `ollama-signin`, no model version, disabled content logging and a model ID whose tag is `cloud` or ends in `-cloud`. This is the only loopback endpoint admitted for a non-local zone: with no profile or any other profile, at any version, a loopback endpoint still binds only the local zone. Because the zone is `private_remote`, the sanitizer, secret scanner and sanitized-dispatch proof apply and local-only egress refuses the route. Native validation cannot see the daemon; `trestle setup bootstrap` checks that its `/api/tags` entries name `https://ollama.com` as `remote_host`. No v7 JSON Schema is published. See [Ollama signed in to Ollama Cloud](remote-model-review.md#ollama-signed-in-to-ollama-cloud).

Runtime policy v8 admits generic connections and the `openrouter_zdr_chat_v2` profile, whose `brokered_route_authority` has exactly `route_record_identity`, `evidence_manifest_digest`, `tenant_id`, `repository_id` and `provider_slugs` (at most 32 distinct slugs, possibly none) and no account identity, single slug or validity window. Its record must carry an OpenRouter privacy witness of schema version 3, which setup records from OpenRouter's public API: the route, credential reference, scope, `zero_data_retention: required_per_request`, the pinned slugs and their source, and an optional observation with both API addresses, the SHA-256 and time of each response and the pinned endpoint facts, labelled as reported by the API and not reviewed. Every request sets `provider.zdr` and `require_parameters`. When slugs are pinned it sends `only` with them and `allow_fallbacks` true, so OpenRouter may retry only inside the pinned slugs, and it sends no `order`. The v1 profile pins its one slug with `only` and `order` and allows no fallback. Versions 3 to 7, the `openrouter_zdr_chat_v1` profile and witness version 2 keep their bytes and identities. No v8 JSON Schema is published. See [OpenRouter zero data retention](openrouter-zdr-profile.md).

Runtime policy v1 keeps its original wire and identity contract. Its `preferred_route_record_identities` are ordered ranking hints, not a verifier-route grant. Runtime policy v2 requires `verification_route_record_identity`, an exact nonzero record identity in the bound route inventory. It binds that grant and version into a distinct policy identity. The local route-pair resolver accepts only the v2 explicit grant, plus a generation pin, and checks local eligibility and independence before producing a preliminary pair. It never derives verifier authority from the preferred-route list. This startup pair is not authorization for an actual sanitized request, does not permit fallback, and does not enable dispatch by itself. Previously persisted v1 plans and policy identities remain readable. New full-local admission requires an explicit v2 verifier grant; an unbound or ineligible pair fails startup before a run is admitted. This is operator-configuration refusal, not the explicit durable abstention required for verifier loss or coverage gaps after admission. That later per-run outcome and the actual-request verifier gate are not implemented by startup validation.

Three schemas cover GitHub source brokering: the source-broker descriptor v1, the configuration-only permission-admin result v2, and the integration-only check request v2. The descriptor retains its native 20 fields, `single_host_exclusive` ownership, and explicit token-creation and demand-renewal booleans. Its schema date pattern is structural; native source parsing validates dates and normalizes admitted trailing endpoint slashes. Setup/admin separately require API year >=2000. Schema validation never opens an owner or approves effects.

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

Integration request v2 has exactly nine required fields: `contract`, `schema_version`, `plan_identity`, `key`, `confirmation`, `approve_integration_permission_authority_identity`, `approve_github_source_broker_authority_identity`, `allow_github_installation_token_creation`, and `approved_by`. Consent must be boolean true, and confirmation is exactly `create GitHub installation token and run integration_permissions_validated`. Credential creation is an explicitly approved effect, not bearer-only authority. The host cap and request approvals remain independent.

Historical integration request v1 remains published but is non-executable; unrelated v1 requests keep their semantics. Current plans, receipts, sessions, and results retain schema 1. Old Ready remains readable and historical, not auto-upcast authority. Migration requires fresh protected state and rerunning all nondeterministic checks, without importing old receipts. The admin v2 output has exactly seven fields: contract, schema version, `configuration_only` status, `identity` operation, and `broker_authority_identity`, `setup_issuance_authority_identity`, and `permission_authority_identity`. It grants no observed or executable authority. See [Setup planning](setup.md#github-integration-permissions) and [local setup API](daemon-api.md#local-setup-api).

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

The daemon API response carries exactly one run receipt, immutable run plan, task lease, task-notification lease, diagnostic set, or sanitized error. Diagnostic versions 1 through 5 contain independently verified finding contracts. Version 8 is version 5 plus a recorded line side on each finding; it is written exactly when a verified finding is on removed base lines. Version 6 contains deterministic observations and does not represent them as verified findings. Version 7 is a final-only full-review result with a terminal outcome and optional exact version 6 deterministic and version 5 (or, with a base-side finding, version 8) verified records; absent verified evidence is not zero verified findings. A failed version 7 result without verified evidence also carries `context_refusal` when its context task recorded a route refusal: the `reason` (`route_context_insufficient` or `no_eligible_route`) and, for the former, the same `context_shortfall` counts as the task, bound into the set identity. A version 7 result recorded after the run's evidence retention lapsed carries `evidence_expired: true` and no `deterministic` or `verified` part, with an empty source; its outcome is never `completed`, only what the run journal proves, and absent evidence is unknown, not clean. Active task status remains in the unchanged run receipt. Separately bound evidence counts use the run-progress response, not a provisional diagnostic set. Nested contracts are referenced by their schema URNs.

Every schema has a stable versioned `urn:open-trestle:schema:...` identity, rejects unknown object properties, and declares explicit bounds. The plan, receipt, event, lease, and completion encoders have repository tests that compare their canonical top-level record shape and constants with these documents.

A `review-task-lease` and a `task-notification-lease` contain bearer secrets. It is suitable only for the authorized worker transport. Do not place it in logs, diagnostics, URLs, model context, audit events, or public state. `review-run-receipt` and `review-run-event` are intentionally secret-free.

The v5 `context_input_prepared` event advances the exact v4 packet checkpoint under the same task, attempt, lease and worker. Its bounded public descriptor is untrusted claims about artifact envelopes and route/scanner identities. It is not proof of an actual scanner run, route selection, audit join, stored sanitized request, receipt, generation input or authorization. It contains no recoverable request, receipt, input, authorization, or repository bytes. Neither this event nor a route-audit subject grants task success or model authority. Ordinary completion, lease renewal and expiry reclaim remain blocked. Trusted recovery may append a no-output policy failure after lease expiry. A distinct owner-only v6 `context_input_settled` event can settle a recorded v5 preparation only after exact stored-byte, audit, and scoped selection proof; generic task completion cannot do so. Existing v1-v4 encodings and v3 abstention behavior remain unchanged.

Consumers must treat all strings, tool descriptions, repository material, and webhook fields as untrusted data even after structural validation. They must not infer publication authority, provider access, or policy approval from a schema-valid document. Those decisions require the corresponding content-addressed policy and effect receipts.
