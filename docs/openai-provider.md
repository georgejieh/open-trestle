# OpenAI Responses provider adapter

`adapters/providers/openai` implements the gateway `RouteDispatcher` contract for the [OpenAI Responses API](https://platform.openai.com/docs/api-reference/responses). Its request and response fields follow the official [`openai/openai-openapi`](https://github.com/openai/openai-openapi) contract. The adapter is an execution boundary. Route policy, provider eligibility, privacy classification, budget reservation, retry decisions, and fallback selection remain gateway responsibilities.

## Exact route binding

An adapter instance binds these values:

- provider zone
- provider ID
- adapter ID
- connection ID
- declared content-logging mode
- HTTPS endpoint, or an HTTP endpoint on an IP-literal loopback address
- endpoint locality that matches the route zone: numeric loopback for `local`, non-loopback HTTPS for `private_remote`
- no `localhost` or `*.localhost` names, unspecified addresses, link-local addresses, or multicast addresses

A dispatch must match all bound values. A mismatch fails before credential retrieval or network access. Register instances in `gateway.RouteDispatcherCatalog` by their exact adapter IDs.

If the route declares a model version, that exact version is sent as the API `model` selector. Otherwise, the model ID is sent. The returned `model` must match the same selector exactly. A pinned version must be a model selector accepted by the configured Responses API; the adapter does not dispatch a moving alias and check its version only afterward.

## Request and response contract

The adapter sends the provider-neutral request payload as one user `input_text` item. It also copies the exact identity-bound host instructions into the Responses API `instructions` field, which gives them system or developer-message priority over repository-controlled input. A missing instruction contract fails before credential retrieval. Standard candidate-generation and independent-verification requests can use numeric-loopback `local` routes or approved `private_remote` routes. A private-remote request must be the exact sanitized request authorized by the model handler and must carry that handler's opaque, receipt-bound dispatch proof. The generic dispatcher still denies non-local repository context before credential retrieval. New candidate-generation and verifier context packets use input schema version 3. Each contains fixed host instructions, the complete canonical `output_schema`, and its `output_schema_identity`. The provider request identity binds the complete sanitized payload, including those contract bytes. Source, memory, and candidate text cannot select or replace the host contract. The adapter does not enable provider tools or execute model-proposed actions.

The schemas are readable output guidance, not provider-enforced constrained decoding. This adapter does not request strict JSON schema mode. The canonical schemas use JSON Schema features that some provider subsets do not support. Output still requires host parsing, evidence admission, independent verification, and publication authorization. Readable guidance does not guarantee model correctness.

Historical version 2 context and result records remain readable with their exact original bytes and identities. They are not enriched into version 3. Historical parsing does not authorize a new model attempt: current generation and verifier execution require version 3. Generic opaque provider request version 1 identities and the output schemas' version 1 contracts remain unchanged.

Review route selection reserves an input estimate of `max(declared_estimated_input_tokens, payload_bytes + system_channel_bytes + 256)`. The system channel is the trusted host contract and any specialist guidance that the adapter sends as the system message; a sanitized request or a local verification envelope is measured by the request the adapter unwraps. When a planned route uses the [local Chat schema transport](local-model-review.md#chat-completions-transport), the estimate also adds the serialized `response_format` bytes that transport sends. The 256 units are a fixed framing reserve. The full encoded payload includes schemas, context, and JSON escaping. Investigation turns use the same estimate and record the system channel bytes in each turn record (estimate version 2); turn records written under estimate version 1 counted the payload alone and read back with that formula. This is a byte-based planning estimate, not exact tokenization or a guarantee for every provider tokenizer. Capacity and price checks use that estimate without increasing the declared output limit or monetary cap. Reported usage still requires cost reconciliation. The full provider payload remains bounded at 8 MiB.

Every request includes:

- the exact authorized model version, or model ID when unpinned
- the identity-bound host instructions at instruction priority
- the authorized maximum output-token count
- `store: false`
- no tool declarations

`store: false` is not a substitute for account-level retention controls. The configured content-logging mode must match the approved route record. Operators are responsible for making that declaration match the provider account and connection controls.

The adapter accepts completed responses and the closed incomplete reasons `max_output_tokens` and `content_filter`. It discards provider reasoning items, preserves assistant text and refusals, and represents valid JSON output as structured data. Unknown output item types, duplicate JSON keys, case-variant JSON keys, model mismatches, invalid usage, and excessive content fail closed. A reply that stopped at the output limit with no answer, or with answer text that is not one complete JSON value, fails as `output_exhausted` but keeps the usage it reported, checked as for a successful reply, so its cost settles from that usage; without valid usage it stays unknown. A rate limit (429, or a 503 that names a `Retry-After` in seconds) is a refusal before processing, so it reports known zero usage. Every other failed dispatch reports unknown usage.

## Transport and credentials

Credentials are retrieved for each request through `APIKeyProvider`. Keys are bounded, header-safe values and redact themselves during formatting. Redirects are rejected so authorization headers cannot move to another origin. Response bodies, error bodies, headers, and request duration are bounded.

HTTP failures become closed gateway classes without retaining provider error text. Network ambiguity, server errors, malformed successful responses, and timeouts use `outcome_unknown` replay safety. The gateway will not retry those outcomes automatically. Explicit rate-limit responses can carry a bounded `Retry-After` delay and are marked as having no model side effect and known zero usage. A 503 that names a `Retry-After` in seconds is classified as a rate limit too; a 503 without one, or with an HTTP date or zero, stays `provider_server`.

Every request profile, the OpenCode console included, classifies a non-200 status the same way, from the status alone. The error body is drained unread, so a provider's message never reaches a result, record or log:

| Status | Class | Replay safety |
|---|---|---|
| 400, 422 | `request_rejected` (the request is invalid, for example an unknown model ID or a parameter the model or endpoint does not accept) | `no_side_effect` |
| 401 | `authentication` | `no_side_effect` |
| 402 | `payment_required` (billing or quota) | `no_side_effect` |
| 403 | `authorization` | `no_side_effect` |
| 404 | `model_unavailable` (model or endpoint not served) | `no_side_effect` |
| 405, 415 | `request_rejected` (the endpoint does not take the method or media type) | `no_side_effect` |
| 408, 504 | `timeout` | `outcome_unknown` |
| 410 | `model_retired` | `no_side_effect` |
| 413 | `budget_exhausted` | `no_side_effect` |
| 429 | `rate_limited`, with a bounded `Retry-After` and known zero usage | `no_side_effect` |
| 503 with a `Retry-After` in seconds | `rate_limited`, as 429 | `no_side_effect` |
| other 5xx | `provider_server` | `outcome_unknown` |
| any other, for example 409 | `invalid_response` (an unexpected answer) | `no_side_effect` |

A 200 whose reply the adapter refuses (malformed, truncated, empty or oversized, a Chat Completions reply with an unrecognized field (for OpenRouter, in the answer rather than its [routing metadata](openrouter-zdr-profile.md#how-a-reply-is-read)), or otherwise not the strict document above) is `invalid_response` too, with `outcome_unknown` replay safety.

`payment_required`, `model_unavailable`, `model_retired` and `request_rejected` are not transient, so the gateway never retries them, and none counts as a provider outage: the provider answered. A payment refusal is also not eligible for fallback to another route, like a spent budget; a model refusal leaves another route's model eligible, and so does a rejected request, because another route builds its own request for its own model ID, endpoint and parameters. The model handlers fail the task as a `policy` refusal for each of them, as for `authentication` and `authorization`, and record the matching `provider_*` task failure reason when the provider answered, `provider_request_rejected` for a rejected request (a rate limit is first retried on the same route at most twice inside the task attempt, after its bounded `Retry-After`, each retry taking over the refused attempt's reservation, and records `provider_rate_limited` only when every retry is rate-limited too); the local review reports them as failure details; see [local model review](local-model-review.md#provider-refusals). An `invalid_response` after the request was sent keeps the task's `internal` failure and records the `provider_response_invalid` reason and failure detail, so a refused reply is not reported as an internal bug; one before sending records none.

The adapter performs no request during construction and has no background activity.

For controlled-hybrid and Kubernetes HA setup, `trestle setup check provider` separately records named approval of the exact protected inventory, policy, endpoint locality, credential environment references, logging posture, budget, and distinct-provider route pair. That authorization reads no credential and constructs no adapter. It is not a connectivity probe or dispatch authority.

## Configuration authority

Version-first wire model selection was introduced in Responses adapter configuration identity version 3. The current Responses adapter uses version 4; Chat Completions uses its separate identity version 1. Rebuild approved dispatcher catalogs when upgrading from earlier dispatch semantics; do not reuse an old adapter configuration identity.

Each adapter requires a canonical lowercase SHA-256 `CredentialIdentity`. This identifies the credential lease or environment authority, never the secret value. The adapter derives `ConfigurationIdentity()` from its adapter, provider, connection, zone, logging, endpoint, credential-authority, HTTP timeout, and HTTP-client-authority values. The route dispatcher catalog binds that identity as well as the adapter ID. Changing a service endpoint, credential authority, or HTTP authority therefore changes the downstream model-handler identity even when the public adapter name is unchanged.

`runtimecatalog.NewOpenAIRouteDispatcherCatalog` constructs exact OpenAI adapters from a validated route inventory. Every adapter namespace in the inventory must have one connection definition. Multiple models may share one adapter only when provider, connection, zone, and logging authority are identical. Missing, extra, duplicate, or cross-wired definitions fail closed.

The direct adapter dispatches `local` routes only through numeric loopback endpoints. It accepts a non-loopback HTTPS `private_remote` route only through `DispatchSanitizedRoute`, after the trusted generation or verification handler has reloaded and jointly validated the sanitized-request and egress-receipt artifacts. A receipt has no dispatch authority by itself; authority comes from the handler-sealed proof. The proof binds the exact review scope, sanitized request identity, receipt identity, and request kind. It is opaque outside the handler package. A missing, forged, crossed-scope, stale, raw, or wrong-kind proof fails before credential retrieval or network access. Investigation requests do not have this authority and remain local-only. Generic adapters reject `brokered_remote` and `subscription_oauth`. The closed [OpenRouter ZDR Chat profile](openrouter-zdr-profile.md) adds one explicitly bound brokered route through runtime policy v3; it is not generic broker admission or OAuth support. DNS names are classified without resolving them during configuration validation. The runtime rejects conventional localhost names and non-unicast numeric addresses before credential retrieval or dispatch.

## Sanitized egress boundary

Before either standard model stage is authorized, the host extracts the typed text fields and runs an initial scan in a fresh fixed scanner process. Reported bytes are replaced without changing byte length or line breaks. A second fresh process scans the projected request. Dispatch is denied unless both scans complete and the residual scan has zero matches. Candidate generation and independent verification are sanitized separately; verification includes candidate, source, and memory text from its own typed request.

The pinned scanner is Betterleaks v1.8.1, commit `5eab48332cc48565864514e3bc6de89df091a7c4`, with 417 embedded default rules at ruleset identity `27ded783c81940d13c22cc46556a3f8184baf397bff08a69fcfae87991925f42`, RE2, and build profile `public_detect_run_re2_purego_go1.26.11_linux_amd64_v1`. New scans emit and require only that profile, from a worker whose launcher and worker digests match the values injected into the daemon. Responses and receipts recorded under the previous `public_detect_run_re2_purego_go1.26.10_linux_amd64_v1` profile still read back and validate; no other profile is accepted. A scan accepts 1 to 256 UTF-8 fields, no more than 256 KiB per field and 2 MiB decoded in aggregate. The worker deadline is five seconds and the parent watchdog is six seconds. Invalid input, timeout, cancellation, incomplete iteration, resource exhaustion, sandbox failure, unexpected output, or any residual finding produces no partial success and no remote dispatch.

Scanner output and the durable receipt are content-free. Together they retain scanner and binary identities, completion and byte counts, field roles and ordinals, rule IDs, and zero-based half-open byte spans. They do not retain field text, paths, snippets, matched values, source digests, upstream fingerprints, or provider error text. Those spans still disclose the location and length of a match, so receipt access remains scoped review evidence rather than public telemetry.

The reviewed representative corpus found 11 of 14 expected occurrences across 10 of 11 positive files under the go1.26.10 profile. The public span fixtures pass under the go1.26.11 profile; its private coverage and performance qualification is pending. The named misses are bearer credentials, AWS secret keys, and AWS session tokens. One near-miss file produced a `generic-api-key` finding at `[7,51)`, so the corresponding bytes are redacted even though the finding is not a true secret. This fixed profile is a bounded filter, not a guarantee that a request contains no secret. Operators must assume other false negatives and false positives are possible. A remote provider receives the sanitized request, and `store: false` does not replace account retention and content-logging controls.

The built-in bounded HTTP client has a derived fixed authority identity. It gives each request a deadline of two minutes per 4096 tokens of that request's output allowance, at least two and at most five minutes (`DefaultClientRequestTimeout`), so a 16384-token allowance gets five minutes; a caller's earlier deadline still wins. Its identity, version 3 of `open-trestle/openai-default-http-client`, binds the five-minute outer timeout and that rule; version 2 bound a fixed two-minute timeout, so adapter configuration identities that use the built-in client change. A caller that supplies a custom `http.Client` must provide a non-secret `HTTPClientIdentity`; its own timeout applies unchanged (two minutes when it sets none) and is also bound independently. Unidentified custom transports are rejected.
