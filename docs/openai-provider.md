# OpenAI Responses provider adapter

The adapter in `adapters/providers/openai` sends review requests to the [OpenAI Responses API](https://platform.openai.com/docs/api-reference/responses). Its request and response fields follow the official [`openai/openai-openapi`](https://github.com/openai/openai-openapi) contract. This page is for contributors and operators who need to know exactly what the adapter sends, what it accepts back, and which decisions it leaves to the gateway.

The adapter implements the gateway's `RouteDispatcher` contract, and it only executes requests. Route policy, provider eligibility, privacy classification, budget reservation, retry decisions and fallback selection stay with the gateway.

## Route binding

Each adapter instance is bound to these values:

- the provider zone
- the provider ID
- the adapter ID
- the connection ID
- the declared content-logging mode
- the endpoint, which must be HTTPS or an HTTP endpoint on an IP-literal loopback address
- an endpoint locality that matches the route zone: numeric loopback for `local`, non-loopback HTTPS for `private_remote`

The endpoint cannot be a `localhost` or `*.localhost` name, an unspecified address, a link-local address or a multicast address.

A dispatch must match every bound value. A mismatch fails before the adapter retrieves a credential or touches the network. Register each instance in `gateway.RouteDispatcherCatalog` under its exact adapter ID.

If the route declares a model version, the adapter sends that exact version as the API `model` selector. Otherwise it sends the model ID. The `model` in the reply must match the same selector exactly. A pinned version must be a model selector that the configured Responses API accepts. The adapter does not send a moving alias and then check the version afterward.

## Request and response contract

The adapter sends the provider-neutral request payload as a single user `input_text` item. It also copies the host instructions into the Responses API `instructions` field, so they take system or developer-message priority over input that comes from the repository. The instructions are bound to the request by their identity. If the instruction contract is missing, the request fails before credential retrieval.

Standard candidate-generation and independent-verification requests can use numeric-loopback `local` routes or approved `private_remote` routes. A private-remote request must be the exact sanitized request that the model handler authorized, and it must carry that handler's opaque dispatch proof, which is tied to the egress receipt. The generic dispatcher still refuses to send non-local repository context before it retrieves a credential.

New candidate-generation and verifier context packets use input schema version 3. Each packet holds fixed host instructions, the complete canonical `output_schema` and its `output_schema_identity`. The provider request identity covers the whole sanitized payload, including those contract bytes. Text from source, memory or a candidate cannot select or replace the host contract. The adapter does not enable provider tools and does not execute actions that the model proposes.

The schemas are output guidance that the model can read. The provider does not enforce them, and the adapter does not request strict JSON schema mode, because the canonical schemas use JSON Schema features that some providers do not support. The host still parses the output, admits its evidence, verifies it independently and authorizes publication. Readable guidance does not make a model correct.

Context and result records of version 2 stay readable with their original bytes and identities, and they are not upgraded to version 3. Reading an old record does not authorize a new model attempt: current generation and verifier runs require version 3. The generic opaque provider request identities (version 1) and the version 1 output schema contracts are unchanged.

### Input estimate

When Open Trestle selects a route for a review, it reserves an input estimate of `max(declared_estimated_input_tokens, payload_bytes + system_channel_bytes + 256)`.

- The system channel is the trusted host contract plus any specialist guidance that the adapter sends as the system message. For a sanitized request or a local verification envelope, the estimate measures the request that the adapter unwraps.
- When a planned route uses the [local Chat schema transport](local-model-review.md#chat-completions-transport), the estimate also adds the serialized `response_format` bytes that the transport sends.
- The 256 units are a fixed reserve for framing. The full encoded payload includes the schemas, the context and JSON escaping.
- Investigation turns use the same estimate and record the system channel bytes in each turn record (estimate version 2). Turn records written under estimate version 1 counted the payload alone, and they are read back with that formula.

The estimate is a byte-based planning figure, not exact tokenization, and it may not hold for every provider's tokenizer. Capacity and price checks use it without raising the declared output limit or the monetary cap. Reported usage still has to be reconciled against cost. The full provider payload is limited to 8 MiB.

### What every request contains

- The exact authorized model version, or the model ID when no version is pinned.
- The host instructions, at instruction priority.
- The authorized maximum output-token count.
- `store: false`.
- No tool declarations.

`store: false` does not replace account-level retention controls. The configured content-logging mode must match the approved route record, and operators are responsible for making that declaration match the controls on the provider account and connection.

### What the adapter accepts back

The adapter accepts completed responses and two incomplete reasons, `max_output_tokens` and `content_filter`. It discards provider reasoning items, keeps assistant text and refusals, and represents valid JSON output as structured data.

The adapter fails closed on any of these:

- unknown output item types
- duplicate JSON keys
- JSON keys that differ only in case
- a model mismatch
- invalid usage
- excessive content

A reply that stopped at the output limit with no answer, or with answer text that is not one complete JSON value, fails as `output_exhausted`. It keeps the usage the provider reported, checked as for a successful reply, so its cost settles from that usage. Without valid usage, the usage stays unknown.

A rate limit is a refusal before any processing, so it reports known zero usage. A rate limit is a 429, or a 503 that names a `Retry-After` in seconds. Every other failed dispatch reports unknown usage.

## Transport and credentials

The adapter retrieves a credential for each request through `APIKeyProvider`. Keys are bounded, header-safe values that redact themselves when formatted. The adapter rejects redirects, so authorization headers cannot move to another origin. Response bodies, error bodies, headers and request duration are all bounded.

### Failure classes

HTTP failures become closed gateway classes, and the adapter does not keep the provider's error text. Network ambiguity, server errors, malformed successful responses and timeouts have `outcome_unknown` replay safety, which means the gateway will not retry them automatically. An explicit rate-limit response can carry a bounded `Retry-After` delay. It is marked as having no model side effect and known zero usage. A 503 that names a `Retry-After` in seconds is classified as a rate limit too. A 503 without one, or with an HTTP date or zero, stays `provider_server`.

Every request profile, including the OpenCode console, classifies a non-200 status the same way, from the status alone. The adapter drains the error body unread, so a provider's message never reaches a result, record or log.

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

A 200 response that the adapter refuses is also `invalid_response`, with `outcome_unknown` replay safety. The adapter refuses a reply that is malformed, truncated, empty or oversized, that is not the strict document described above, or that is a Chat Completions reply with an unrecognized field. For OpenRouter, the unrecognized field check applies to the answer, not to its [routing metadata](openrouter-zdr-profile.md#how-a-reply-is-read).

### How the gateway and task handlers respond

`payment_required`, `model_unavailable`, `model_retired` and `request_rejected` are not transient, so the gateway never retries them. None of them counts as a provider outage, because the provider did answer.

- A payment refusal is not eligible for fallback to another route, just like a spent budget.
- A model refusal leaves another route's model eligible.
- A rejected request also leaves another route eligible, because another route builds its own request for its own model ID, endpoint and parameters.

The model handlers fail the task as a `policy` refusal for each of these four classes, as they do for `authentication` and `authorization`. When the provider answered, they record the matching `provider_*` task failure reason. For a rejected request that reason is `provider_request_rejected`.

A rate limit is handled differently. Open Trestle first retries it on the same route, at most twice inside the task attempt, after the bounded `Retry-After`. Each retry takes over the reservation of the attempt it replaces. The task records `provider_rate_limited` only when every retry is rate-limited too. The local review reports all of these as failure details; see [local model review](local-model-review.md#provider-refusals).

An `invalid_response` after the request was sent keeps the task's `internal` failure and records the `provider_response_invalid` reason and failure detail, so a refused reply is not reported as an internal bug. An `invalid_response` before sending records neither.

The adapter makes no request when it is constructed and has no background activity.

For controlled-hybrid and Kubernetes HA setups, `trestle setup check provider` records a named approval of the exact protected inventory, policy, endpoint locality, credential environment references, logging posture, budget and distinct-provider route pair. That approval reads no credential and builds no adapter. It is not a connectivity probe and it does not authorize dispatch.

## Configuration identity

Responses adapter configuration identity version 3 introduced version-first wire model selection. The current Responses adapter uses version 4, and Chat Completions uses its own identity version 1. When you upgrade from earlier dispatch semantics, rebuild the approved dispatcher catalogs. Do not reuse an old adapter configuration identity.

Each adapter requires a `CredentialIdentity`, a canonical lowercase SHA-256 value. It identifies the credential lease or environment authority, never the secret value. The adapter derives `ConfigurationIdentity()` from its adapter, provider, connection, zone, logging, endpoint, credential-authority, HTTP timeout and HTTP-client-authority values. The route dispatcher catalog binds that identity as well as the adapter ID. Changing a service endpoint, a credential authority or the HTTP authority therefore changes the downstream model-handler identity, even when the public adapter name stays the same.

`runtimecatalog.NewOpenAIRouteDispatcherCatalog` builds the exact OpenAI adapters from a validated route inventory. Every adapter namespace in the inventory must have one connection definition. Several models may share one adapter only when their provider, connection, zone and logging authority are identical. Definitions that are missing, extra, duplicated or cross-wired fail closed.

## Which routes the adapter can dispatch

The direct adapter dispatches `local` routes only through numeric loopback endpoints. It accepts a non-loopback HTTPS `private_remote` route only through `DispatchSanitizedRoute`. That path requires that the trusted generation or verification handler has reloaded the sanitized request and the egress receipt and validated them together.

A receipt has no dispatch authority by itself. The authority comes from the proof the handler seals. The proof is tied to the exact review scope, the sanitized request identity, the receipt identity and the request kind, and it is opaque outside the handler package. A proof that is missing, forged, from another scope, stale, raw or for the wrong kind of request fails before credential retrieval or network access. Investigation requests do not have this authority and stay local-only.

Generic adapters reject `brokered_remote` and `subscription_oauth`. The closed request profiles add explicitly bound brokered routes:

- the [OpenRouter ZDR Chat profile](openrouter-zdr-profile.md), in runtime policy v3 to v5, and v8 for the current profile
- the [OpenCode Go profile](opencode-go-profile.md), in v4
- the [OpenCode Console profile](opencode-console-profile.md), in v5

None of these is general admission of brokered routes or OAuth support.

During configuration validation, Open Trestle classifies DNS names without resolving them. At run time, the adapter rejects conventional localhost names and non-unicast numeric addresses before credential retrieval or dispatch.

## Sanitized egress boundary

Before either standard model stage is authorized, the host extracts the typed text fields and scans them in a fresh scanner process with fixed settings. It replaces reported bytes without changing the byte length or the line breaks. A second fresh process then scans the projected request. Dispatch is denied unless both scans complete and the second scan finds nothing. Candidate generation and independent verification are sanitized separately, and verification includes the candidate, source and memory text from its own typed request.

The pinned scanner is Betterleaks v1.8.1, commit `5eab48332cc48565864514e3bc6de89df091a7c4`, with 417 embedded default rules at ruleset identity `27ded783c81940d13c22cc46556a3f8184baf397bff08a69fcfae87991925f42`, RE2, and build profile `public_detect_run_re2_purego_go1.26.11_linux_amd64_v1`.

- New scans write and require only that profile, from a worker whose launcher and worker digests match the values injected into the daemon.
- Responses and receipts recorded under the previous profile, `public_detect_run_re2_purego_go1.26.10_linux_amd64_v1`, still read back and validate. No other profile is accepted.
- A scan accepts 1 to 256 UTF-8 fields, with no more than 256 KiB per field and 2 MiB decoded in total.
- The worker deadline is five seconds and the parent watchdog is six seconds.
- Invalid input, a timeout, cancellation, an incomplete iteration, resource exhaustion, a sandbox failure, unexpected output or any remaining finding produces no partial success and no remote dispatch.

The scanner output and the durable receipt contain no content. Together they keep the scanner and binary identities, completion and byte counts, field roles and ordinals, rule IDs, and zero-based half-open byte spans. They do not keep field text, paths, snippets, matched values, source digests, upstream fingerprints or provider error text. The spans still reveal the location and length of a match, so access to a receipt remains limited review evidence and is not public telemetry.

### What the scan misses

The reviewed representative corpus found 11 of 14 expected occurrences across 10 of 11 positive files under the go1.26.10 profile. The public span fixtures pass under the go1.26.11 profile, and its private coverage and performance qualification is pending. The misses were bearer credentials, AWS secret keys and AWS session tokens. One near-miss file produced a `generic-api-key` finding at `[7,51)`, so those bytes are redacted even though the finding is not a true secret.

This fixed profile is a bounded filter, and it does not guarantee that a request contains no secret. Operators must assume that other false negatives and false positives are possible. A remote provider receives the sanitized request, and `store: false` does not replace account retention and content-logging controls.

### The built-in HTTP client

The built-in bounded HTTP client has a fixed authority identity that Open Trestle derives. It gives each request a deadline of two minutes per 4096 tokens of that request's output allowance, with a minimum of two minutes and a maximum of five minutes (`DefaultClientRequestTimeout`). A 16384-token allowance therefore gets five minutes. A deadline set earlier by the caller still wins.

The client identity is version 3 of `open-trestle/openai-default-http-client`, and it binds the five-minute outer timeout and that rule. Version 2 bound a fixed two-minute timeout, so the configuration identities of adapters that use the built-in client changed.

A caller that supplies its own `http.Client` must provide a non-secret `HTTPClientIdentity`. That client's own timeout applies unchanged (two minutes when it sets none), and it is also bound independently. Custom transports without an identity are rejected.
