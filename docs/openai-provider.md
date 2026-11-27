# OpenAI-compatible provider adapter

The adapter in `adapters/providers/openai` sends review requests to the [OpenAI Responses API](https://platform.openai.com/docs/api-reference/responses) or to a Chat Completions endpoint (see the [Chat transport](local-model-review.md#chat-completions-transport)). Its Responses fields follow the official [`openai/openai-openapi`](https://github.com/openai/openai-openapi) contract. This page is for contributors and operators who need to know what the adapter sends, what it accepts back, and which decisions it leaves to the gateway.

The adapter implements the gateway's `RouteDispatcher` contract and only executes requests. Route policy, provider eligibility, privacy classification, budget reservation and retry decisions stay with the gateway.

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

A dispatch must match every bound value, and a mismatch fails before the adapter retrieves a credential or touches the network. Register each instance in `gateway.RouteDispatcherCatalog` under its adapter ID.

If the route declares a model version, the adapter sends that version as the API `model` selector, and otherwise it sends the model ID. The `model` in the reply must match the same selector. A pinned version must be a model selector that the configured Responses API accepts.

## Request and response contract

The adapter sends the provider-neutral request payload as a single user `input_text` item. It also copies the host instructions into the Responses API `instructions` field, so they take system or developer-message priority over input that comes from the repository. If the instruction contract is missing, the request fails before credential retrieval.

Standard candidate-generation and verification requests can use numeric-loopback `local` routes or approved `private_remote` routes. A private-remote request must be the sanitized request that the model handler authorized, and it must carry that handler's opaque dispatch proof, which is tied to the egress receipt. The generic dispatcher refuses to send non-local repository context before it retrieves a credential.

New candidate-generation and verifier context packets use input schema version 3. Each packet holds the host instructions, the canonical `output_schema` and its `output_schema_identity`, and the provider request identity covers the whole sanitized payload, including those contract bytes. The adapter does not enable provider tools and does not execute actions that the model proposes.

The schemas are output guidance that the model can read. The provider does not enforce them, and the adapter does not request strict JSON schema mode, because the canonical schemas use JSON Schema features that some providers do not support. The host parses the output itself.

Context and result records of version 2 stay readable and are not upgraded to version 3, but current generation and verifier runs require version 3.

### Input estimate

When Open Trestle selects a route for a review, it reserves an input estimate of `max(declared_estimated_input_tokens, payload_bytes + system_channel_bytes + 256)`.

- The system channel is the trusted host contract plus any specialist guidance that the adapter sends as the system message. For a sanitized request or a local verification envelope, the estimate measures the request that the adapter unwraps.
- When a planned route uses the [local Chat schema transport](local-model-review.md#chat-completions-transport), the estimate also adds the serialized `response_format` bytes that the transport sends.
- The 256 units are a fixed reserve for framing. The full encoded payload includes the schemas, the context and JSON escaping.
- Investigation turns use the same estimate and record the system channel bytes in each turn record (estimate version 2).

The estimate is a byte-based planning figure, not exact tokenization, and it may not hold for every provider's tokenizer. Reported usage is reconciled against cost. The full provider payload is limited to 8 MiB.

### What every request contains

- The authorized model version, or the model ID when no version is pinned.
- The host instructions, at instruction priority.
- The authorized maximum output-token count.
- `store: false`.
- No tool declarations.

`store: false` does not replace account-level retention controls. The configured content-logging mode must match the approved route record, and you are responsible for making that declaration match the controls on the provider account and connection.

### What the adapter accepts back

The adapter accepts completed responses and two incomplete reasons, `max_output_tokens` and `content_filter`. It discards provider reasoning items, keeps assistant text and refusals, and represents valid JSON output as structured data.

The adapter refuses a reply with any of these:

- unknown output item types
- duplicate JSON keys
- JSON keys that differ only in case
- a model mismatch
- invalid usage
- excessive content

A reply that stopped at the output limit with no answer, or with answer text that is not one complete JSON value, fails as `output_exhausted`. It keeps the usage the provider reported, checked as for a successful reply, so its cost settles from that usage. Without valid usage, the usage stays unknown.

## Transport and credentials

The adapter retrieves a credential for each request through `APIKeyProvider`. Keys are header-safe values that redact themselves when formatted. The adapter rejects redirects, so authorization headers cannot move to another origin. Response bodies, error bodies, headers and request duration all have size or time limits.

### Failure classes

HTTP failures become gateway classes, and the adapter does not keep the provider's error text. Every request profile, including the OpenCode console, classifies a non-200 status from the status alone, and the adapter drains and discards the error body. The status-to-class table, the retry rules and the failure details are in [provider failures](remote-model-review.md#provider-failures).

Replay safety tells the gateway whether it may retry. A timeout (408, 504), another 5xx response, a network ambiguity and a 200 reply that the adapter refuses have `outcome_unknown` replay safety, so the gateway does not retry them automatically. Every other class, including `invalid_response` for a non-200 status such as 409, has `no_side_effect` replay safety.

A rate limit (a 429, or a 503 that names a `Retry-After` in seconds) is a refusal before any processing. It carries a bounded `Retry-After` delay and reports known zero usage. A 503 without one, or with an HTTP date or zero, stays `provider_server`. Every other failed dispatch reports unknown usage.

A 200 response that the adapter refuses is `invalid_response`. The adapter refuses a reply that is malformed, truncated, empty or oversized, that is not the strict document described above, or that is a Chat Completions reply with an unrecognized field. For OpenRouter, the unrecognized-field check applies to the answer, not to its [routing metadata](openrouter-zdr-profile.md#how-a-reply-is-read).

`payment_required`, `model_unavailable`, `model_retired` and `request_rejected` are not transient, so the gateway does not retry them, and none of them counts as a provider outage. For each of these classes, as for `authentication` and `authorization`, the model handlers fail the task as a `policy` refusal and record the matching `provider_*` reason. An `invalid_response` after the request was sent keeps the task's `internal` failure and records `provider_response_invalid`, while an `invalid_response` before sending records neither.

The adapter makes no request when it is constructed and has no background activity.

## Configuration identity

Responses adapter configuration identity version 3 introduced version-first wire model selection. The current Responses adapter uses version 4, and Chat Completions uses its own identity version 1. When you upgrade from earlier dispatch semantics, rebuild the approved dispatcher catalogs instead of reusing an old adapter configuration identity.

Each adapter requires a `CredentialIdentity`, a canonical lowercase SHA-256 value that identifies the credential lease or environment authority, not the secret value. The adapter derives `ConfigurationIdentity()` from its adapter, provider, connection, zone, logging, endpoint, credential-authority, HTTP timeout and HTTP-client-authority values, and the route dispatcher catalog binds that identity as well as the adapter ID. Changing a service endpoint, a credential authority or the HTTP authority therefore changes the downstream model-handler identity, even when the public adapter name stays the same.

`runtimecatalog.NewOpenAIRouteDispatcherCatalog` builds the OpenAI adapters from a validated route inventory. Every adapter namespace in the inventory must have one connection definition. Several models may share one adapter only when their provider, connection, zone and logging authority are identical. Definitions that are missing, extra, duplicated or cross-wired are refused.

## Which routes the adapter can dispatch

The direct adapter dispatches `local` routes only through numeric loopback endpoints. It accepts a non-loopback HTTPS `private_remote` route only through `DispatchSanitizedRoute`, which requires that the trusted generation or verification handler has reloaded the sanitized request and the egress receipt and validated them together.

A receipt does not authorize dispatch by itself; the proof that the handler seals does. The proof is tied to the review scope, the sanitized request identity, the receipt identity and the request kind, and it is opaque outside the handler package. A proof that is missing, forged, from another scope, stale, raw or for the wrong kind of request fails before credential retrieval or network access. Investigation requests do not have this authority and stay local-only.

Generic adapters reject `brokered_remote` and `subscription_oauth`. The closed request profiles add explicitly bound brokered routes:

- the [OpenRouter ZDR Chat profile](openrouter-zdr-profile.md), in runtime policy v3 to v5, and v8 for the current profile
- the [OpenCode Go profile](opencode-go-profile.md), in v4 and v5
- the [OpenCode Console profile](opencode-go-profile.md#opencode-console-profile), in v5

These profiles do not make brokered routes or OAuth generally supported.

During configuration validation, Open Trestle classifies DNS names without resolving them. At run time, the adapter rejects conventional localhost names and non-unicast numeric addresses before credential retrieval or dispatch.

## Sanitized egress boundary

Before either standard model stage is authorized, the host scans the request twice in the secret scan helper, and dispatch is denied unless both scans complete and the second finds nothing. A receipt is accepted only for the helper digest that the reading program pins. The scanner, its pin and its limits are described in [what the scan does](remote-model-review.md#what-the-scan-does).

### The built-in HTTP client

The built-in HTTP client has an authority identity that Open Trestle derives. Its request deadline depends on the output allowance (see [request deadline](remote-model-review.md#output-allowance-and-request-deadline)), and a deadline set earlier by the caller still wins. The client identity is version 3 of `open-trestle/openai-default-http-client`, and it binds the five-minute outer timeout and that rule.

A caller that supplies its own `http.Client` must provide a non-secret `HTTPClientIdentity`. That client's own timeout applies (two minutes when it sets none), and it is bound separately. Custom transports without an identity are rejected.
