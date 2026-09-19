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

The adapter sends the provider-neutral request payload as one user `input_text` item. New candidate-generation and verifier context packets use input schema version 3. Each contains fixed host instructions, the complete canonical `output_schema`, and its `output_schema_identity`. The existing provider request identity binds the full payload, including those contract bytes. Source, memory, and candidate text cannot select or replace the host contract. The adapter does not add hidden instructions, enable tools, or execute model-proposed actions.

The schemas are readable output guidance, not provider-enforced constrained decoding. This adapter does not request strict JSON schema mode. The canonical schemas use JSON Schema features that some provider subsets do not support. Output still requires host parsing, evidence admission, independent verification, and publication authorization. Readable guidance does not guarantee model correctness.

Historical version 2 context and result records remain readable with their exact original bytes and identities. They are not enriched into version 3. Historical parsing does not authorize a new model attempt: current generation and verifier execution require version 3. Generic opaque provider request version 1 identities and the output schemas' version 1 contracts remain unchanged.

Review route selection reserves an input estimate of `max(declared_estimated_input_tokens, payload_bytes + 256)`. The 256 units are a fixed framing reserve. The full encoded payload includes instructions, schemas, context, and JSON escaping. This is a byte-based planning estimate, not exact tokenization or a guarantee for every provider tokenizer. Capacity and price checks use that estimate without increasing the declared output limit or monetary cap. Reported usage still requires cost reconciliation. The full provider payload remains bounded at 8 MiB.

Every request includes:

- the exact authorized model version, or model ID when unpinned
- the authorized maximum output-token count
- `store: false`
- no tool declarations

`store: false` is not a substitute for account-level retention controls. The configured content-logging mode must match the approved route record. Operators are responsible for making that declaration match the provider account and connection controls.

The adapter accepts completed responses and the closed incomplete reasons `max_output_tokens` and `content_filter`. It discards provider reasoning items, preserves assistant text and refusals, and represents valid JSON output as structured data. Unknown output item types, duplicate JSON keys, case-variant JSON keys, model mismatches, invalid usage, and excessive content fail closed.

## Transport and credentials

Credentials are retrieved for each request through `APIKeyProvider`. Keys are bounded, header-safe values and redact themselves during formatting. Redirects are rejected so authorization headers cannot move to another origin. Response bodies, error bodies, headers, and request duration are bounded.

HTTP failures become closed gateway classes without retaining provider error text. Network ambiguity, server errors, malformed successful responses, and timeouts use `outcome_unknown` replay safety. The gateway will not retry those outcomes automatically. Explicit rate-limit responses can carry a bounded `Retry-After` delay and are marked as having no model side effect.

The adapter performs no request during construction and has no background activity.

For controlled-hybrid and Kubernetes HA setup, `trestle setup check provider` separately records named approval of the exact protected inventory, policy, endpoint locality, credential environment references, logging posture, budget, and distinct-provider route pair. That authorization reads no credential and constructs no adapter. It is not a connectivity probe or dispatch authority.

## Configuration authority

Adapter configuration identity version 3 binds the version-first wire model selection behavior. Rebuild approved dispatcher catalogs when upgrading from the earlier alias-first behavior; do not reuse an old adapter configuration identity for the new dispatch semantics.

Each adapter requires a canonical lowercase SHA-256 `CredentialIdentity`. This identifies the credential lease or environment authority, never the secret value. The adapter derives `ConfigurationIdentity()` from its adapter, provider, connection, zone, logging, endpoint, credential-authority, HTTP timeout, and HTTP-client-authority values. The route dispatcher catalog binds that identity as well as the adapter ID. Changing a service endpoint, credential authority, or HTTP authority therefore changes the downstream model-handler identity even when the public adapter name is unchanged.

`runtimecatalog.NewOpenAIRouteDispatcherCatalog` constructs exact OpenAI adapters from a validated route inventory. Every adapter namespace in the inventory must have one connection definition. Multiple models may share one adapter only when provider, connection, zone, and logging authority are identical. Missing, extra, duplicate, or cross-wired definitions fail closed.

The direct adapter accepts `local` routes only through numeric loopback endpoints and `private_remote` routes only through non-loopback HTTPS endpoints. It rejects `brokered_remote` and `subscription_oauth` because those zones require different transport and credential authorities. DNS names are classified without resolving them during configuration validation; operators remain responsible for controlling the approved remote DNS authority. The runtime rejects conventional localhost names and non-unicast numeric addresses before credential retrieval or dispatch.

The built-in bounded HTTP client has a derived fixed authority identity. A caller that supplies a custom `http.Client` must provide a non-secret `HTTPClientIdentity`; the actual timeout is also bound independently. Unidentified custom transports are rejected.
