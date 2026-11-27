# OpenRouter zero data retention

OpenRouter can require zero data retention (ZDR) on a single request: with `"provider": {"zdr": true}` in the request, it routes the request only to endpoints on its ZDR list. Open Trestle uses that per-request switch. `trestle init` requires it without asking, and continues without it only if you pass `--without-zdr` or keep a model that has no ZDR endpoint.

For the setup steps, see [getting started](getting-started.md) and [remote model review](remote-model-review.md#openrouter).

## What setup reads

Setup makes two GET requests to OpenRouter's public API without credentials. They go through the same client as the wizard's evidence fetch, which uses public addresses only, sends no key, cookie, query or repository content, and allows each request at most 8 MiB and 20 seconds. The two addresses are:

- `https://openrouter.ai/api/v1/endpoints/zdr`: the endpoints OpenRouter routes to when a request requires ZDR, with each endpoint's routing slug (`tag`), prices, context length, maximum output and supported parameters.
- `https://openrouter.ai/api/v1/models`: the model list.

### Which endpoints setup keeps

For each model you choose, setup keeps the ZDR endpoints that Open Trestle can use. A usable endpoint reports `safety_retention: false`, accepts `max_tokens`, lists decimal prices, and has at least 8192 tokens of context and 4096 of output. Setup orders the usable endpoints by price, cheapest first, and keeps at most 32.

Endpoints that report Safety Retention, or do not say, are left out and listed as excluded. OpenRouter documents that a ZDR request may still be routed to Safety Retention endpoints, depending on account settings, so pinning only the other endpoints keeps those out.

### The output allowance

Setup then chooses the review output allowance, which is the most a model may write in one request (the runtime policy's `max_output_tokens`), and pins only the usable endpoints that allow at least that much output.

The target allowance is 16384 tokens, so that a reasoning model has room to finish its answer after it reasons. `--max-output-tokens N` sets the allowance to `N` instead, and `--output-tokens N` caps it at `N`. This way, one endpoint with a small output limit does not set the limit for every pinned endpoint of both models. For example, if a model has 25 ZDR endpoints and one of them allows 4096 output tokens and another 8192, setup pins the other 23 and says "2 endpoints that allow less than 16384 output tokens are left out".

If no usable endpoint of a model allows the target, setup keeps all of that model's usable endpoints, and the allowance becomes the smallest output they allow, but never less than 4096. The wizard says so in one line. Both models are pinned with that one floor, so the allowance fits every pinned endpoint. An allowance that you set with `--max-output-tokens` is never lowered: if no usable endpoint of a model allows it, setup stops and names the most that model's endpoints allow.

### Facts setup fills in

From the pinned endpoints alone, setup fills in the facts that the configuration needs:

- the routing slugs
- the smallest context limit and the smallest output limit that any pinned endpoint of either model allows
- the highest input price and the highest output price of any pinned endpoint, in micro-USD per million tokens, rounded up
- whether structured output is reported

Any flag you pass overrides the detected value. With `--*-provider-slug`, the facts are those of the endpoints you name. If the API does not list a slug as a usable ZDR endpoint of that model, the facts stay unknown, and you must pass the four capacity and price flags.

### What setup cannot know

The API does not say whether your OpenRouter account or key enforces ZDR. If a model you chose has no ZDR endpoint, the wizard warns that an account or key with ZDR enforced will refuse its requests, and it offers to pick a model that has one.

If setup cannot read the API, it says why and asks you for the limits and prices instead. It can still require ZDR on every request, but it then pins no endpoints, so OpenRouter chooses among its own ZDR endpoints. Depending on your account settings, those may include Safety Retention endpoints.

## The two routes

| Route | `--provider` | Zone | Request profile | Runtime policy |
|---|---|---|---|---|
| ZDR required on every request | `openrouter-zdr` | `brokered_remote` | `openrouter_zdr_chat_v2` | version 8 |
| ZDR not required by Open Trestle | `openrouter` | `private_remote` | none (generic Chat Completions) | version 2 |

### ZDR required

Every request sets the same provider controls:

```json
{"provider":{"zdr":true,"only":["<slug>","..."],"allow_fallbacks":true,"require_parameters":true}}
```

`only` holds the recorded slugs, so OpenRouter may use only those endpoints. A route with no recorded slugs sends no list. Open Trestle sends no `order`, so OpenRouter balances requests across the pinned endpoints. The cost limit uses the highest price among the recorded endpoints, so balancing stays within it.

Because the request requires ZDR, OpenRouter refuses it rather than send it to an endpoint outside its ZDR list. The request carries the model selector, the output bound, the host instructions and the sanitized context. It has no request overlay, no tool execution and no model array.

`allow_fallbacks` is true so that OpenRouter may retry a request on another pinned endpoint when the one it picked fails. Without it, OpenRouter serves a request only from its top-ranked endpoint, and one failing endpoint would fail the review. Fallback never leaves `only`, and if no endpoint in `only` serves the model, OpenRouter refuses the request with HTTP 404 even with `allow_fallbacks` true.

A request also carries `"reasoning":{"effort":"low"}` when every pinned endpoint lists `reasoning` among its supported parameters. Reasoning tokens count against `max_tokens`, and OpenRouter documents low effort as about a fifth of the allowance, so the answer keeps room (the model provider decides the exact use). Because `require_parameters` is true, OpenRouter would not route a request to an endpoint that lacks a parameter the request carries. A route with any other endpoint, or with no recorded slugs, therefore sends no `reasoning` member.

A verification request also carries `response_format` with the request's output schema (`json_schema`, `strict` true) when every pinned endpoint of the verification route supports structured outputs. The endpoint then constrains the checker's answer to that schema, and Open Trestle still checks every answer as before. When the endpoint rejects the schema (HTTP 400 or 422), the request is sent once more without `response_format`. Each verification reservation counts the schema's bytes. Generation requests send no `response_format`.

The setup summary, `bootstrap check` (`data_retention: required_per_request`) and the wizard all say that ZDR is required on every request. This describes the request, not what a provider retains. OpenRouter documents legal exceptions to ZDR, such as CSAM handling.

### ZDR not required

This route is a generic `private_remote` Chat Completions connection to `https://openrouter.ai/api/v1`, like Ollama Cloud. Its requests carry no `provider` object, so OpenRouter routes them by its defaults and by your account and key settings, and the model provider may keep prompts under its own terms. Your account or key may still enforce ZDR, in which case OpenRouter refuses a model that has no ZDR endpoint. Every request carries `"reasoning":{"effort":"low"}`. Without `require_parameters`, an endpoint that does not support a parameter ignores it, so a model that does not reason is unaffected.

`trestle init` chooses this route when you pass `--without-zdr`, or when a chosen model has no ZDR endpoint and you press Enter to keep it. It explains the trade-off in two sentences, and both the summary and the one confirmation under it say that ZDR is not required. `setup bootstrap init --provider openrouter` makes the same choice directly.

Every place that shows the route labels it:

- The wizard summary and review prompt say "zero data retention not required by Open Trestle".
- `bootstrap check` reports `data_retention: not_required_by_open_trestle` and the limitation `zero_data_retention_not_required_by_open_trestle`.
- Every review result carries `openrouter_zero_data_retention_not_required`.

## What is recorded

Each ZDR route record carries a privacy witness, schema version 3, in its evidence manifest. The witness records what setup saw and chose:

- the route and its effective selector
- the fixed endpoint, profile, protocol and bearer mode
- the credential reference identity, which is a digest of the variable name and never the key
- the tenant and repository
- the fixed `zero_data_retention: required_per_request`
- the pinned `provider_slugs`, and where they came from (`provider_slug_source`: `openrouter_api`, `operator` for `--*-provider-slug` flags, or `none`)

The witness's `observation` holds what the API reported at one moment, or `null` when the API could not be read. It contains these members:

- `authority_label`: `as reported by OpenRouter's API at <time>; not reviewed or verified by the operator`
- `retrieved_at` and `sources`: both API addresses, each with its own retrieval time and the SHA-256 of the exact response bytes
- `zdr_endpoints`: for each pinned endpoint, its tag, provider name, context, prompt and output limits, prices, structured-output support, and whether it accepts the reasoning parameter (`reasoning`)
- `safety_retention_endpoints_excluded`: the ZDR endpoints left out because they report Safety Retention or do not say
- `output_limit_endpoints_excluded`: the usable ZDR endpoints left out because they allow fewer output tokens than the review output allowance, each with its `tag` and reported `max_completion_tokens` (empty when the slugs came from flags, or when no endpoint was left out)

A route without ZDR records the same observation, without endpoint facts, in an informational `openrouter_route` member labeled `not_required_by_open_trestle`.

Every member of the witness is required and closed, except an endpoint's `reasoning`, which reads as false in a witness saved without it. Only `observation` may be `null`. The slug rules are:

- Slugs use lowercase letters, digits, `-`, `_`, `.` and `/`, are at most 256 bytes each, and are distinct. There are at most 32.
- With `openrouter_api`, the slugs are exactly the observed endpoint tags, in order. `operator` needs at least one slug, and `none` has none.
- An excluded tag is never pinned.

An endpoint left out for its output limit allows at least 4096 output tokens and fewer than every pinned endpoint. It is listed once, is not also left out for Safety Retention, and appears only with `openrouter_api`. At most 64 are listed. Each source time is no earlier than `retrieved_at`, and the label names that time.

### Runtime policy version 8

Version 8 accepts generic connections and the `openrouter_zdr_chat_v2` profile. Its `brokered_route_authority` has exactly these members: `route_record_identity`, `evidence_manifest_digest`, `tenant_id`, `repository_id` and `provider_slugs`. The route record must carry a valid version 3 witness whose route, credential reference, scope and slugs match the connection exactly. There is no account identity, single slug or validity window, and no v8 JSON Schema is published. The adapter configuration identity binds the slug list under adapter preimage version 3.

## How a reply is read

Open Trestle decodes the answer part of a reply strictly: the identity, the one choice, its message and the usage. It refuses an unknown member there, and it also refuses a choice that reports an error, returns images, or whose reasoning ran a server tool.

- The message's `reasoning` text and `reasoning_details` summaries are dropped and never become output.
- An answer wrapped in exactly one outer Markdown fence (with no language, or `json`) is unwrapped before the same strict validation, because some endpoints that list structured output support still fence their JSON. Any other wrapping is refused.
- `native_finish_reason` is ignored.
- The usage must report prompt, completion and total tokens, no BYOK charge, no tool use and no deferred tool turns. Cached prompt tokens may not exceed prompt tokens.
- The completion breakdown (reasoning, audio, image and prediction counts) is checked as unsigned integers and then dropped. It is not compared with the completion count, because upstream providers report it inconsistently and settlement does not use it.

OpenRouter's routing metadata around the answer is not decoded strictly, because OpenRouter adds members there that its published schema does not list, such as a top-level `provider` in replies. The upstream `provider` name must be a short printable string. If `openrouter_metadata.pipeline` lists any stage other than an account `guardrail` (a plugin, server tool, response healing or context compression), something changed what the model saw or answered, and Open Trestle refuses the reply. It does not read other envelope members, such as `alignment` and `safeguard_results`.

## When OpenRouter refuses a request

As on every route, the review classifies a refusal by its HTTP status alone (see [provider failures](remote-model-review.md#provider-failures)). For an OpenRouter route, HTTP 404 means that OpenRouter served no endpoint for the request. Either the model ID is not served, or no endpoint that the request may use can take it. For example, ZDR may be required, by the request or by your account or key, while the model has no ZDR endpoint. OpenRouter refuses such a request with HTTP 404 at its data-policy routing step, before any model runs. If OpenRouter changes that status, the generic detail for the new status applies.

A 404 records `failure_detail` `provider_no_allowed_endpoint` and this hint: "OpenRouter has no endpoint for this model that the request may use: if zero data retention is required (by this setup or by your OpenRouter account or key settings), choose a model with zero-data-retention endpoints and run trestle init again (https://openrouter.ai/docs/guides/features/zdr); otherwise check the model ID". The daemon still records the generic `provider_model_unavailable` reason.

OpenRouter answers an unknown model ID with HTTP 400 instead. That is a rejected request, not a ZDR refusal, so it records `provider_request_rejected` with the hint to check the model ID.

## Earlier reviewed setups

Setups made with the earlier form of this route use the `openrouter_zdr_chat_v1` profile in runtime policy version 3, 4 or 5. They carry a version 2 witness that you reviewed and declared by hand, with one slug per model, four evidence objects, an account review and a validity window. Their bytes, identities and dispatch are unchanged. They keep working until their review window ends, and `bootstrap check` then reports `privacy_declaration_current` as refused.

To continue, run `trestle init --directory NEW_FOLDER`, which writes the version 3 form described above. `setup bootstrap init --provider openrouter-zdr` no longer accepts the slug evidence, account declaration or review-window flags, and refuses each one with a message that the flag is no longer used.
