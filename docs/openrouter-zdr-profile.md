# OpenRouter zero data retention

OpenRouter can require zero data retention (ZDR) on a single request: with
`"provider": {"zdr": true}` it routes the request only to endpoints on its ZDR
list. Open Trestle uses that per-request switch. `trestle init` recommends it and
selects it by default; it is not a gate you must pass before setup continues.

This page describes what setup reads from OpenRouter, what it records, what each
request sends, and how a route without ZDR is labelled. The setup steps are in
[getting started](getting-started.md) and
[remote model review](remote-model-review.md#openrouter).

## What setup reads

Setup makes two bounded, credential-free GET requests to OpenRouter's public API,
through the same client as the wizard's evidence fetch (public addresses only,
no key, cookie, query or repository content, at most 8 MiB and 20 seconds each):

- `https://openrouter.ai/api/v1/endpoints/zdr`, the endpoints OpenRouter routes
  to when a request requires ZDR, with each endpoint's routing slug (`tag`),
  prices, context length, maximum output and supported parameters;
- `https://openrouter.ai/api/v1/models`, the model list.

For each chosen model it keeps the ZDR endpoints Open Trestle can use: those
that report `safety_retention: false`, accept `max_tokens`, list decimal
prices, and have at least 8192 tokens of context and 4096 of output. They are
ordered by price, cheapest first, at most 32. Endpoints that report Safety
Retention (or do not say) are left out and listed as excluded: OpenRouter
documents that a ZDR request may still be routed to Safety Retention endpoints,
depending on account settings, and pinning the others keeps them out.

From those endpoints it fills in the facts the configuration needs: the routing
slugs, the smaller context and output limit of the two models, the higher input
and output price in micro-USD per million tokens (rounded up), and whether
structured output is reported. Any flag you pass overrides the detected value.

The API cannot tell Open Trestle whether your OpenRouter account or key enforces
ZDR, so setup does not claim either way. If a chosen model has no ZDR endpoint,
the wizard warns that an account or key with ZDR enforced will refuse its
requests, and offers to pick a model that has one.

If the API cannot be read, setup says why and asks for the limits and prices
instead. It can still require ZDR on every request; it then pins no endpoints
and OpenRouter chooses among its own ZDR endpoints, which may include Safety
Retention endpoints depending on your account settings.

## The two routes

| Route | `--provider` | Zone | Request profile | Runtime policy |
|---|---|---|---|---|
| ZDR required on every request | `openrouter-zdr` | `brokered_remote` | `openrouter_zdr_chat_v2` | version 8 |
| ZDR not required by Open Trestle | `openrouter` | `private_remote` | none (generic Chat Completions) | version 2 |

### ZDR required

Every request sets the same provider controls:

```json
{"provider":{"zdr":true,"only":["<slug>","..."],"order":["<slug>","..."],"allow_fallbacks":false,"require_parameters":true}}
```

`only` and `order` are the recorded slugs, so OpenRouter may use only those
endpoints, in that order. A route with no recorded slugs sends neither list.
Because the request itself requires ZDR, OpenRouter refuses it rather than
sending it to an endpoint outside its ZDR list; there is no review window to
expire. The exact model selector, output bound, host instructions, sanitized
context, strict response parser, usage reconciliation and bounded transport
still apply. There is no request overlay, tool execution, model array or
provider fallback.

The setup summary, `bootstrap check` (`data_retention: required_per_request`)
and the wizard all say that ZDR is required on every request. That is a fact
about the request, not a promise about what any provider retains: OpenRouter
documents legal exceptions to ZDR, such as CSAM handling.

### ZDR not required

The route is a generic `private_remote` Chat Completions connection to
`https://openrouter.ai/api/v1`, like Ollama Cloud. Requests carry no `provider`
object, so OpenRouter routes them by its defaults and your account and key
settings. The model provider may keep prompts under its own terms. Your account
or key may still enforce ZDR, in which case a model without a ZDR endpoint is
refused.

`trestle init` chooses this route only after it explains that in two sentences
and you answer yes, or with `--without-zdr`; `setup bootstrap init --provider
openrouter` is that choice made directly. It is labelled everywhere it appears: the
wizard summary and review prompt ("zero data retention not required by Open
Trestle"), `bootstrap check` (`data_retention: not_required_by_open_trestle`
and the limitation `zero_data_retention_not_required_by_open_trestle`) and every
review result (`openrouter_zero_data_retention_not_required`). None of these
claims that a provider retains or deletes anything.

## What is recorded

Each ZDR route record carries a privacy witness, schema version 3, in its
evidence manifest. It binds the route and effective selector, the fixed
endpoint, profile, protocol and bearer mode, the credential reference identity
(a digest of the variable name, never the key), the tenant and repository, the
fixed `zero_data_retention: required_per_request`, the pinned `provider_slugs`,
and where they came from (`provider_slug_source`: `openrouter_api`, `operator`
for `--*-provider-slug` flags, or `none`). Its `observation` holds what the API
reported, or `null` when the API could not be read:

- `authority_label`: `as reported by OpenRouter's API at <time>; not reviewed or
  verified by the operator`;
- `retrieved_at` and `sources`: both API addresses, each with its own retrieval
  time and the SHA-256 of the exact response bytes;
- `zdr_endpoints`: for each pinned endpoint its tag, provider name, context,
  prompt and output limits, prices and structured-output support;
- `safety_retention_endpoints_excluded`: the ZDR endpoints left out.

The witness records what the API reported at one time. It is not evidence that
an endpoint retains nothing, and the operator does not review or vouch for it.
A route without ZDR records the same observation, without endpoint facts, in an
informational `openrouter_route` member labelled
`not_required_by_open_trestle`.

### Synthetic format example

This witness is an offline format example, not an observation of OpenRouter.
Setup writes the real one; do not copy this.

```json
{
  "openrouter_privacy": {
    "contract": "open-trestle/openrouter-privacy-witness",
    "schema_version": 3,
    "route": {
      "zone": "brokered_remote",
      "provider_id": "openrouter",
      "adapter_id": "openrouter-generation",
      "connection_id": "openrouter/generation",
      "model_id": "vendor/model",
      "model_version": "",
      "effective_selector": "vendor/model"
    },
    "endpoint": "https://openrouter.ai/api/v1",
    "request_profile": "openrouter_zdr_chat_v2",
    "protocol": "openai_chat_completions",
    "credential_mode": "bearer",
    "credential_reference_identity": "99d4435c2238d0cdf988ace246b7f44305262a35bd1c45ebe0559ed0d0286e4c",
    "tenant_id": "personal",
    "repository_id": "project",
    "zero_data_retention": "required_per_request",
    "provider_slugs": ["fixture-cloud", "fixture-cloud/us"],
    "provider_slug_source": "openrouter_api",
    "observation": {
      "authority_label": "as reported by OpenRouter's API at 2026-11-10T21:00:00Z; not reviewed or verified by the operator",
      "retrieved_at": "2026-11-10T21:00:00Z",
      "sources": [
        {"url": "https://openrouter.ai/api/v1/endpoints/zdr", "retrieved_at": "2026-11-10T21:00:00Z", "content_sha256": "e6b11692df5754cdf6d2c71791df04ea1c3cc6483d887ce7ba5c4f491caee63a"},
        {"url": "https://openrouter.ai/api/v1/models", "retrieved_at": "2026-11-10T21:00:01Z", "content_sha256": "4df85e58e5206a5a1ae7fc7d672ca80a270bc9c3b4332fa14a122201c4aae40b"}
      ],
      "zdr_endpoints": [
        {"tag": "fixture-cloud", "provider_name": "Fixture Cloud", "context_length": 200000, "max_prompt_tokens": 0, "max_completion_tokens": 64000, "prompt_micro_usd_per_million_tokens": 3000000, "completion_micro_usd_per_million_tokens": 15000000, "structured_outputs": true},
        {"tag": "fixture-cloud/us", "provider_name": "Fixture Cloud", "context_length": 200000, "max_prompt_tokens": 0, "max_completion_tokens": 64000, "prompt_micro_usd_per_million_tokens": 3300000, "completion_micro_usd_per_million_tokens": 16500000, "structured_outputs": true}
      ],
      "safety_retention_endpoints_excluded": ["fixture-safety/global"]
    }
  }
}
```

Every member is required and closed; only `observation` may be `null`. Slugs are
lowercase letters, digits, `-`, `_`, `.` and `/`, at most 256 bytes, distinct,
at most 32. With `openrouter_api` the slugs are exactly the observed endpoint
tags in order; `operator` needs at least one slug and `none` none. An excluded
tag is never pinned. Each source time is no earlier than `retrieved_at`, and
the label names that time.

### Runtime policy version 8

Version 8 admits generic connections and the `openrouter_zdr_chat_v2` profile.
Its `brokered_route_authority` has exactly `route_record_identity`,
`evidence_manifest_digest`, `tenant_id`, `repository_id` and `provider_slugs`.
The record must carry a valid version 3 witness whose route, credential
reference, scope and slugs match the connection exactly. There is no account
identity, single slug or validity window. No v8 JSON Schema is published. The
adapter configuration identity binds the slug list under adapter preimage
version 3.

## How a reply is read

The answer part of a reply is decoded strictly: the identity, the one choice,
its message and the usage. An unknown member there is refused, and so is a
choice that reports an error, returns images, or whose reasoning ran a server
tool. The message's `reasoning` text and `reasoning_details` summaries are
bounded and dropped; they never become output. `native_finish_reason` is
bounded and ignored. The usage must report prompt, completion and total
tokens, no BYOK charge, no tool use and no deferred tool turns, and cached
prompt tokens may not exceed prompt tokens. The completion breakdown
(reasoning, audio, image and prediction counts) is checked as unsigned
integers and dropped without being compared with the completion count, because
upstream providers report it inconsistently and settlement does not use it.

OpenRouter's routing metadata around the answer is not decoded strictly,
because OpenRouter adds members there that its published schema does not list
(live replies carry a top-level `provider`). The upstream `provider` name must be
a short printable string. If `openrouter_metadata.pipeline` lists any stage
other than an account `guardrail` (a plugin, server tool, response healing or
context compression), something changed what the model saw or answered, and
the reply is refused. Other envelope members, such as `alignment` and
`safeguard_results`, are not read.

## When OpenRouter refuses a request

The review classifies a refusal by its HTTP status alone and never reads the
error body. For an OpenRouter route, HTTP 404 means OpenRouter served no
endpoint for the request: the model ID is not served, or no endpoint the request
may use can take it, for example because ZDR is required (by the request or by
your account or key) and the model has no ZDR endpoint. A live probe on
2026-11-11, a ZDR-required request for a model with no ZDR endpoint, was refused
with HTTP 404 at OpenRouter's data-policy routing step, before any model ran; if
OpenRouter changes that status, the generic detail for the new status applies.
A 404 records `failure_detail`
`provider_no_allowed_endpoint` and the hint "OpenRouter has no endpoint for
this model that the request may use: if zero data retention is required (by
this setup or by your OpenRouter account or key settings), choose a model with
zero-data-retention endpoints and run trestle init again
(https://openrouter.ai/docs/guides/features/zdr); otherwise check the model
ID". The daemon still records the generic `provider_model_unavailable` reason.

## Earlier reviewed setups

Setups made before this change use the `openrouter_zdr_chat_v1` profile in
runtime policy version 3, 4 or 5, with a version 2 witness that you reviewed and
declared by hand: one slug per model, four evidence objects, an account review
and a validity window. Their bytes, identities and dispatch are unchanged. They
keep working until their review window ends; `bootstrap check` then reports
`privacy_declaration_current` as refused. To continue, run `trestle init
--directory NEW_FOLDER`, which writes the version 3 form above. `setup bootstrap
init --provider openrouter-zdr` no longer accepts the slug evidence, account
declaration or review-window flags; each one is refused with a message that it
is no longer used.

Offline synthetic transports establish development behavior only. They do not
qualify an actual OpenRouter account, endpoint, model quality, retention
practice or live usage. Live inference, credentials, private source egress and
charges require separate explicit authorization.
