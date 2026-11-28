# OpenCode profiles

Open Trestle has two named OpenCode request profiles that route review requests through a brokered OpenCode endpoint: `opencode_go_chat_v1` for an OpenCode Go subscription account, and `opencode_console_chat_v1` for the paid OpenCode Console inference endpoint. This page is the operator contract for both. It describes the Go profile first, and [the Console profile](#opencode-console-profile) lists only what differs.

## Go profile status

Runtime policy v4 and v5 accept the `opencode_go_chat_v1` profile alongside the generic and OpenRouter connections. Setup writes v4.

`trestle init --provider opencode-go` and `trestle setup bootstrap init --provider opencode-go` write this profile's policy and inventory from the evidence and declarations that you supply, with both the generation and verification roles on the brokered Go route (see [remote model review](remote-model-review.md#opencode-go)). No command creates credentials or issues the approval. The profile does not use OpenRouter's `provider.zdr` request controls.

Before you use the profile, you approve the account, the model, the evidence, the egress of private source code and a cost reservation.

## Connection and authority

The Go connection uses these settings:

- `implementation`: `openai_chat_completions`
- `endpoint`: `https://opencode.ai/inference/go/openai/v1`
- bearer mode, with an explicit `OPEN_TRESTLE_PROVIDER_` credential reference
- `request_profile`: `opencode_go_chat_v1`
- provider `opencode-go`, zone `brokered_remote`, disabled content logging and one approved inventory record

### Route authority

`opencode_go_authority` has seven required, non-null keys: `route_record_identity`, `evidence_manifest_digest`, `account_policy_identity`, `tenant_id`, `repository_id`, `valid_from` and `valid_until`. Together they bind the record, the typed manifest, the derived account identity, the repository scope and the validity interval. There is no `provider_slug`.

`brokered_route_authority` and `opencode_go_authority` are mutually exclusive, even when one of them is null. Generic connections carry neither authority nor a `request_profile`.

### Model selection

Model selection belongs to the operator. The bare effective selector goes on the wire of the direct API. `opencode-go/` is a client configuration namespace, not a prefix to add to a direct model ID. Go's pay-as-you-go, Responses, Anthropic, Gemini, free-tier and tools or BYOK paths are not part of this profile.

## Typed privacy and account witness

The evidence manifest contains the reserved `opencode_go_privacy` member, the privacy and account witness that records the claims the route depends on. Its contract is `open-trestle/opencode-go-privacy-witness`, with integer schema version 1. It binds these values:

- the route tuple and the effective selector
- the endpoint, profile, protocol and authentication
- the model's privacy and the broker's privacy
- the account
- the tenant and repository
- the validity interval

If typed evidence is missing or invalid, Open Trestle refuses Go consumption by name.

### Evidence roles and sources

Three evidence roles are required:

- the model's no-training and zero-day retention
- the privacy scope of the broker or service
- a distinct review of the actual account or workspace

The roles may reference the same artifact when it supports all of those claims. Each source has an HTTPS `url` of at most 2048 UTF-8 bytes (with a host and without userinfo, query or fragment), a canonical UTC `retrieved_at` and a nonzero lowercase `content_sha256`. Labels are at most 256 UTF-8 bytes. The parser checks syntax and linkage, but it does not fetch evidence URLs or read their content.

### Account and client

The supported account shape is subscription `go`, workspace membership `single_member`, privacy training `disabled` and Extra Usage `disabled`. Go Plus, Teams, service accounts and a balance fallback are not supported. BYOK, tools, plugins and streaming are `excluded`. The client declaration is `open-trestle/1` and `authorized_review_scope_sha256_v1`.

`account_policy_identity` is the lowercase SHA-256 of the compact Go `encoding/json.Marshal` output of a wrapper with the fields `contract` (`open-trestle/opencode-go-account-policy`), `version` (1) and `account`. The credential reference identity inside the account is the SHA-256 of `open-trestle/provider-credential-environment/` plus the environment variable name, not its value. Setup computes these identities for you. If you prepare a manifest by hand, use the maintained native types in `runtimeconfig`.

### Model version, retention and parsing

`model_version` must be present and non-null, but it may be empty. An empty version uses the model ID as the effective selector, and otherwise the version is the selector. `retention_days` is a present, non-null integer that is 0, and training is `disabled`. The broker retention is `model_specific_documented_zero_days`, which is the provider's documented claim, not a warranty.

A duplicate, aliased or unknown field, a missing or null required field, or a trailing value refuses typed consumption. The limits are a 1 MiB manifest and an inventory of 64 routes and 8 MiB.

### Time rules

- Every source retrieval is no later than the review.
- The review is no later than `valid_from`.
- `valid_from` is before `valid_until`. The interval includes its start and excludes its end.
- There is no default TTL and no grace period.
- Currentness is checked before credential resolution and again before dispatch.

## Session, response and accounting

### Session header

After Open Trestle validates the sanitizer proof for the repository, run and request, the request sets `x-opencode-session` to `trestle_` followed by the lowercase SHA-256 of the UTF-8 text `open-trestle/opencode-go-session/v1/` plus the validated review-scope identity. The value is 72 ASCII bytes. It stays the same within that scope, across roles and requests, and differs between reviews. Payload fields cannot override it. The User-Agent is `open-trestle/1`.

### Requests and replies

Requests are non-streaming Chat POSTs with `stream:false`, the sanitized user content, the host instructions and an output cap. They carry no OpenRouter routing body, and this profile adds no retry or fallback. `message.reasoning_content` is validated and then discarded, so only assistant content reaches the candidate parser.

### Token counts

Known native `prompt_tokens` and `completion_tokens` stay the counts that the provider reported. An optional total must equal their overflow-safe sum, and an absent total is derived from that pair. If the whole usage is missing or null, it stays unknown and is not treated as free. Partial or malformed native counts are refused. Only the native `cached_tokens` details can supply the neutral cached subset.

The billed `opencode.tokens.input` excludes cache reads and writes, and billed output includes reasoning. These billed counters are a separate family, so do not equate billed input with the prompt count. Open Trestle validates the billed counters and then discards them.

### Billing block

When an `opencode` billing block is present, it must have these properties:

- `billing_source` is `go`
- `list_cost` and `allowance` are required, finite and nonnegative
- the billed counters are well-formed
- `estimated` is absent or false

Balance, free, BYOK, go-plus and estimated billing are refused. With Extra Usage disabled, `usage.cost` may be absent, null or numeric zero. Open Trestle refuses a positive charge, but the refusal cannot undo it. Unknown or malformed extensions are rejected.

### Cost reconciliation

Cost reconciliation uses the two rates fixed in the record. It is registry accounting, not reconciliation against the Console bill and not a cap on account spend. Set prices and the reservation conservatively, and take the selected model's cache-tier terms into account. Subscription pricing does not justify zero rates. When usage is absent, the handler keeps an unknown outcome and its reservation, along with any valid native counts.

Failures follow the mapping in [provider failures](remote-model-review.md#provider-failures).

## OpenCode Console profile

`opencode_console_chat_v1` routes review requests to the paid OpenCode Console inference endpoint. It works like the Go profile, with the differences below. Neither `trestle init` nor `trestle setup bootstrap init` writes it, so the operator prepares the protected policy and inventory by hand.

| | Go profile | Console profile |
| --- | --- | --- |
| Runtime policy | v4 and v5 | v5 only |
| Endpoint | `https://opencode.ai/inference/go/openai/v1` | `https://opencode.ai/inference/openai/v1` |
| Provider ID | `opencode-go` | `opencode-console` |
| Authority member | `opencode_go_authority` | `opencode_console_authority` (the same seven non-null fields) |
| Witness member and contract | `opencode_go_privacy`, `open-trestle/opencode-go-privacy-witness` | `opencode_console_privacy`, `open-trestle/opencode-console-privacy-witness` |
| Account policy contract | `open-trestle/opencode-go-account-policy` | `open-trestle/opencode-console-account-policy` |
| Session header | SHA-256 of `open-trestle/opencode-go-session/v1/` plus the scope | SHA-256 of `open-trestle/opencode-console-session/v1/` plus the scope |
| Billing source | `go` | `balance` |
| Actual cost | derived from usage | unknown for every result |

The Go, OpenRouter and Console authority members are mutually exclusive, including when one is present but null. Policy v5 still accepts the Go, OpenRouter and generic branches.

The Console account shape is narrow: personal keys, a single-member workspace and a prepaid balance.

| Account field | Value |
|---|---|
| `billing_mode` | `prepaid_balance` |
| `key_kind` | `personal` |
| `models_request` | true |
| `workspace_membership` | `single_member` |
| `privacy_training` | `disabled` |
| `auto_recharge` | `disabled` |

BYOK, tools, plugins and streaming are `excluded`. Service accounts, shared workspaces, invoiced credit and automatic recharge are not covered. The account object also requires `authority_label`, `credential_reference_identity` and `review_evidence`. The witness carries the same three evidence roles, source format and time rules as the Go witness.

Requests carry the bare effective selector as the model name, and Open Trestle refuses known `-free` selectors and `big-pickle`. Do not use the Go endpoint, a subscription allowance, OpenRouter routing controls or an implicit fallback.

### Console replies and cost

As with Go, only assistant content reaches the candidate parser, and `reasoning_content` is validated and discarded. The native prompt and completion counters stay separate from the billed counters. Every Console result has unknown neutral usage and unknown actual cost, even when the reply reports a positive charge, so the full reservation stays held and no free zero is recorded.

When a reply includes billing, the block must have `billing_source` `balance`, a nonnegative `list_cost`, six bounded billed counters, `estimated` absent or false and no Go allowance. A wrong free, Go or BYOK source is refused. `usage.cost` accepts positive and nonnegative amounts, and treats absent or null as unknown, not free. USD values use exact decimal arithmetic and round upward to micro-USD.

A completed, valid reply keeps a typed `RouteReportedDebitUpperBound` when it has an explicit `billing_source:"balance"`, no `estimated:true` and a numeric `usage.cost`. The value is limited to 1 << 62 micro-USD, and a numeric zero that is present is distinct from absence. The bound does not replace `RouteActualCost`: actual cost stays unknown and the reservation stays held.

A 429 from the Console can be a refusal because of a policy budget, not only temporary throttling. It is retried as for every profile (see [provider failures](remote-model-review.md#provider-failures)). Budgets are checked at request start, so requests that are already running may exceed them slightly.

## Qualification limits

Model catalog metadata does not approve privacy or entitlement, activate routes or discover dispatch endpoints. The ordinary local-only composition refuses brokered routes. These remain separate requirements: separate eligibility for direct verification, admission by protected configuration, scanner proof, publication authority and live qualification.
