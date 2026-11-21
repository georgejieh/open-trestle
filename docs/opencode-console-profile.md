# OpenCode Console Chat profile

The OpenCode Console Chat profile, `opencode_console_chat_v1`, lets an operator route review requests to the paid OpenCode Console inference endpoint through a protected configuration. This page is for operators who prepare that configuration and for contributors who work on the adapter.

## Status

Runtime policy v5 adds the finite `opencode_console_chat_v1` profile. The profile stays inactive until you supply a protected runtime policy and route inventory and the reviewed authority for the route. It adds protocol and admission support only.

`trestle init` and `trestle setup bootstrap init` do not write this profile. The operator prepares the protected policy and inventory by hand.

The Go and OpenRouter profiles remain separate named contracts. The ordinary local-only composition refuses this route.

## Connection and account

Use the existing `openai_chat_completions` adapter with these settings:

- the endpoint `https://opencode.ai/inference/openai/v1`
- bearer credentials through an explicit `OPEN_TRESTLE_PROVIDER_` reference
- provider `opencode-console`
- zone `brokered_remote`
- content logging disabled

Requests carry the bare effective selector as the model name. `glm-5.3-flash` is an example of a paid model, not a default. Open Trestle refuses known `-free` selectors and `big-pickle`, because the upstream only permits free-tier chat from OpenCode itself. Do not use the Go endpoint, a subscription allowance, OpenRouter routing controls or an implicit fallback.

### Route authority

`opencode_console_authority` contains seven non-null fields: `route_record_identity`, `evidence_manifest_digest`, `account_policy_identity`, `tenant_id`, `repository_id`, `valid_from` and `valid_until`. The Go and OpenRouter authority fields are mutually exclusive with these, including when a field is present but null. Generic connections carry no authority fields. Policy v5 still accepts the existing Go, OpenRouter and generic branches.

### Supported account shape

The supported account shape is narrow: personal keys, a single-member workspace and a prepaid balance. In the witness account, these values apply:

| Field | Value |
|---|---|
| `billing_mode` | `prepaid_balance` |
| `key_kind` | `personal` |
| `models_request` | true |
| `workspace_membership` | `single_member` |
| `privacy_training` | `disabled` |
| `auto_recharge` | `disabled` |

BYOK (bring your own key), tools, plugins and streaming are `excluded`. The profile does not cover service accounts, shared workspaces, invoiced credit or automatic recharge.

The account object also requires `authority_label`, `credential_reference_identity` and `review_evidence`.

### Account identity

The account identity is the SHA-256 of the Go `encoding/json.Marshal` output of a wrapper object. The wrapper's fields, in order, are `contract`, `version` and `account`. The contract is `open-trestle/opencode-console-account-policy` and the version is 1.

- The account fields are ordered `authority_label`, `credential_reference_identity`, `billing_mode`, `key_kind`, `models_request`, `workspace_membership`, `privacy_training`, `auto_recharge`, `review_evidence`.
- Each source has the fields `url`, `retrieved_at`, `content_sha256`, in that order.
- The credential reference identity hashes `open-trestle/provider-credential-environment/` followed by the environment variable name, not its value.

Use the maintained native types to compute identities.

## Privacy evidence

The reserved `opencode_console_privacy` member is the privacy witness. It records the privacy claims that the route depends on. Its contract is `open-trestle/opencode-console-privacy-witness`, with integer schema version 1. It binds these values:

- the route tuple and the effective selector
- the endpoint, profile, protocol and authentication
- the tenant and repository
- a validity window
- the account identity

`model_version` is required and non-null. It may be empty, and then the model ID is the effective selector.

The witness carries the same three evidence roles and the same source format as the Go witness: the model, the broker scope and the account review. Model training is `disabled`, and `retention_days`, when present and non-null, is the integer 0. The broker retention contract is `model_specific_documented_zero_days`. It is the provider's documented claim, not a warranty.

The client declares `user_agent: open-trestle/1` and `session_derivation: authorized_review_scope_sha256_v1`.

### Time and source rules

- The review is no later than `valid_from`.
- Source retrieval is no later than the review.
- `valid_from` is before `valid_until`. The start is inclusive and the end is exclusive.
- There is no default time to live and no grace period.
- Sources use HTTPS URLs without userinfo, query or fragment, canonical UTC retrieval times, and nonzero lowercase SHA-256 content hashes.
- A duplicate, aliased, unknown, missing or null required field is refused.
- The existing manifest and inventory limits apply.

### What the providers document

The Console Models page, retrieved October 31, 2026, states zero retention by the provider and no training, with exceptions:

- OpenAI and Anthropic requests are retained for 30 days.
- Mistral inputs are not used for training, but retention follows Mistral's own policy.
- Beam Free has no training but keeps data for 30 days for safety.
- Flint 40B Free may improve the model and retains data for 30 days.
- Big Pickle, MiMo-V2.6-Flash Free and the NVIDIA Nemotron trial endpoints have improvement or logging exceptions. These do not suit private source code.

No training is not the same as zero data retention.

The broker's Privacy Policy (effective March 6, 2026) describes prompt pass-through as not stored. Account, payment and device data have separate business and legal retention. The Terms (effective August 15, 2026) distinguish retention by third-party models and permit improvement from unpaid accounts. These statements do not amount to zero retention for the whole service. The paid model you select and your account must each meet the zero-day branch.

## Request, response and cost

Requests are non-streaming JSON Chat POSTs. They carry the trusted instructions, the sanitized user content, an explicit output cap and `stream:false`. They set `User-Agent: open-trestle/1`, and they set `x-opencode-session` to `trestle_` plus the lowercase SHA-256 of `open-trestle/opencode-console-session/v1/` followed by the validated review-scope identity. The value is stable for each review scope.

The scope proof is checked before credentials are resolved and before dispatch. The upstream recommends the session header for Console.

### Reply handling

Only assistant content reaches the candidate parser. Optional `reasoning_content` is validated and discarded.

The native prompt and completion counters stay separate from the billed counters. Their overflow-safe sum supplies a missing total, and a total that the reply supplies must match. Partial or malformed native usage is refused. The native details are validated, but this first profile does not export native counters to the ledger.

Every Console result has unknown neutral usage and unknown actual cost, including when the reply reports a positive charge. The reconciliation path keeps the full reservation and does not record a free zero.

### Billing block

When a reply includes billing, the Console billing block must have these properties:

- the source is `balance`
- a required nonnegative `list_cost`
- six required, bounded billed counters
- `estimated` absent or false
- no Go allowance

Billed input excludes cache reads and writes, and billed output includes reasoning. Do not equate the billed counters with the native prompt and completion counts, and do not require that billed cache reads are at most the native prompt count. A wrong free, Go or BYOK source is refused.

`usage.cost` accepts positive and nonnegative amounts, and treats absent or null as unknown, not free. USD values use exact decimal arithmetic and round upward to micro-USD. Source numbers have at most 64 bytes and an exponent magnitude of at most 64, and the rounded result must fit in a uint64. Malformed or unknown extensions are refused.

### Reported debit bound

A completed, valid reply keeps a typed `RouteReportedDebitUpperBound` when it has an explicit `billing_source:"balance"`, no `estimated:true` and a numeric `usage.cost`. The supported money domain limits this value to 1 << 62 micro-USD. Parsing rounds upward. A numeric zero that is present is distinct from absence. A missing or null cost, a list price alone, or a missing billing block supplies no bound.

The response, the dispatch, the attempt outcome and the durable records bind this optional value in their identities. Older readers reject extended records. Accounting-only completion records keep the bound even if admitting the output fails later.

The billed counters are discarded, and the bound does not replace `RouteActualCost`. Actual cost stays unknown and the full reservation stays held. Native-token tariffs cannot express Console billing or cached prices, so settlement of billed usage and cost is unsupported. The upstream says that a reported charge may exceed the final debit when the balance runs out, and is never lower. A parse failure or a cancellation does not reverse spend.

The representative price table on October 31 lists $0.15 per million input tokens, $0.50 per million output tokens and $0.03 per million cached-read tokens. Prices can change. Credit purchases incur 4.6% + $0.31, so do not add that fee to every inference.

### Failure handling

- 401 and 403 use the existing authentication and authorization failures.
- 402 maps to `payment_required` with no replay side effect, the class every profile uses for 402. Like a spent budget, it is not retried. The task is refused as `policy`, and the local review reports `provider_payment_required`.
- 404 and 410 map to `model_unavailable` and `model_retired`, as for every profile.
- 429 includes a refusal because of a policy budget, so it is not always temporary RPM throttling. Like every profile's 429, and like a 503 that names a `Retry-After`, it records known zero usage. Open Trestle retries it on the same route at most twice inside the task attempt, after its `Retry-After` or the task's fixed delay, and each retry takes over the refused attempt's reservation. Budgets are checked at request start, so requests that are already running may exceed them slightly.
- 400, 405, 415 and 422 reject the request as invalid, for example for an unknown model ID or an unsupported parameter. They map to `request_rejected`, as for every profile. The request is not retried, the task is refused as `policy`, and the local review reports `provider_request_rejected`.
- A malformed reply, or a status that no class names (for example 409), keeps the task's `internal` failure and records `provider_response_invalid`.
- Timeouts, transport loss, 5xx responses and malformed replies after the request took effect stay outcome unknown. There is no other automatic retry and no fallback, and no upstream error body is stored.

## Metadata and setup

Manual authenticated metadata uses the existing refresh and apply path. A protected source manifest can use the following shape. It is a non-secret declaration and does not itself make a request or activate anything.

```json
{
  "schema_version": 2,
  "sources": [{
    "id": "opencode-console",
    "kind": "openai_models",
    "url": "https://opencode.ai/inference/v1/models",
    "credential_environment": "OPEN_TRESTLE_PROVIDER_OPENCODE_CONSOLE"
  }]
}
```

Remote refresh needs your explicit opt-in. Applying the result needs the reviewed proposal and current digests. The credential covers metadata only, not inference. Returned metadata cannot choose the dispatch endpoint or activate a route. A failed refresh keeps the last-known-good entries.

The normal runtime catalog checks the current evidence before it resolves credential providers. Setup accepts an approved Console generator together with a distinct private direct verifier, which must differ in provider, origin, connection and credential. Setup checks do not create keys, payment methods, approvals or services.

## Official sources

Retrieved October 31, 2026:

- https://opencode.ai/v2/docs/console/models/
- https://opencode.ai/v2/docs/console/api/inference/
- https://opencode.ai/v2/docs/console/api/
- https://opencode.ai/v2/docs/console/harnesses/
- https://opencode.ai/v2/docs/console/billing/
- https://opencode.ai/v2/docs/console/budgets/
- https://opencode.ai/legal/privacy-policy
- https://opencode.ai/legal/terms-of-service
