# OpenCode Console Chat profile

The OpenCode Console Chat profile, `opencode_console_chat_v1`, lets an operator route review requests to the paid OpenCode Console inference endpoint through a reviewed, protected configuration. This page is for operators who prepare that configuration and for contributors who work on the adapter.

## Status

Runtime policy v5 adds the finite `opencode_console_chat_v1` profile. The profile stays inactive until you supply a protected runtime policy and route inventory and the exact reviewed authority for the route. It is offline protocol and admission support only. It is not a qualification of the live service, an account approval, consent to send private source code, or permission to spend money.

`trestle init` and `trestle setup bootstrap init` do not write this profile. The operator prepares the protected policy and inventory by hand.

Historical v1 to v4 schema identities are unchanged. The Go and OpenRouter profiles remain separate named contracts. The ordinary local-only composition refuses this route.

## Connection and account

Use the existing `openai_chat_completions` adapter with these settings:

- the endpoint exactly `https://opencode.ai/inference/openai/v1`
- bearer credentials through an explicit `OPEN_TRESTLE_PROVIDER_` reference
- provider `opencode-console`
- zone `brokered_remote`
- content logging disabled

Requests carry the bare effective selector as the model name. `glm-5.3-flash` is a representative paid fixture, not a default and not an approved model. Open Trestle refuses known `-free` selectors and `big-pickle`, because the upstream only permits free-tier chat from OpenCode itself. Do not use the Go endpoint, a subscription allowance, OpenRouter routing controls or an implicit fallback.

### Route authority

`opencode_console_authority` contains exactly seven non-null fields: `route_record_identity`, `evidence_manifest_digest`, `account_policy_identity`, `tenant_id`, `repository_id`, `valid_from` and `valid_until`. The Go and OpenRouter authority fields are mutually exclusive with these, including when a field is present but null. Generic connections carry no authority fields. Policy v5 still accepts the existing Go, OpenRouter and generic branches.

### Supported account shape

The first account shape is deliberately narrow: personal keys, a single-member workspace and a prepaid balance. In the witness account, these values apply:

| Field | Value |
|---|---|
| `billing_mode` | `prepaid_balance` |
| `key_kind` | `personal` |
| `models_request` | true |
| `workspace_membership` | `single_member` |
| `privacy_training` | `disabled` |
| `auto_recharge` | `disabled` |

BYOK (bring your own key), tools, plugins and streaming are `excluded`. The provider supports other account forms, but this first branch does not extend to service accounts, shared workspaces, invoiced credit or automatic recharge. A public page does not prove who really owns a key, what its settings are, or that its owner consented.

The account object also requires `authority_label`, `credential_reference_identity` and `review_evidence`.

### Account identity

The account identity is the SHA-256 of the Go `encoding/json.Marshal` output of a wrapper object. The wrapper's fields, in order, are `contract`, `version` and `account`. The contract is `open-trestle/opencode-console-account-policy` and the version is 1.

- The account fields are ordered `authority_label`, `credential_reference_identity`, `billing_mode`, `key_kind`, `models_request`, `workspace_membership`, `privacy_training`, `auto_recharge`, `review_evidence`.
- Each source has the fields `url`, `retrieved_at`, `content_sha256`, in that order.
- The credential reference identity hashes `open-trestle/provider-credential-environment/` followed by the exact environment variable name, never its value.

Use the maintained native types to compute identities. Changing a secret behind an unchanged reference does not prove that the account stayed the same.

## Privacy evidence

The reserved `opencode_console_privacy` member is the privacy witness. It is a reviewed record of the privacy claims that the route depends on. Its contract is `open-trestle/opencode-console-privacy-witness`, with integer schema version 1. It binds these values:

- the complete route tuple and the effective selector
- the endpoint, profile, protocol and authentication
- the tenant and repository
- a finite, reviewed validity window
- the account identity

`model_version` is required and non-null. It may be empty, and then the model ID is the effective selector.

The witness carries the same three explicit evidence roles and the same strict source format as the Go witness: the exact model, the broker scope and the actual account review. Model training is `disabled`, and `retention_days`, when present and non-null, is the integer 0. The broker retention contract is `model_specific_documented_zero_days`. That is a reviewed, documented claim, not an unconditional warranty from the provider.

The client declares `user_agent: open-trestle/1` and `session_derivation: authorized_review_scope_sha256_v1`.

### Time and source rules

- The review is no later than `valid_from`.
- Source retrieval is no later than the review.
- `valid_from` is strictly before `valid_until`. The start is inclusive and the end is exclusive.
- Open Trestle invents no default time to live and no grace period.
- Sources use HTTPS URLs without userinfo, query or fragment, canonical UTC retrieval times, and nonzero lowercase SHA-256 content hashes.
- A duplicate, aliased, unknown, missing or null required field refuses typed consumption.
- The existing manifest and inventory limits and the protected configuration authority apply.

### What the providers document

The official Console Models page, retrieved October 31, 2026, states zero retention by the provider and no training, with exceptions:

- OpenAI and Anthropic requests are retained for 30 days.
- Mistral inputs are not used for training, but retention follows Mistral's own policy.
- Beam Free has no training but keeps data for 30 days for safety.
- Flint 40B Free may improve the model and retains data for 30 days.
- Big Pickle, MiMo-V2.6-Flash Free and the NVIDIA Nemotron trial endpoints have improvement or logging exceptions. These are not general permission for private source code.

No training is not the same as zero data retention.

The broker's Privacy Policy (effective March 6, 2026) describes prompt pass-through as not stored. Account, payment and device data have separate business and legal retention. The Terms (effective August 15, 2026) distinguish retention by third-party models and permit improvement from unpaid accounts. Do not collapse these statements into zero retention for the whole service. The paid model you select and your actual account must each meet the zero-day branch on their own. A metadata record or a digest alone does not approve privacy or entitlement.

## Request, response and cost

Requests are bounded, non-streaming JSON Chat POSTs. They carry the trusted instructions, the sanitized user content, an explicit output cap and `stream:false`. They set `User-Agent: open-trestle/1`, and they set `x-opencode-session` to `trestle_` plus the lowercase SHA-256 of `open-trestle/opencode-console-session/v1/` followed by the validated review-scope identity. The value is stable for each authorized scope. It is not a raw repository label, a credential or a secrecy claim.

The scope proof is checked before credentials are resolved and before dispatch. The upstream recommends the session header for Console. Open Trestle does not present the session wording that the Go profile requires as a Console requirement.

### Reply handling

Only assistant content reaches the candidate parser. Bounded optional `reasoning_content` is validated and discarded. Accepting it is a local compatibility choice, not a claim of an official GLM response guarantee.

The native prompt and completion counters stay separate from the billed counters. Their overflow-safe sum supplies a missing total, and a total that the reply supplies must match exactly. Partial or malformed native usage is refused. The native details are validated, but this first profile does not export native counters to the ledger.

Every Console result has unknown neutral usage and unknown actual cost, including when the reply reports a positive charge. The unchanged reconciliation path keeps the full reservation and never records a free zero.

### Billing block

When a reply includes billing, the Console billing block is closed. It must have these properties:

- the source is exactly `balance`
- a required nonnegative `list_cost`
- six required, bounded billed counters
- `estimated` absent or false
- no Go allowance

Billed input excludes cache reads and writes, and billed output includes reasoning. Do not equate the billed counters with the native prompt and completion counts, and do not require that billed cache reads are at most the native prompt count. A wrong free, Go or BYOK source is refused.

`usage.cost` accepts positive and nonnegative amounts, and treats absent or null as unknown, never as free. USD values use bounded exact decimal arithmetic and round upward to micro-USD. Source numbers have at most 64 bytes and an exponent magnitude of at most 64, and the rounded result must fit in a uint64. Malformed or unknown extensions are refused.

### Reported debit bound

A completed, valid reply keeps a typed `RouteReportedDebitUpperBound` when it has an explicit `billing_source:"balance"`, no `estimated:true` and a numeric `usage.cost`. The supported money domain limits this evidence to 1 << 62 micro-USD. Exact rational parsing rounds upward, which keeps the documented relation that the eventual account debit is at most the reported cost. A numeric zero that is present is distinct from absent evidence. A missing or null cost, a list price alone, or a missing billing block supplies no bound. The constructor validates the representation. It does not establish where the provider data came from, and it does not authorize spending.

The response, the dispatch, the attempt outcome and the existing durable records bind this optional evidence in their identities. When the evidence is absent, the legacy bytes and identities are unchanged. Strict older readers reject extended records. Accounting-only completion records keep the bound even if admitting the output fails later.

The billed counters are still discarded, and the bound is never substituted for `RouteActualCost`. Actual cost stays unknown and the full reservation stays held. Native-token tariffs cannot express Console billing or cached prices, so accurate settlement of billed usage and cost is unsupported. This is not a service qualification, and it is not proof of a conservative all-billed quantity and rate bound before dispatch. The upstream says that a reported charge may exceed the final debit when the balance runs out, and never be lower.

Neither a parse failure nor a cancellation reverses spend, and retaining a reservation does not prove that it bounds the final charge.

The representative price table on October 31 lists $0.15 per million input tokens, $0.50 per million output tokens and $0.03 per million cached-read tokens. No zero-price activation and no permanent price claim follows from it. Credit purchases incur 4.6% + $0.31, so do not add that fee to every inference.

### Failure handling

- 401 and 403 use the existing authentication and authorization failures.
- 402 maps to `payment_required` with no replay side effect, the class every profile uses for 402. Like a spent budget, it is neither retried nor eligible for fallback. The task is refused as `policy`, and the local review reports `provider_payment_required`.
- 404 and 410 map to `model_unavailable` and `model_retired`, as for every profile.
- 429 includes a refusal because of a policy budget, so it is not always temporary RPM throttling. Like every profile's 429, and like a 503 that names a `Retry-After`, it records known zero usage. Open Trestle retries it on the same route at most twice inside the task attempt, after its `Retry-After` or the task's fixed delay, and each retry takes over the refused attempt's reservation. Budgets are checked at request start, so requests that are already running may exceed them slightly.
- 400, 405, 415 and 422 reject the request as invalid, for example for an unknown model ID or an unsupported parameter. They map to `request_rejected`, as for every profile. The request is not retried, the task is refused as `policy`, and the local review reports `provider_request_rejected`.
- A malformed reply, or a status that no class names (for example 409), keeps the task's `internal` failure and records `provider_response_invalid`.
- Timeouts, transport loss, 5xx responses and malformed replies after the request took effect stay outcome unknown. There is no other automatic retry, no fallback and no raw upstream error body stored.

## Metadata and setup

Manual authenticated metadata uses the existing refresh and apply path, not another registry. A protected source manifest can use the following shape. It is a non-secret declaration. It does not permit a network request and does not activate anything.

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

Remote refresh still needs your explicit opt-in. Applying the result needs the exact reviewed proposal and current digests. The credential grants authority over metadata only, and it is not implicit authorization for inference. Returned metadata cannot choose the dispatch endpoint, prove the privacy or account posture, or activate a route. A failed refresh keeps the last-known-good entries through the existing contract.

The normal runtime catalog checks the current evidence before it resolves credential providers. Setup accepts an exact approved Console generator together with the existing distinct private direct verifier. It keeps the independence of provider, origin, connection and credential, and it keeps the scope. Setup checks do not create keys, payment methods, approvals or services.

Native tests use fake transports, loopback services and synthetic evidence. Real qualification of the model, cost, cancellation, privacy and account needs separate exact authorization, safe credentials and bounded live caps.

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
