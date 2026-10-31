# OpenCode Console Chat profile

## Status

Runtime policy v5 adds the finite `opencode_console_chat_v1` profile. It is
inactive without protected policy/inventory and exact reviewed authority. This
is offline protocol and admission support, not live service qualification,
account approval, private-source egress consent or permission to spend.
Historical v1-v4 schema identities stay unchanged. Go and OpenRouter remain
separate named contracts. The ordinary local-only composition refuses this route.

## Connection and account

Use the existing `openai_chat_completions` adapter with exactly
`https://opencode.ai/inference/openai/v1`, bearer credentials through an explicit
`OPEN_TRESTLE_PROVIDER_` reference, provider `opencode-console`, zone
`brokered_remote` and disabled content logging. The bare effective selector goes
on the wire. `glm-5.3-flash` is a representative paid fixture, not a default or
approved model. Known `-free` selectors and `big-pickle` are refused. The upstream
only permits free-tier chat from OpenCode itself. Do not use the Go endpoint,
subscription allowance, OpenRouter routing controls or implicit fallback.

`opencode_console_authority` contains exactly seven non-null fields:
`route_record_identity`, `evidence_manifest_digest`, `account_policy_identity`,
`tenant_id`, `repository_id`, `valid_from`, `valid_until`. Go/OpenRouter authority
fields are mutually exclusive, including null presence. Generic connections
carry none. V5 continues to admit existing Go/OpenRouter/generic branches.

The first account shape is deliberately limited to personal keys, a single-member
workspace and prepaid balance. In the witness account, `billing_mode` is
`prepaid_balance`, `key_kind` is `personal`, `models_request` is true,
`workspace_membership` is `single_member`, `privacy_training` is `disabled` and
`auto_recharge` is `disabled`. The provider supports other account forms, but
service accounts, shared workspaces, invoiced credit and automatic recharge are
not inferred into this first branch. BYOK, tools, plugins and streaming are
`excluded`. A public page does not prove real key ownership, settings or consent.

The account object also requires `authority_label`,
`credential_reference_identity` and `review_evidence`. Account identity is SHA-256
of Go `encoding/json.Marshal` of ordered wrapper fields `contract`, `version`,
`account`, with contract `open-trestle/opencode-console-account-policy`, version
1. Account field order is `authority_label`, `credential_reference_identity`,
`billing_mode`, `key_kind`, `models_request`, `workspace_membership`,
`privacy_training`, `auto_recharge`, `review_evidence`. Source field order is
`url`, `retrieved_at`, `content_sha256`. Credential-reference identity hashes
`open-trestle/provider-credential-environment/` plus the exact environment name,
never its value. Use the maintained native types when computing identities.
Changing a secret behind an unchanged reference does not prove account continuity.

## Privacy evidence

The reserved `opencode_console_privacy` member has contract
`open-trestle/opencode-console-privacy-witness`, integer schema version 1. It
binds the complete route tuple and effective selector, endpoint/profile/protocol/
auth, tenant/repository, finite reviewed validity window and account identity.
`model_version` is required and non-null; it may be empty, in which case model ID
is effective. It carries the same explicit three evidence roles and strict source
format as the Go witness: exact model, broker scope and actual account review.
Model training is `disabled`; present non-null integer `retention_days` is exactly
0. Broker retention contract is `model_specific_documented_zero_days`. This is a
reviewed documented claim, not an unconditional provider warranty.

The client declares `user_agent: open-trestle/1` and
`session_derivation: authorized_review_scope_sha256_v1`. Review is no later than
valid-from; source retrieval is no later than review; valid-from is strictly
before valid-until. Start is inclusive and end exclusive. No default TTL or grace
is invented. Sources use HTTPS URLs without userinfo/query/fragment, canonical
UTC retrieval times and nonzero lowercase SHA-256 content hashes. Duplicate,
aliased, unknown, missing or null required fields refuse typed consumption.
The existing manifest/inventory limits and protected configuration authority apply.

The official Console Models page retrieved October 31, 2026 states provider
zero retention and no training with exceptions. OpenAI and Anthropic requests
are retained 30 days. Mistral inputs are not used for training but retention
follows Mistral's own policy. Beam Free has no training but 30-day safety
retention. Flint 40B Free may improve the model and retains 30 days. Big Pickle,
MiMo-V2.6-Flash Free and NVIDIA Nemotron trial endpoints have improvement/logging
exceptions, not generic private-source permission. No-training is not ZDR.

The broker Privacy Policy (effective March 6, 2026) describes prompt pass-through
as not stored; account/payment/device data has separate business/legal retention.
The Terms (effective August 15, 2026) distinguish third-party model retention and
permit improvement from unpaid accounts. These statements must not be collapsed
into all-service zero retention. The selected paid model and actual account
must meet this zero-day branch independently. A metadata record or digest alone
does not approve privacy or entitlement.

## Request, response and cost

Requests remain bounded nonstream JSON Chat POSTs, with trusted instructions,
sanitized user content, explicit output cap and `stream:false`. They set
`User-Agent: open-trestle/1` and `x-opencode-session` to `trestle_` plus lowercase
SHA-256 of `open-trestle/opencode-console-session/v1/` concatenated with the
validated review-scope identity. This is stable per authorized scope, not a raw
repository label, credential or secrecy claim. Scope proof is checked before
credentials and dispatch. The session is recommended by upstream for Console;
the Go-required session wording is not misrepresented as a Console requirement.

Only assistant content reaches the candidate parser. Bounded optional
`reasoning_content` is validated and discarded. Its acceptance is local
compatibility, not a claimed official GLM response guarantee. Native prompt and
completion counters remain distinct from billed counters. Their overflow-safe
sum supplies missing total; supplied total must match exactly. Partial/malformed
native usage refuses. Native details are validated, but this first profile does
not export native counters to the ledger. Every Console result has unknown
neutral usage and unknown actual cost, including positive reported charge. The
unchanged reconciliation path retains the full reservation, never a free zero.

Present Console billing is closed: source exactly `balance`, required nonnegative
`list_cost`, six required bounded billed counters, `estimated` absent/false and
no Go allowance. Billed input excludes cache reads/writes; billed output includes
reasoning. Do not equate these with native prompt/completion counts or require
billed cache-read <= native prompt count. Wrong free/Go/BYOK sources refuse.
`usage.cost` accepts positive nonnegative amounts, absent/null as unknown, never
as free. USD values use bounded exact decimal arithmetic and upward micro-USD
rounding; source numbers have at most 64 bytes and exponent magnitude at most 64,
and the rounded result must fit uint64. Malformed/unknown extensions refuse.

Reported cost and billed counters are validated then discarded, not substituted
for the existing two-rate `RouteActualCost`. Native-token tariffs do not express
Console billing or cached prices. Accurate billed usage and cost settlement are
unsupported; V1-04 remains incomplete. This is not service qualification. A later
typed settlement contract needs deliberate identity/schema review before it can
retain native counters and monetary information independently. The upstream says
reported charge may exceed final debit when balance runs out, never be lower.
Neither parse failure nor cancellation reverses spend. Retaining a reservation
is not proof that it bounds the final charge. The representative table on
October 31 lists $0.15 input/$0.50 output/$0.03 cached-read per million tokens.
No zero-price activation or permanent price claim follows.
Credit purchases incur 4.6% + $0.31; do not add that fee to every inference.

401/403 use existing authentication/authorization failures. Console 402 maps to
budget exhausted with no replay side effect. 429 includes policy-budget refusal;
it need not be temporary RPM throttling. Budgets are checked at request start,
so already-running requests may exceed them slightly. Timeouts/transport loss/
5xx/malformed post-effect replies remain outcome unknown; there is no automatic
retry, fallback or raw upstream error-body persistence.

## Metadata and setup

Manual authenticated metadata uses the existing refresh/apply path, not another
registry. A protected source manifest can use the shape below; this is a
non-secret declaration, not permission to issue a network request or activate:

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

Remote refresh still needs explicit opt-in; apply needs exact reviewed proposal
and current digests. The credential is metadata authority only, not implicit
inference authorization. Returned metadata cannot choose the dispatch endpoint,
prove privacy/account posture or activate a route. Failed refresh preserves
last-known-good entries through the existing contract.

The normal runtime catalog checks current evidence before resolving credential
providers. Setup admits an exact approved Console generator plus the existing
distinct private direct verifier, retaining provider/origin/connection/credential
independence and scope. Setup checks do not create keys, payment methods,
approvals or services. Native tests use fake transports/loopback services and
synthetic evidence. Real model/cost/cancellation/privacy/account qualification
requires separate exact authorization, safe credentials and bounded live caps.

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
