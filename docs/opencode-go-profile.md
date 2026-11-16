# OpenCode Go Chat profile

The OpenCode Go Chat profile, `opencode_go_chat_v1`, lets an operator route review requests through an OpenCode Go subscription account. This page is the operator contract for that profile: what the configuration must contain, what evidence backs it, and what Open Trestle does with each reply. It is not a qualification of the live service and it does not describe a ready configuration.

## Status and activation boundary

Runtime policy v4 defines the finite `opencode_go_chat_v1` profile alongside the existing generic and OpenRouter connections. The setup checker supports an exact approved Go generation route together with a distinct private direct verifier. That support does not qualify the live service.

`trestle init --provider opencode-go` and `trestle setup bootstrap init --provider opencode-go` write this profile's policy and inventory from the evidence and declarations that you supply (see [remote model review](remote-model-review.md#opencode-go)). No command creates credentials, issues the approval or activates a route on its own. Do not treat a schema-valid document, a metadata refresh or a setup receipt as authority to dispatch. The daemon consumes the protected runtime policy and inventory.

The historical runtime policy v1, v2 and v3 schema bytes and accepted identity preimages are unchanged. V4 continues to accept generic connections and the existing `openrouter_zdr_chat_v1` profile. It does not change OpenRouter's retention contract, and it does not reuse OpenRouter's `provider.zdr` request controls for Go.

Before you activate the profile, these steps must be done independently:

- native static validation
- the named common catalog and adapter integration
- tests of the actual sanitized-handler callers
- separate setup-authority support and the required gates

An operator must then approve the exact account, the model, the evidence, the egress of private source code, and a defensible, conservative reservation. Representative live qualification requires separate explicit authorization, credentials, and bounded caps on requests, cost and time. Offline fixtures alone do not qualify the live protocol, cancellation, privacy or usage.

## Connection and authority

The selected Go generation connection uses these settings:

- `implementation`: `openai_chat_completions`
- `endpoint`: exactly `https://opencode.ai/inference/go/openai/v1`
- bearer mode, with an explicit `OPEN_TRESTLE_PROVIDER_` credential reference
- `request_profile`: `opencode_go_chat_v1`
- provider `opencode-go`, zone `brokered_remote`, disabled content logging and one approved, exact inventory record
- a distinct, eligible `private_remote` direct verifier, which is not the brokered route

### Route authority

`opencode_go_authority` has exactly seven required, non-null keys: `route_record_identity`, `evidence_manifest_digest`, `account_policy_identity`, `tenant_id`, `repository_id`, `valid_from` and `valid_until`. They bind the exact record, the immutable typed manifest, the derived account identity, the repository scope and the validity interval. It has no `provider_slug`.

`brokered_route_authority` and `opencode_go_authority` are mutually exclusive, even when one of them is null. Generic connections carry neither authority nor `request_profile`. The OpenRouter branch keeps its eight-field authority and its exact endpoint.

### Model selection

Model selection belongs to the operator. `glm-5.3-flash` below is a representative fixture, not a default and not a model approval. Its bare effective selector goes on the wire of the direct API. `opencode-go/` is a client configuration namespace, not a prefix to add to a direct model ID. Go's pay-as-you-go, Responses, Anthropic, Gemini, free-tier and tools or BYOK paths are not part of this profile.

## Typed privacy and account witness

The immutable evidence manifest contains the reserved `opencode_go_privacy` member. This is the privacy and account witness: a reviewed record of the claims the route depends on. Its local contract is `open-trestle/opencode-go-privacy-witness`, with integer schema version 1. It binds these values:

- the complete route tuple and the effective selector
- the endpoint, profile, protocol and authentication
- the exact model's privacy and the broker's privacy
- the account
- the tenant and repository
- the reviewed validity interval

If typed evidence is missing or invalid, Open Trestle refuses Go consumption by name. Generic opaque manifests keep their existing admission semantics. A digest is not privacy approval.

### Evidence roles and sources

Three evidence roles are required:

- the exact model's no-training and zero-day retention
- the privacy scope of the broker or service
- a distinct review of the actual account or workspace

The roles may reference the same artifact when it supports all of those claims. A public terms page does not establish account settings or key ownership.

Each source has these properties:

- an HTTPS `url` of at most 2048 UTF-8 bytes, with a host and without userinfo, query or fragment
- a canonical UTC `retrieved_at`
- a nonzero lowercase `content_sha256`

Labels are at most 256 UTF-8 bytes. The parser checks syntax and linkage, which cannot prove what the evidence says, how the provider behaves or who owns the account. It does not fetch evidence URLs.

### Account and client

The first account shape is exactly subscription `go`, workspace membership `single_member`, privacy training `disabled` and Extra Usage `disabled`. Go Plus, Teams, service accounts and a balance fallback need separate design and evidence. Open Trestle does not infer them from the endpoint or from a zero request cost. BYOK, tools, plugins and streaming are `excluded`. The client declaration is exactly `open-trestle/1` and `authorized_review_scope_sha256_v1`.

### Model version, retention and parsing

`model_version` must be present and non-null, but it may be empty. An empty version uses the model ID as the effective selector, and otherwise the version is the selector. `retention_days` is a present, non-null integer that is exactly 0, and training is `disabled`. The broker retention is `model_specific_documented_zero_days`, which is a documented claim that an operator reviewed, not an unconditional warranty from the provider.

A duplicate, aliased or unknown field, a missing or null required field, and trailing values all refuse typed consumption. Open Trestle scans the entire original manifest before it extracts the reserved member. The existing limits apply: a 1 MiB manifest and an inventory of 64 routes and 8 MiB.

### Time rules

- Every source retrieval is no later than the review.
- The review is no later than `valid_from`.
- `valid_from` is strictly before `valid_until`. The interval includes its start and excludes its end.
- A dated source agreement must not outlive its stated expiry, so translate the exclusive bound explicitly.
- Where no service-wide expiry exists, choose a finite reviewed window. Do not claim it is a provider TTL.
- The native parser cannot find a contractual expiry from the content of a document.
- There is no default TTL and no grace period.
- In the complete integration, currentness is checked before credential resolution and again before dispatch effects.

## Synthetic format example

This is an offline fixture with no secrets. It is not a real account review and not a live approval. The `.invalid` URLs and the hashes label synthetic artifacts. Replace all route, source, account, scope and window inputs through protected review. Then recompute the account, manifest, record, inventory and policy identities, in that order. Never copy this example as provider evidence or as a ready policy.

```json
{
  "opencode_go_privacy": {
    "contract": "open-trestle/opencode-go-privacy-witness",
    "schema_version": 1,
    "route": {
      "zone": "brokered_remote",
      "provider_id": "opencode-go",
      "adapter_id": "adapter-a",
      "connection_id": "primary/opencode-go",
      "model_id": "glm-5.3-flash",
      "model_version": "",
      "effective_selector": "glm-5.3-flash"
    },
    "endpoint": "https://opencode.ai/inference/go/openai/v1",
    "request_profile": "opencode_go_chat_v1",
    "protocol": "openai_chat_completions",
    "credential_mode": "bearer",
    "model_privacy": {
      "training": "disabled",
      "retention_days": 0,
      "evidence": {
        "url": "https://evidence.fixture.invalid/go/glm-5.3-flash-privacy",
        "retrieved_at": "2026-10-29T00:00:00Z",
        "content_sha256": "6411c64f0e97782bfa36e83dae22b1d7552d8636660a6983fe8aa70f987ee7f4"
      }
    },
    "broker_privacy": {
      "retention_contract": "model_specific_documented_zero_days",
      "evidence": {
        "url": "https://evidence.fixture.invalid/go/broker-privacy-scope",
        "retrieved_at": "2026-10-29T00:00:00Z",
        "content_sha256": "0e964027f19aa3b82341d257d7104d0d0a8c4fab5ce41008f0dd3e4ba37a15c2"
      }
    },
    "tenant_id": "tenant-a",
    "repository_id": "repository-a",
    "reviewed_at": "2026-10-29T00:00:00Z",
    "valid_from": "2026-10-29T00:00:00Z",
    "valid_until": "2026-11-01T00:00:00Z",
    "byok": "excluded",
    "tools": "excluded",
    "plugins": "excluded",
    "streaming": "excluded",
    "client": {
      "user_agent": "open-trestle/1",
      "session_derivation": "authorized_review_scope_sha256_v1"
    },
    "account": {
      "authority_label": "synthetic Go single-member account, not live approval",
      "credential_reference_identity": "c4e57d4e720439faf991f69945fb8c2a2f0483b22a302a74c0397048eb0d4f78",
      "subscription": "go",
      "workspace_membership": "single_member",
      "privacy_training": "disabled",
      "extra_usage": "disabled",
      "review_evidence": {
        "url": "https://account-review.fixture.invalid/go/privacy-and-extra-usage",
        "retrieved_at": "2026-10-29T00:00:00Z",
        "content_sha256": "aed3632278360014a40066e0fe0e23900164283c67b462c951a853d73fec574b"
      }
    }
  }
}
```

### Account identity recipe

`account_policy_identity` is the lowercase SHA-256 of the `encoding/json.Marshal` output of a fixed wrapper, with no newline and no key sorting. Go JSON escaping and canonical UTC strings matter. The field orders are:

- wrapper: `contract`, `version`, `account`
- account: `authority_label`, `credential_reference_identity`, `subscription`, `workspace_membership`, `privacy_training`, `extra_usage`, `review_evidence`
- source: `url`, `retrieved_at`, `content_sha256`

The credential reference identity is the SHA-256 of `open-trestle/provider-credential-environment/` plus the exact environment variable name, never its value. Changing the account, its settings, the review evidence or the reference changes the account identity and every identity that encloses it. Replacing a real key behind the same reference does not establish that the account stayed the same.

Save the calculation below, which uses only the standard library, outside the product tree as `go-account-identity.go`. Given the non-secret witness file, the offline command is `go run go-account-identity.go manifest.json`. The recipe makes no network request and looks up no credential. Its permissive decoding is not the product validator, and it only calculates a candidate digest. It grants no setup authority and does not show readiness.

```go
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

type source struct {
	URL           string `json:"url"`
	RetrievedAt   string `json:"retrieved_at"`
	ContentSHA256 string `json:"content_sha256"`
}

type account struct {
	AuthorityLabel              string `json:"authority_label"`
	CredentialReferenceIdentity string `json:"credential_reference_identity"`
	Subscription                string `json:"subscription"`
	WorkspaceMembership         string `json:"workspace_membership"`
	PrivacyTraining             string `json:"privacy_training"`
	ExtraUsage                  string `json:"extra_usage"`
	ReviewEvidence              source `json:"review_evidence"`
}

func main() {
	if len(os.Args) != 2 {
		panic("usage: go run go-account-identity.go manifest.json")
	}
	file, err := os.Open(os.Args[1])
	if err != nil {
		panic(err)
	}
	defer file.Close()
	encoded, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil || len(encoded) > 1<<20 {
		panic("cannot read bounded manifest")
	}
	var manifest struct {
		Privacy struct {
			Account account `json:"account"`
		} `json:"opencode_go_privacy"`
	}
	if err := json.Unmarshal(encoded, &manifest); err != nil {
		panic(err)
	}
	preimage, err := json.Marshal(struct {
		Contract string  `json:"contract"`
		Version  int     `json:"version"`
		Account  account `json:"account"`
	}{"open-trestle/opencode-go-account-policy", 1, manifest.Privacy.Account})
	if err != nil {
		panic(err)
	}
	digest := sha256.Sum256(preimage)
	fmt.Println(hex.EncodeToString(digest[:]))
}
```

For exactly the synthetic account above, the compact, ordered UTF-8 preimage is 581 bytes, and its SHA-256 is `b7202d516d63a29f9886372fb0d23caa4c316d83572e2181534097e64b0e773f`. The Go recipe reproduces this value from the ASCII-only ordered fixture, without a trailing newline. It is not a digest of a real account or of the complete evidence manifest.

## Session, response and accounting

### Session header

After Open Trestle validates the sanitizer proof for the repository, run and request, the request sets `x-opencode-session` to `trestle_` followed by the lowercase SHA-256 of the UTF-8 text `open-trestle/opencode-go-session/v1/` plus the validated review-scope identity. The value is exactly 72 ASCII bytes. It stays the same within that scope, even across roles and requests, and differs between authorized reviews. It carries no raw scope labels, key or user text. The hash is an opaque format, not secrecy and not an authentication token. Payload fields cannot override it. The User-Agent is exactly `open-trestle/1`.

### Requests

Requests are bounded, non-streaming Chat POSTs with `stream:false`, the existing sanitized user content, the trusted instructions and an output cap. This profile introduces no OpenRouter routing body, no endpoint substitution, no retry and no fallback.

### Replies

Go-only `message.reasoning_content` is validated and then discarded. It never becomes candidate output, audit content or a separate reasoning artifact. Only assistant content reaches the existing candidate parser.

### Token counts

Known native `prompt_tokens` and `completion_tokens` stay bounded counts that the provider reported. An optional total must equal their overflow-safe sum, and an absent total is derived from that known pair. If the whole usage is missing or null, it stays unknown and is never treated as free. Partial or malformed native counts are refused. Only the native `cached_tokens` details can supply the neutral cached subset.

The billed `opencode.tokens.input` excludes cache reads and writes, and billed output includes reasoning. Those counters are a separate family. Never equate billed input with the prompt count, never add cache reads to the prompt count, and never assume that cache reads are at most `prompt_tokens`. Open Trestle validates the bounded billed counters and then discards them, rather than manufacturing neutral counts from them.

### Billing block

When an `opencode` billing block is present, it is closed:

- `billing_source` is exactly `go`
- `list_cost` and `allowance` are required, finite and nonnegative
- the billed counters are closed
- `estimated` is absent or false

Balance, free, BYOK, go-plus and estimated billing are refused. In this case,
where Extra Usage is disabled, `usage.cost` may be absent, null or numeric zero. A positive charge is a contradictory result after the effect has happened, so Open Trestle refuses it, but the refusal cannot undo the charge. A zero cost or allowance does not authorize a free route or a future balance. Unknown or malformed extensions are rejected, not silently treated as zero.

### Cost reconciliation

The existing cost reconciliation, with two rates fixed in the record, is registry accounting. It is not reconciliation against the Console bill and not a technical cap on account spend. Operator-reviewed prices and a pessimistic reservation must be conservative and must account for the selected model's cache-tier terms. Subscription pricing does not justify zero rates. If no defensible, conservative reservation is possible, refuse activation.

When usage is genuinely absent, the existing handler keeps an explicit unknown outcome and its reservation, and it must not discard valid native counts. A budget refusal that comes late cannot reverse an effect on the service.

## Qualification limits

Model catalog metadata does not approve privacy or entitlement, activate routes or discover dispatch endpoints. The ordinary local-only composition still refuses brokered routes.

These are independent requirements:

- setup Go authority
- separate eligibility for direct verification
- admission by protected configuration
- scanner proof
- publication authority
- live qualification

OpenCode pay-as-you-go and Ollama Cloud remain separate, named conformance work.

The official-source basis is the retained public OpenCode Go, Console inference and harness documentation, retrieved October 30, 2026. Review the current account and model terms again before activation:

- https://opencode.ai/v2/docs/console/go
- https://opencode.ai/v2/docs/console/api/inference
- https://opencode.ai/v2/docs/console/harnesses
