# OpenCode Go Chat profile

## Status and activation boundary

Runtime policy v4 defines the finite `opencode_go_chat_v1` profile alongside
existing generic and OpenRouter connections. This document describes its
operator contract, not a live-service qualification or a ready configuration.
The setup checker supports an exact approved Go generation route and a distinct
private direct verifier. Setup support does not prove live service qualification.
No command here issues approval, creates credentials or activates a route. Do not
use a schema-valid document, metadata refresh or setup receipt as dispatch authority.
The daemon consumes protected runtime policy and inventory.

Historical runtime-policy v1/v2/v3 schema bytes and accepted identity preimages
stay unchanged. V4 continues to admit generic connections and the existing
`openrouter_zdr_chat_v1` profile. It does not change OpenRouter's retention
contract or reuse OpenRouter's `provider.zdr` request controls for Go.

Before activation, independently complete native static validation, the named
common catalog and adapter integration, actual sanitized-handler caller tests,
separate setup-authority support and required gates. An operator must then
approve the exact account, model, evidence, private-source egress and defensible
conservative reservation. Representative live qualification requires separate
explicit authorization, credentials and bounded request/cost/time caps. Offline
fixtures alone do not qualify live protocol, cancellation, privacy or usage.

## Connection and authority

The selected Go generation connection uses:

- `implementation`: `openai_chat_completions`;
- `endpoint`: exactly `https://opencode.ai/inference/go/openai/v1`;
- bearer mode and an explicit `OPEN_TRESTLE_PROVIDER_` credential reference;
- `request_profile`: `opencode_go_chat_v1`;
- provider `opencode-go`, zone `brokered_remote`, disabled content logging and
  one approved exact inventory record;
- a distinct eligible `private_remote` direct verifier, not the brokered route.

`opencode_go_authority` has exactly seven required non-null keys:
`route_record_identity`, `evidence_manifest_digest`, `account_policy_identity`,
`tenant_id`, `repository_id`, `valid_from`, `valid_until`. They bind the exact
record, immutable typed manifest, derived account identity, repository scope and
validity interval. It has no `provider_slug`. `brokered_route_authority` and
`opencode_go_authority` are mutually exclusive, even if one is null. Generic
connections carry neither authority nor `request_profile`. The OpenRouter branch
retains its eight-field authority and exact endpoint.

Model selection is operator-owned. `glm-5.3-flash` below is a representative
fixture, not a default or model approval. Its bare effective selector goes on
the direct API wire. `opencode-go/` is a client configuration namespace, not a
prefix to add to a direct model ID. Go's pay-as-you-go, Responses, Anthropic,
Gemini, free-tier and tools/BYOK paths are not this profile.

## Typed privacy and account witness

The immutable evidence manifest contains the reserved `opencode_go_privacy`
member with local contract `open-trestle/opencode-go-privacy-witness`, integer
schema version 1. It binds the complete route tuple, effective selector,
endpoint/profile/protocol/auth, exact model and broker privacy, account,
tenant/repository and reviewed validity interval. Missing or invalid typed
evidence refuses named Go consumption; generic opaque manifests keep their
existing admission semantics. A digest is not privacy approval.

Three evidence roles are required: exact model no-training/zero-day retention,
broker/service privacy scope, and a distinct actual account/workspace review.
They may reference the same artifact when it supports those claims. A public
terms page does not establish account settings or key ownership. Sources have
HTTPS `url` (at most 2048 UTF-8 bytes, host, no userinfo/query/fragment), canonical
UTC `retrieved_at` and nonzero lowercase `content_sha256`. Labels are at most
256 UTF-8 bytes. Parser syntax/linkage cannot prove evidence substance, provider
conduct or account ownership, and does not fetch evidence URLs.

The first account shape is exactly subscription `go`, workspace membership
`single_member`, privacy training `disabled`, Extra Usage `disabled`. Go Plus,
Teams, service-account and balance fallback require separate design/evidence;
they are not inferred from the endpoint or a zero request cost. BYOK, tools,
plugins and streaming are `excluded`. The client declaration is exactly
`open-trestle/1` and `authorized_review_scope_sha256_v1`.

`model_version` must be present and non-null but may be empty. An empty version
uses model ID as effective selector; otherwise the version is the selector.
`retention_days` is a present non-null integer exactly 0, and training is
`disabled`. Broker retention is `model_specific_documented_zero_days`, an
operator-reviewed documented claim, not an unconditional provider warranty.
Duplicate, aliased, unknown, missing/null required fields and trailing values
refuse typed consumption. The entire original manifest is scanned before the
reserved member is extracted. Existing 1 MiB manifest and 64-route/8 MiB inventory
bounds apply.

Every source retrieval is no later than review, review no later than
`valid_from`, and `valid_from` strictly before `valid_until`. The interval includes
its start and excludes its end. A dated source agreement must not outlive its
stated expiry; translate the exclusive bound explicitly. Where a service-wide
expiry is absent, choose a finite reviewed window, not a claimed provider TTL.
The native parser cannot discover contractual expiry from document content.
There is no default TTL or grace. Currentness is checked before credential
resolution and again before dispatch effects in the complete integration.

## Synthetic format example

This is an offline non-secret fixture, not a real account review or live approval.
The `.invalid` URLs and hashes label synthetic artifacts. Replace all route,
source, account, scope and window inputs through protected review. Then recompute
account, manifest, record, inventory and policy identities in order. Never copy
this example as provider evidence or a ready policy.

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

`account_policy_identity` is lowercase SHA-256 of `encoding/json.Marshal` of the
fixed wrapper below, without newline or key sorting. Wrapper field order is
`contract`, `version`, `account`. Account order is `authority_label`,
`credential_reference_identity`, `subscription`, `workspace_membership`,
`privacy_training`, `extra_usage`, `review_evidence`. Source order is `url`,
`retrieved_at`, `content_sha256`. Go JSON escaping and canonical UTC strings matter.
Credential-reference identity is SHA-256 of
`open-trestle/provider-credential-environment/` plus the exact environment
variable name, never its value. Changing account/settings/review evidence or
reference changes the account and all enclosing identities. Replacing a real
key behind the same reference does not establish account continuity.

Save the standard-library-only calculation outside the product tree as
`go-account-identity.go`. Given the non-secret witness file, the offline invocation
is `go run go-account-identity.go manifest.json`. This recipe performs no network
or credential lookup. Its permissive decoding is NOT the product validator; it
only calculates a candidate digest. It grants no setup authority or readiness.

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

For exactly the synthetic account above, the compact ordered UTF-8 preimage is
581 bytes, and its SHA-256 is
`b7202d516d63a29f9886372fb0d23caa4c316d83572e2181534097e64b0e773f`.
The Go recipe reproduces this value from the ASCII-only ordered fixture, without
a trailing newline. It is not a digest of a real account or the complete evidence
manifest.

## Session, response and accounting

After repository/run/request sanitizer-proof validation, the request sets
`x-opencode-session` to `trestle_` followed by lowercase SHA-256 of UTF-8
`open-trestle/opencode-go-session/v1/` concatenated with the validated review-scope
identity. It is exactly 72 ASCII bytes, stable within that scope even across
roles/requests and distinct across authorized reviews. It carries no raw scope
labels, key or user text. Hashing is opaque formatting, not secrecy or an auth
token. Payload fields cannot override it. User-Agent is exactly `open-trestle/1`.

Requests remain bounded nonstreaming Chat POSTs with `stream:false`, existing
sanitized user content, trusted instructions and output cap. No OpenRouter
routing body, endpoint substitution, retry or fallback is introduced.
Go-only `message.reasoning_content` is validated then discarded, never promoted
to candidate output, audit content or a separate reasoning artifact. Only
assistant content reaches the existing candidate parser.

Known native `prompt_tokens`/`completion_tokens` remain bounded provider-reported
counts. Optional total must equal their overflow-safe sum; absent total is derived
from that known pair. Missing/null whole usage stays unknown, never free. Partial
or malformed native counts refuse. Only native cached_tokens details can supply
the neutral cached subset. Billed `opencode.tokens.input` excludes cache reads
and writes; billed output includes reasoning. Those are a separate family:
never equate billed input with prompt count, add cache reads to prompt count or
invent cache_read <= prompt_tokens. Validate bounded billed counters then discard
them rather than manufacture neutral counts.

Present `opencode` billing is closed: `billing_source` exactly `go`, required
finite nonnegative `list_cost` and `allowance`, closed billed counters, optional
`estimated` absent/false. Balance/free/BYOK/go-plus and estimated billing refuse.
`usage.cost` may be absent/null or numeric zero for this disabled-Extra-Usage
branch. A positive charge is a contradictory post-effect result and refuses;
that refusal cannot undo the charge. Zero cost/allowance is not free-route or
future balance authority. Unknown/malformed extensions reject, not silently zero.

Existing record-fixed two-rate cost reconciliation is registry accounting, not
Console bill reconciliation or a technical account-spend cap. Conservative
operator-reviewed prices and pessimistic reservation must account for selected
model/cache-tier terms; subscription pricing does not justify zero rates. If no
defensible conservative reservation is possible, refuse activation. Genuine
absent usage retains explicit unknown outcome and its reservation under the
existing handler; it must not discard valid native counts. Late budget refusal
cannot reverse a service effect.

## Qualification limits

Model catalog metadata does not approve privacy or entitlement, activate routes
or discover dispatch endpoints. Ordinary local-only composition still refuses
brokered routes. Setup Go authority, separate direct verification eligibility,
protected configuration admission, scanner proof, publication authority and live
qualification are independent requirements. No setup or activation command is
introduced by this document. OpenCode pay-as-you-go and Ollama Cloud remain
separate named conformance work.

Official-source basis: the retained public OpenCode Go, Console inference and
harness documentation retrieved October 30, 2026. Current account/model terms
must be reviewed again before activation:

- https://opencode.ai/v2/docs/console/go
- https://opencode.ai/v2/docs/console/api/inference
- https://opencode.ai/v2/docs/console/harnesses
