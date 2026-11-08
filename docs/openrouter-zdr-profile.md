# OpenRouter ZDR Chat profile

Runtime policy version 3 adds the closed `openrouter_zdr_chat_v1` request profile.
Versions 1 and 2 and their accepted identity preimages remain unchanged. This
profile is not generic permission to use brokered providers.

## Required authority

The connection must use `openai_chat_completions`, bearer credentials and the
exact base `https://openrouter.ai/api/v1`. Its single approved inventory record
must declare provider `openrouter`, zone `brokered_remote` and disabled content
logging. `brokered_route_authority` binds that record identity, evidence manifest
digest, account policy identity, tenant, logical repository, provider routing slug
and canonical UTC `valid_from`/`valid_until`. The interval includes its start and
excludes its end. The credential reference is bound through the connection's
derived credential identity, never through the secret value.

These fields must match a typed `openrouter_privacy` section in the immutable
evidence manifest. The runtime checks the declaration and its exact linkage, not
provider conduct, account ownership or ZDR eligibility. A digest alone is not
privacy approval. Before enabling
the route, verify that the actual credential belongs to the approved account and
that the evidence covers every endpoint the selected provider slug can match.
A slug may cover a family or variant; a discovery tag is not that approval.

## Dispatch contract

Every Chat request sets the same provider controls:

```json
{"provider":{"zdr":true,"only":["<approved-slug>"],"order":["<approved-slug>"],"allow_fallbacks":false,"require_parameters":true}}
```

The existing exact model selector, output bound, host instructions, sanitized
context, strict response parser, usage reconciliation and bounded transport
still apply. There is no arbitrary request overlay, tool execution, model array,
provider fallback or implicit credential downgrade.

The common catalog rejects stale declarations before resolving credential
providers. Each dispatch rechecks freshness, the full route and approved record,
and the trusted handler's opaque repository, run and request attestation before
retrieving a key or making HTTP calls. One catalog can serve successive runs in
its declared repository; another repository is not admitted. Expiry after
preparation still refuses dispatch. A raw request or receipt alone has no
remote dispatch authority.

## Reachability and limits

Two compositions reach this profile. The opt-in GitHub advisory daemon consumes
protected inventory and runtime policy as explicit operator inputs. The direct
foreground `trestle local-git model-review --egress policy-approved` path also
admits it through the same catalog and sanitized handlers, while
`--egress local-only` still rejects it. `trestle setup bootstrap init --provider
openrouter-zdr` writes that protected configuration and this witness from explicit
operator declarations; see [remote model review](remote-model-review.md). A setup
approval receipt is a separate readiness artifact; the daemon does not consume
it as dispatch authority. Publication remains separately authorized.

OpenRouter documents legal CSAM handling exceptions to ZDR. ZDR is not a claim
that no processing, exceptional retention or other account controls exist.
Review current provider terms and account controls before sending source.

Offline synthetic transports establish development behavior only. They do not
qualify an actual OpenRouter account, selected upstream, model quality, live
usage/cancellation semantics, Go, Ollama Cloud or any other named service. Live
inference, credentials, private source egress and charges require separate
explicit authorization.


## Typed privacy witness

The reserved `openrouter_privacy` member uses local contract
`open-trestle/openrouter-privacy-witness`, schema version 2. It binds the full
route tuple and effective model selector (version when nonempty, otherwise model
ID), exact endpoint/profile/protocol/bearer mode, routing slug and
`all_slug_matches` scope, tenant/repository, credential-reference identity
and exact policy validity interval. The scope covers every endpoint matched by
the slug, including its Safety Retention variants. It is not a physical endpoint
pin.

A schema version 1 witness, or one with the earlier `all_zdr_eligible_matches`
scope or account-policy version 1, is not upgraded or reported separately: it is
treated exactly like a missing witness, so the named profile refuses at its next
validation. Re-record the witness at version 2 and approve the renewed
configuration identities.

Four fixed evidence objects are required: upstream model/slug retention and
no-training evidence, broker retention/exception evidence, slug-coverage evidence
and a separate account/workspace review reference. Each contains `url`,
`retrieved_at` and nonzero lowercase `content_sha256`. Account review must cover
the actual account settings and key ownership. A public privacy page alone is
not account review. Source substance remains a human obligation; the parser does
not fetch URLs or prove that an artifact supports a claim. Roles may reference
the same artifact, so structural acceptance is not proof of independent review.

The account requires `safety_retention_scope` exactly
`effective_account_and_guardrails`, plus `effective_safety_retention_google` and
`effective_safety_retention_other` both exactly `denied`. Review must establish
that the actual key's effective account and applicable guardrails deny Safety
Retention for both groups throughout the reviewed interval. Missing, null,
allowed, unknown or account-only declarations refuse. These are local evidence
fields, not request parameters and not a live inspection of provider settings.

OpenRouter documents that request `provider.zdr:true` follows the effective
account/guardrail Safety Retention choice. Self-serve accounts with no saved
choice may allow it. The Guardrails API fields
`allow_safety_retention_google` and `allow_safety_retention_other` are not Chat
request fields. A successful request or a ZDR label alone is not evidence of the
required denial. Recheck the [current ZDR documentation](https://openrouter.ai/docs/guides/features/zdr)
and actual key/account settings before approval. Provider conduct and later
settings drift remain outside local structural validation.

All declared training and content logging states are `disabled`. BYOK, private
endpoints, tools and plugins are `excluded`. Upstream, broker and repository
approval must explicitly accept
`openrouter_zdr_with_documented_exceptions`, not unconditional non-retention.
This profile cannot satisfy a separate unconditional-retention requirement.
The current generic policy has no such separate requirement field; protected
operator review must not use logging-disabled as a substitute for it.

The witness has closed, required, non-null fields, including `model_version`
(which may be empty). Labels and slugs are at most 256 UTF-8 bytes; evidence URLs
are HTTPS, at most 2048 bytes, with a host and no user information, query or
fragment. Existing 1 MiB manifest and 64-route/8 MiB inventory limits remain.
Timestamps use canonical UTC RFC3339Nano. Every source retrieval is no later
than review, review is no later than `valid_from`, and `valid_from` is strictly
before `valid_until`. No default TTL or grace is added.

Only brokered OpenRouter candidates are considered for projection. Their entire
JSON manifest is scanned for duplicate/noncanonical keys and trailing values
before the reserved member is located. Other top-level members remain
semantically opaque but are subject to that scan. Missing, malformed or
non-object manifests retain generic inventory behavior; the named profile
refuses them. Generic v1/v2 opaque manifests and identity preimages are unchanged.
The common catalog validates currentness before resolving any credential
provider. Dispatch uses the same exact window before key retrieval and HTTP.


### Synthetic format example

This complete witness is an offline format example, not evidence about an actual
provider or account. Replace its route, source artifacts, credential-reference,
scope and reviewed window through protected operator review. Recompute the
account identity and the enclosing manifest/record/inventory/policy identities;
do not copy this fixture as a live approval.

```json
{
  "openrouter_privacy": {
    "contract": "open-trestle/openrouter-privacy-witness",
    "schema_version": 2,
    "route": {
      "zone": "brokered_remote",
      "provider_id": "openrouter",
      "adapter_id": "adapter-a",
      "connection_id": "primary/openrouter",
      "model_id": "vendor/model",
      "model_version": "fixture-version",
      "effective_selector": "fixture-version"
    },
    "endpoint": "https://openrouter.ai/api/v1",
    "request_profile": "openrouter_zdr_chat_v1",
    "protocol": "openai_chat_completions",
    "credential_mode": "bearer",
    "provider_slug": "fixture-upstream/region",
    "provider_slug_scope": "all_slug_matches",
    "upstream": {
      "retention_contract": "openrouter_zdr_with_documented_exceptions",
      "training": "disabled",
      "evidence": {
        "url": "https://evidence.fixture.invalid/upstream-model-slug-scope",
        "retrieved_at": "2026-09-30T00:00:00Z",
        "content_sha256": "e6b11692df5754cdf6d2c71791df04ea1c3cc6483d887ce7ba5c4f491caee63a"
      }
    },
    "broker": {
      "retention_contract": "openrouter_zdr_with_documented_exceptions",
      "evidence": {
        "url": "https://evidence.fixture.invalid/broker-retention-exceptions",
        "retrieved_at": "2026-09-30T00:00:00Z",
        "content_sha256": "4df85e58e5206a5a1ae7fc7d672ca80a270bc9c3b4332fa14a122201c4aae40b"
      }
    },
    "slug_evidence": {
      "url": "https://evidence.fixture.invalid/all-zdr-eligible-slug-matches",
      "retrieved_at": "2026-09-30T00:00:00Z",
      "content_sha256": "b882ee7acf551e591577a5b1db2236d1ec202f2c2a9b5f83501cdf29b7812878"
    },
    "account": {
      "authority_label": "synthetic account review, not live approval",
      "credential_reference_identity": "99d4435c2238d0cdf988ace246b7f44305262a35bd1c45ebe0559ed0d0286e4c",
      "content_logging": "disabled",
      "training": "disabled",
      "safety_retention_scope": "effective_account_and_guardrails",
      "effective_safety_retention_google": "denied",
      "effective_safety_retention_other": "denied",
      "review_evidence": {
        "url": "https://account-review.fixture.invalid/reviews/synthetic-account",
        "retrieved_at": "2026-09-30T00:00:00Z",
        "content_sha256": "d0e58a62d765bce7ccb529fe9a7fbc6a9344bca732e511dec2289686c07b8d2d"
      }
    },
    "tenant_id": "tenant-a",
    "repository_id": "repository-a",
    "accepted_retention_contract": "openrouter_zdr_with_documented_exceptions",
    "reviewed_at": "2026-09-30T00:00:00Z",
    "valid_from": "2026-10-01T00:00:00Z",
    "valid_until": "2026-11-01T00:00:00Z",
    "byok": "excluded",
    "private_endpoints": "excluded",
    "tools": "excluded",
    "plugins": "excluded"
  }
}
```

### Account identity calculation

`account_policy_identity` is SHA-256 lowercase hexadecimal of `encoding/json.Marshal`
of the fixed Go struct below, without a trailing newline. The wrapper contract
is `open-trestle/openrouter-account-policy`, version 2. Account field order is
`authority_label`, `credential_reference_identity`, `content_logging`, `training`,
`safety_retention_scope`, `effective_safety_retention_google`,
`effective_safety_retention_other`, `review_evidence`. Field order, Go JSON string
escaping and already-canonical UTC timestamp strings matter. The account
subsection includes its review evidence, so changing that evidence changes the
account identity too. A nonzero arbitrary digest is not accepted.

Save this standard-library-only calculation as `account-identity.go` outside the
product source tree, then run `go run account-identity.go manifest.json` against
the protected non-secret manifest. It performs no network or credential lookup.
It only calculates the candidate value; it does not validate the witness, prove
account ownership or grant approval. Run `trestle config validate --route-inventory inventory.json --runtime-policy policy.json`
against the complete inventory/policy after authoring it. Do not treat this
recipe's permissive decoding as the product validator.

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
	AuthorityLabel                 string `json:"authority_label"`
	CredentialReferenceIdentity    string `json:"credential_reference_identity"`
	ContentLogging                 string `json:"content_logging"`
	Training                       string `json:"training"`
	SafetyRetentionScope           string `json:"safety_retention_scope"`
	EffectiveSafetyRetentionGoogle string `json:"effective_safety_retention_google"`
	EffectiveSafetyRetentionOther  string `json:"effective_safety_retention_other"`
	ReviewEvidence                 source `json:"review_evidence"`
}

func main() {
	if len(os.Args) != 2 {
		panic("usage: go run account-identity.go manifest.json")
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
		} `json:"openrouter_privacy"`
	}
	if err := json.Unmarshal(encoded, &manifest); err != nil {
		panic(err)
	}
	preimage, err := json.Marshal(struct {
		Contract string  `json:"contract"`
		Version  int     `json:"version"`
		Account  account `json:"account"`
	}{"open-trestle/openrouter-account-policy", 2, manifest.Privacy.Account})
	if err != nil {
		panic(err)
	}
	digest := sha256.Sum256(preimage)
	fmt.Println(hex.EncodeToString(digest[:]))
}
```

The account `credential_reference_identity` is SHA-256 of
`open-trestle/provider-credential-environment/` followed by the exact environment
variable name, not its value. Changing the reference makes the witness,
manifest, record, inventory and policy environment-specific. Replacing a real
key behind an unchanged reference does not prove account continuity.

### Compatibility

The existing runtime-policy v3 schema bytes stay unchanged. Named OpenRouter
consumption now requires privacy witness schema version 2 and account-policy
identity version 2. Retained v1 witness bytes and account identities do not gain
Safety Retention authority and fail named validation, even if they previously
passed. Generic v1/v2 opaque manifest handling and accepted identity preimages
are unchanged. There is no automatic rewrite or receipt upgrade. Obtain fresh
reviewed effective settings and all-slug-match evidence, author a v2 witness,
then recompute the account, manifest, record, inventory and policy identities.
Renewed witness bytes require fresh exact setup approval. The daemon still consumes protected
configuration, not setup receipts.

The binding uses the existing transitive chain: policy record identity and
evidence digest -> immutable manifest -> typed witness, plus the derived account
identity. There is no second approval list, mutable registry or self-hash.
