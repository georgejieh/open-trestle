package runtimeconfig

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/provider"
)

// Every value below is a synthetic offline fixture, not an observation of
// OpenRouter or of any account.

func observedWitnessFixture(slugs []string, source string, observed bool) map[string]any {
	witness := map[string]any{
		"contract": "open-trestle/openrouter-privacy-witness", "schema_version": 3,
		"route":    map[string]any{"zone": "brokered_remote", "provider_id": "openrouter", "adapter_id": "adapter-a", "connection_id": "primary/openrouter", "model_id": "vendor/model", "model_version": "", "effective_selector": "vendor/model"},
		"endpoint": "https://openrouter.ai/api/v1", "request_profile": "openrouter_zdr_chat_v2", "protocol": "openai_chat_completions", "credential_mode": "bearer",
		"credential_reference_identity": credentialEnvironmentIdentity("OPEN_TRESTLE_PROVIDER_OPENROUTER"),
		"tenant_id":                     "tenant-a", "repository_id": "repository-a", "zero_data_retention": "required_per_request",
		"provider_slugs": slugs, "provider_slug_source": source, "observation": nil,
	}
	if observed {
		endpoints := []any{}
		for _, slug := range slugs {
			endpoints = append(endpoints, map[string]any{"tag": slug, "provider_name": "Fixture " + slug, "context_length": 200000, "max_prompt_tokens": 0, "max_completion_tokens": 64000, "prompt_micro_usd_per_million_tokens": 3000000, "completion_micro_usd_per_million_tokens": 15000000, "structured_outputs": true})
		}
		witness["observation"] = map[string]any{
			"authority_label": "as reported by OpenRouter's API at 2026-11-10T21:00:00Z; not reviewed or verified by the operator",
			"retrieved_at":    "2026-11-10T21:00:00Z",
			"sources": []any{
				map[string]any{"url": OpenRouterZDREndpointsURL, "retrieved_at": "2026-11-10T21:00:00Z", "content_sha256": strings.Repeat("ab", 32)},
				map[string]any{"url": OpenRouterModelsURL, "retrieved_at": "2026-11-10T21:00:01Z", "content_sha256": strings.Repeat("cd", 32)},
			},
			"zdr_endpoints": endpoints, "safety_retention_endpoints_excluded": []string{"fixture-safety"}, "output_limit_endpoints_excluded": []any{},
		}
		if source == "openrouter_api" && len(slugs) != 0 {
			witness["observation"].(map[string]any)["output_limit_endpoints_excluded"] = []any{map[string]any{"tag": "fixture-small/fp4", "max_completion_tokens": 4096}}
		}
	}
	return witness
}

func observedPolicyDocument(t *testing.T, witness map[string]any) (RouteInventory, map[string]any) {
	t.Helper()
	generation := routeDefinition(t, "vendor/model")
	var err error
	generation.Route, err = provider.NewRouteReference(provider.ProviderZoneBrokeredRemote, "openrouter", "adapter-a", "primary/openrouter", "vendor/model", "")
	if err != nil {
		t.Fatal(err)
	}
	generation.EvidenceManifest, err = json.Marshal(map[string]any{"openrouter_privacy": witness})
	if err != nil {
		t.Fatal(err)
	}
	verifier := routeDefinition(t, "verifier")
	verifier.Route, err = provider.NewRouteReference(provider.ProviderZonePrivateRemote, "direct", "verifier", "primary/direct", "verifier", "")
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := NewRouteInventory(context.Background(), []RouteDefinition{generation, verifier})
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if json.Unmarshal(runtimePolicyDocument(t, inventory), &wire) != nil {
		t.Fatal("fixture policy")
	}
	var generationRecord, verifierRecord, evidenceDigest string
	for _, observed := range inventory.Candidates() {
		record := observed.ResolvedRecord().RouteRegistryRecord()
		if record.RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference().AdapterID() == "adapter-a" {
			generationRecord, evidenceDigest = record.Identity(), record.EvidenceManifestDigest()
		} else {
			verifierRecord = record.Identity()
		}
	}
	wire["schema_version"] = 8
	wire["allowed_zones"] = []string{"brokered_remote", "private_remote"}
	wire["pinned_route_record_identity"] = generationRecord
	wire["preferred_route_record_identities"] = []string{}
	wire["verification_route_record_identity"] = verifierRecord
	wire["connections"] = []any{
		map[string]any{"implementation": "openai_chat_completions", "adapter_id": "adapter-a", "endpoint": "https://openrouter.ai/api/v1", "credential_environment": "OPEN_TRESTLE_PROVIDER_OPENROUTER", "request_profile": "openrouter_zdr_chat_v2", "brokered_route_authority": map[string]any{
			"route_record_identity": generationRecord, "evidence_manifest_digest": evidenceDigest, "tenant_id": "tenant-a", "repository_id": "repository-a", "provider_slugs": witness["provider_slugs"],
		}},
		map[string]any{"implementation": "openai_responses", "adapter_id": "verifier", "endpoint": "https://direct.example/v1", "credential_environment": "OPEN_TRESTLE_PROVIDER_DIRECT"},
	}
	return inventory, wire
}

func decodeObservedPolicy(t *testing.T, inventory RouteInventory, wire map[string]any) (RuntimePolicy, error) {
	t.Helper()
	encoded, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	return DecodeRuntimePolicy(context.Background(), bytes.NewReader(encoded), inventory)
}

func TestRuntimePolicyV8BindsObservedOpenRouterWitness(t *testing.T) {
	for _, form := range []struct {
		name     string
		slugs    []string
		source   string
		observed bool
	}{{"detected", []string{"fixture-a/fp8", "fixture-b"}, "openrouter_api", true}, {"operator slugs", []string{"fixture-a"}, "operator", false}, {"unpinned", []string{}, "none", false}, {"unpinned with observation", []string{}, "none", true}} {
		t.Run(form.name, func(t *testing.T) {
			witness := observedWitnessFixture(form.slugs, form.source, form.observed)
			if form.name == "unpinned with observation" {
				witness["observation"].(map[string]any)["zdr_endpoints"] = []any{}
			}
			inventory, wire := observedPolicyDocument(t, witness)
			policy, err := decodeObservedPolicy(t, inventory, wire)
			if err != nil {
				t.Fatalf("observed authority refused: %v", err)
			}
			var connection ProviderConnection
			for _, candidate := range policy.Connections() {
				if candidate.AdapterID() == "adapter-a" {
					connection = candidate
				}
			}
			authority := connection.BrokeredAuthority()
			if !authority.Observed() || !connection.RequiresZeroDataRetention() || strings.Join(authority.ProviderSlugs(), ",") != strings.Join(form.slugs, ",") || !authority.Current(authority.ValidUntil()) || !authority.ValidFrom().IsZero() {
				t.Fatalf("observed authority lost its form: %#v", authority)
			}
			fields, ok := inventory.OpenRouterObservedWitness(authority.RouteRecordIdentity())
			if !ok || fields.Observed != form.observed || fields.ProviderSlugSource != form.source || form.observed && (fields.ObservedAt.IsZero() || !strings.Contains(fields.AuthorityLabel, "as reported by OpenRouter's API")) {
				t.Fatalf("witness facts not readable: %#v %v", fields, ok)
			}
			if wantExcluded := form.name == "detected"; (fields.OutputLimitExcluded == 1) != wantExcluded {
				t.Fatalf("output-limit exclusions read back as %d", fields.OutputLimitExcluded)
			}
			if inventory.OpenRouterPrivacyCurrent(authority.RouteRecordIdentity(), authority.ValidFrom()) {
				t.Fatal("a version 3 witness was treated as a reviewed version 2 witness")
			}
		})
	}
}

func TestRuntimePolicyV8RefusesUnboundOrMixedForms(t *testing.T) {
	for _, name := range []string{"slug mismatch", "extra authority member", "reviewed member", "missing slugs", "null slugs", "wrong profile", "v3 version", "v1 profile", "tenant mismatch", "duplicate slug", "too many slugs", "credential mismatch", "api source without observation", "api slugs differ from endpoints", "operator source empty", "none source with slugs", "safety endpoint pinned", "unknown witness member", "observation missing member", "label without time", "wrong source url", "small output endpoint", "local structured output", "observation missing output exclusions", "output exclusion pinned", "output exclusion also safety excluded", "output exclusion allows a pinned limit", "output exclusion below a review", "duplicate output exclusion", "output exclusion with operator slugs", "output exclusion member unknown", "output exclusion as a tag"} {
		t.Run(name, func(t *testing.T) {
			witness := observedWitnessFixture([]string{"fixture-a", "fixture-b"}, "openrouter_api", true)
			observation := witness["observation"].(map[string]any)
			switch name {
			case "duplicate slug":
				witness["provider_slugs"] = []string{"fixture-a", "fixture-a"}
			case "too many slugs":
				many := []string{}
				for i := range MaxOpenRouterProviderSlugs + 1 {
					many = append(many, "fixture-"+strings.Repeat("x", i+1))
				}
				witness["provider_slugs"], witness["provider_slug_source"], witness["observation"] = many, "operator", nil
			case "credential mismatch":
				witness["credential_reference_identity"] = credentialEnvironmentIdentity("OPEN_TRESTLE_PROVIDER_OTHER")
			case "api source without observation":
				witness["observation"] = nil
			case "api slugs differ from endpoints":
				witness["provider_slugs"] = []string{"fixture-b", "fixture-a"}
			case "operator source empty":
				witness["provider_slugs"], witness["provider_slug_source"] = []string{}, "operator"
			case "none source with slugs":
				witness["provider_slug_source"] = "none"
			case "safety endpoint pinned":
				observation["safety_retention_endpoints_excluded"] = []string{"fixture-a"}
			case "unknown witness member":
				witness["tools"] = "excluded"
			case "observation missing member":
				delete(observation, "safety_retention_endpoints_excluded")
			case "label without time":
				observation["authority_label"] = "as reported by OpenRouter's API"
			case "wrong source url":
				observation["sources"].([]any)[1].(map[string]any)["url"] = "https://openrouter.ai/api/v1/models/vendor"
			case "small output endpoint":
				observation["zdr_endpoints"].([]any)[0].(map[string]any)["max_completion_tokens"] = 1024
			case "observation missing output exclusions":
				delete(observation, "output_limit_endpoints_excluded")
			case "output exclusion pinned":
				observation["output_limit_endpoints_excluded"] = []any{map[string]any{"tag": "fixture-a", "max_completion_tokens": 4096}}
			case "output exclusion also safety excluded":
				observation["output_limit_endpoints_excluded"] = []any{map[string]any{"tag": "fixture-safety", "max_completion_tokens": 4096}}
			case "output exclusion allows a pinned limit":
				observation["output_limit_endpoints_excluded"] = []any{map[string]any{"tag": "fixture-small/fp4", "max_completion_tokens": 64000}}
			case "output exclusion below a review":
				observation["output_limit_endpoints_excluded"] = []any{map[string]any{"tag": "fixture-small/fp4", "max_completion_tokens": 2048}}
			case "duplicate output exclusion":
				small := map[string]any{"tag": "fixture-small/fp4", "max_completion_tokens": 4096}
				observation["output_limit_endpoints_excluded"] = []any{small, small}
			case "output exclusion with operator slugs":
				witness["provider_slug_source"] = "operator"
			case "output exclusion member unknown":
				observation["output_limit_endpoints_excluded"] = []any{map[string]any{"tag": "fixture-small/fp4", "max_completion_tokens": 4096, "context_length": 8192}}
			case "output exclusion as a tag":
				observation["output_limit_endpoints_excluded"] = []string{"fixture-small/fp4"}
			}
			inventory, wire := observedPolicyDocument(t, witness)
			connection := wire["connections"].([]any)[0].(map[string]any)
			authority := connection["brokered_route_authority"].(map[string]any)
			switch name {
			case "slug mismatch":
				authority["provider_slugs"] = []string{"fixture-a"}
			case "extra authority member":
				authority["valid_from"] = "2026-10-01T00:00:00Z"
			case "reviewed member":
				delete(authority, "provider_slugs")
				authority["provider_slug"] = "fixture-a"
			case "missing slugs":
				delete(authority, "provider_slugs")
			case "null slugs":
				authority["provider_slugs"] = nil
			case "wrong profile":
				connection["request_profile"] = "openrouter_zdr_chat_v3"
			case "v3 version":
				wire["schema_version"] = 3
			case "v1 profile":
				connection["request_profile"] = "openrouter_zdr_chat_v1"
			case "tenant mismatch":
				authority["tenant_id"] = "tenant-b"
			case "local structured output":
				connection["local_structured_output"] = false
			}
			if policy, err := decodeObservedPolicy(t, inventory, wire); err == nil {
				t.Fatalf("%s admitted: %#v", name, policy.Connections())
			}
		})
	}
}

func TestReviewedBrokeredAuthorityKeepsItsIdentityPreimage(t *testing.T) {
	inventory, encoded := openRouterPolicyDocument(t)
	policy, err := DecodeRuntimePolicy(context.Background(), bytes.NewReader(encoded), inventory)
	if err != nil {
		t.Fatal(err)
	}
	for _, connection := range policy.Connections() {
		if connection.RequestProfile() != OpenRouterZDRChatProfile {
			continue
		}
		encodedWire, err := json.Marshal(connection.BrokeredAuthority().wire())
		if err != nil || bytes.Contains(encodedWire, []byte("provider_slugs")) || !bytes.Contains(encodedWire, []byte(`"provider_slug":"fixture-upstream/region"`)) || connection.BrokeredAuthority().Observed() || connection.BrokeredAuthority().ProviderSlugs() != nil {
			t.Fatalf("reviewed authority encoding changed: %s", encodedWire)
		}
	}
	var wire map[string]any
	json.Unmarshal(encoded, &wire)
	wire["connections"].([]any)[0].(map[string]any)["brokered_route_authority"].(map[string]any)["provider_slugs"] = []string{"fixture-upstream/region"}
	if _, err := decodeObservedPolicy(t, inventory, wire); err == nil {
		t.Fatal("a reviewed authority accepted an observed member")
	}
}

func TestObservedOpenRouterWitnessReportsReasoningOnlyWhenEveryPinnedEndpointAcceptsIt(t *testing.T) {
	for _, form := range []struct {
		name      string
		reasoning []any // per endpoint; nil leaves the member out
		want      bool
	}{{"every endpoint", []any{true, true}, true}, {"one endpoint without", []any{true, false}, false}, {"saved without the member", []any{nil, nil}, false}} {
		t.Run(form.name, func(t *testing.T) {
			witness := observedWitnessFixture([]string{"fixture-a/fp8", "fixture-b"}, "openrouter_api", true)
			for i, endpoint := range witness["observation"].(map[string]any)["zdr_endpoints"].([]any) {
				if form.reasoning[i] != nil {
					endpoint.(map[string]any)["reasoning"] = form.reasoning[i]
				}
			}
			inventory, wire := observedPolicyDocument(t, witness)
			if _, err := decodeObservedPolicy(t, inventory, wire); err != nil {
				t.Fatalf("policy refused: %v", err)
			}
			for _, observed := range inventory.Candidates() {
				record := observed.ResolvedRecord().RouteRegistryRecord()
				if record.RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference().AdapterID() != "adapter-a" {
					continue
				}
				fields, ok := inventory.OpenRouterObservedWitness(record.Identity())
				if !ok || fields.Reasoning != form.want {
					t.Fatalf("reasoning = %v (ok %v), want %v", fields.Reasoning, ok, form.want)
				}
			}
		})
	}
}
