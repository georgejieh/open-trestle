package runtimecatalog

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

func TestResolveLocalGenerationRoutePair(t *testing.T) {
	inventory, err := runtimeconfig.NewRouteInventory(context.Background(), localPairDefinitions(t))
	if err != nil {
		t.Fatal(err)
	}
	policy := localPairPolicy(t, inventory, true, []string{"adapter-b"}, "distinct_provider", nil)
	pair, err := ResolveLocalGenerationRoutePair(policy, inventory)
	if err != nil {
		t.Fatal(err)
	}
	if pair.Validate() != nil || pair.GenerationRecordIdentity() == pair.VerificationRecordIdentity() || pair.PolicyIdentity() != policy.Identity() || pair.InventoryIdentity() != inventory.Identity() {
		t.Fatal("invalid exact route pair")
	}
	records := map[string]string{}
	for _, candidate := range inventory.Candidates() {
		record := candidate.ResolvedRecord().RouteRegistryRecord()
		records[record.RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference().AdapterID()] = record.Identity()
	}
	if pair.GenerationRecordIdentity() != records["adapter-a"] || pair.VerificationRecordIdentity() != records["adapter-b"] {
		t.Fatal("wrong record selected")
	}
	reversed := append([]runtimeconfig.RouteDefinition(nil), localPairDefinitions(t)...)
	reversed[0], reversed[1] = reversed[1], reversed[0]
	reordered, err := runtimeconfig.NewRouteInventory(context.Background(), reversed)
	if err != nil {
		t.Fatal(err)
	}
	second := localPairPolicy(t, reordered, true, []string{"adapter-b"}, "distinct_provider", nil)
	again, err := ResolveLocalGenerationRoutePair(second, reordered)
	if err != nil || again.Identity() != pair.Identity() {
		t.Fatalf("reordering changed pair: %v", err)
	}
}

func localPairDefinitions(t *testing.T) []runtimeconfig.RouteDefinition {
	t.Helper()
	capabilities, _ := provider.NewModelCapabilities(128000, 8192, []provider.ModelFeature{provider.ModelFeatureStructuredOutput})
	price, _ := provider.NewRoutePricing(1000000, 1000000)
	definitions := make([]runtimeconfig.RouteDefinition, 2)
	for i, name := range []string{"a", "b"} {
		route, err := provider.NewRouteReference(provider.ProviderZoneLocal, "provider-"+name, "adapter-"+name, "connection-"+name, "model-"+name, "1")
		if err != nil {
			t.Fatal(err)
		}
		definitions[i] = runtimeconfig.RouteDefinition{Route: route, Capabilities: capabilities, ContentLogging: provider.ContentLoggingDisabled, Pricing: price, Quality: provider.RouteQualityTier3, RegistryRevision: 7, RegistryStatus: provider.RouteRegistryApproved, EvidenceManifest: []byte(`{"fixture":"local review route"}`), OperationalRevision: 9, Health: provider.RouteHealthHealthy, Quota: provider.RouteQuotaAvailable, PerformanceRevision: 11, P95LatencyMilliseconds: 2500, LatencySampleCount: 100}
	}
	return definitions
}

func localPairPolicy(t *testing.T, inventory runtimeconfig.RouteInventory, pin bool, preferred []string, independence string, change func(map[string]any), allowInvalid ...bool) runtimeconfig.RuntimePolicy {
	t.Helper()
	records := map[string]string{}
	for _, candidate := range inventory.Candidates() {
		record := candidate.ResolvedRecord().RouteRegistryRecord()
		reference := record.RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference()
		if _, exists := records[reference.AdapterID()]; !exists {
			records[reference.AdapterID()] = record.Identity()
		}
	}
	pinID := ""
	if pin {
		pinID = records["adapter-a"]
	}
	preferenceIDs := make([]string, len(preferred))
	for i, adapter := range preferred {
		preferenceIDs[i] = records[adapter]
	}
	document := map[string]any{
		"schema_version": 2, "verification_route_record_identity": records["adapter-b"], "inventory_identity": inventory.Identity(), "review_policy_identity": strings.Repeat("e", 64),
		"min_context_tokens": 32000, "min_output_tokens": 4096, "required_features": []string{"structured_output"},
		"classification": "confidential", "allowed_zones": []string{"local"}, "content_logging_allowed": false,
		"estimated_input_tokens": 1000, "max_output_tokens": 4096, "max_cost_micro_usd": 1000000,
		"pinned_route_record_identity": pinID, "preferred_route_record_identities": preferenceIDs,
		"verification_independence": independence, "publication_minimum_severity": "medium", "publication_max_inline_findings": 20,
		"publication_minimum_independence": "distinct_provider", "publication_block_on_inconclusive": true,
		"connections": []map[string]string{{"implementation": "openai_responses", "adapter_id": "adapter-a", "endpoint": "http://127.0.0.1:11434/v1", "credential_environment": "OPEN_TRESTLE_PROVIDER_FIXTURE_A"}, {"implementation": "openai_responses", "adapter_id": "adapter-b", "endpoint": "http://127.0.0.1:11435/v1", "credential_environment": "OPEN_TRESTLE_PROVIDER_FIXTURE_B"}},
	}
	if change != nil {
		change(document)
	}
	encoded, _ := json.Marshal(document)
	policy, err := runtimeconfig.DecodeRuntimePolicy(context.Background(), bytes.NewReader(encoded), inventory)
	if err != nil {
		if len(allowInvalid) > 0 && allowInvalid[0] {
			return runtimeconfig.RuntimePolicy{}
		}
		t.Fatalf("invalid test policy: %v", err)
	}
	return policy
}

func TestResolveLocalGenerationRoutePairHonorsIndependenceLevel(t *testing.T) {
	defs := localPairDefinitions(t)
	defs[1].Route, _ = provider.NewRouteReference(provider.ProviderZoneLocal, "provider-a", "adapter-b", "connection-b", "model-b", "1")
	inventory, err := runtimeconfig.NewRouteInventory(context.Background(), defs)
	if err != nil {
		t.Fatal(err)
	}
	policy := localPairPolicy(t, inventory, true, []string{"adapter-b"}, "distinct_model", nil)
	if _, err := ResolveLocalGenerationRoutePair(policy, inventory); err != nil {
		t.Fatalf("distinct model rejected: %v", err)
	}
	defs[1].Route, _ = provider.NewRouteReference(provider.ProviderZoneLocal, "provider-a", "adapter-b", "connection-b", "model-a", "1")
	inventory, err = runtimeconfig.NewRouteInventory(context.Background(), defs)
	if err != nil {
		t.Fatal(err)
	}
	policy = localPairPolicy(t, inventory, true, []string{"adapter-b"}, "distinct_route", nil)
	if _, err := ResolveLocalGenerationRoutePair(policy, inventory); err != nil {
		t.Fatalf("distinct effective route rejected: %v", err)
	}
}

func TestResolveLocalGenerationRoutePairFailsClosed(t *testing.T) {
	cases := []struct {
		name         string
		mutate       func(*testing.T, *[]runtimeconfig.RouteDefinition)
		pin          bool
		preferred    []string
		level        string
		policyChange func(map[string]any)
	}{
		{name: "missing pin", preferred: []string{"adapter-b"}, level: "distinct_provider"},
		{name: "missing verifier", pin: true, level: "distinct_provider", policyChange: func(doc map[string]any) { delete(doc, "verification_route_record_identity") }},
		{name: "unknown verifier grant", pin: true, preferred: []string{"adapter-b", "adapter-c"}, level: "distinct_provider", mutate: func(t *testing.T, d *[]runtimeconfig.RouteDefinition) {
			extra := (*d)[1]
			extra.Route, _ = provider.NewRouteReference(provider.ProviderZoneLocal, "provider-c", "adapter-c", "connection-c", "model-c", "1")
			*d = append(*d, extra)
		}, policyChange: func(doc map[string]any) {
			connections := doc["connections"].([]map[string]string)
			doc["connections"] = append(connections, map[string]string{"implementation": "openai_responses", "adapter_id": "adapter-c", "endpoint": "http://127.0.0.1:11436/v1", "credential_environment": "OPEN_TRESTLE_PROVIDER_FIXTURE_C"})
			doc["verification_route_record_identity"] = strings.Repeat("b", 64)
		}},
		{name: "duplicate effective route", pin: true, preferred: []string{"adapter-b"}, level: "distinct_provider", mutate: func(t *testing.T, d *[]runtimeconfig.RouteDefinition) {
			(*d)[1].Route = (*d)[0].Route
			(*d)[1].EvidenceManifest = []byte(`{"fixture":"other record"}`)
		}},
		{name: "same model", pin: true, preferred: []string{"adapter-b"}, level: "distinct_model", mutate: func(t *testing.T, d *[]runtimeconfig.RouteDefinition) {
			(*d)[1].Route, _ = provider.NewRouteReference(provider.ProviderZoneLocal, "provider-a", "adapter-b", "connection-b", "model-a", "1")
		}},
		{name: "same provider", pin: true, preferred: []string{"adapter-b"}, level: "distinct_provider", mutate: func(t *testing.T, d *[]runtimeconfig.RouteDefinition) {
			(*d)[1].Route, _ = provider.NewRouteReference(provider.ProviderZoneLocal, "provider-a", "adapter-b", "connection-b", "model-b", "1")
		}},
		{name: "remote zone", pin: true, preferred: []string{"adapter-b"}, level: "distinct_provider", mutate: func(t *testing.T, d *[]runtimeconfig.RouteDefinition) {
			(*d)[1].Route, _ = provider.NewRouteReference(provider.ProviderZonePrivateRemote, "provider-b", "adapter-b", "connection-b", "model-b", "1")
		}, policyChange: func(doc map[string]any) {
			doc["allowed_zones"] = []string{"local", "private_remote"}
			connections := doc["connections"].([]map[string]string)
			connections[1]["endpoint"] = "https://provider-b.invalid"
		}},
		{name: "logging enabled", pin: true, preferred: []string{"adapter-b"}, level: "distinct_provider", mutate: func(t *testing.T, d *[]runtimeconfig.RouteDefinition) {
			(*d)[1].ContentLogging = provider.ContentLoggingEnabled
		}, policyChange: func(doc map[string]any) { doc["content_logging_allowed"] = true }},
		{name: "unapproved", pin: true, preferred: []string{"adapter-b"}, level: "distinct_provider", mutate: func(t *testing.T, d *[]runtimeconfig.RouteDefinition) {
			(*d)[1].RegistryStatus = provider.RouteRegistryPending
		}},
		{name: "unhealthy", pin: true, preferred: []string{"adapter-b"}, level: "distinct_provider", mutate: func(t *testing.T, d *[]runtimeconfig.RouteDefinition) { (*d)[1].Health = provider.RouteHealthUnhealthy }},
		{name: "quota unknown", pin: true, preferred: []string{"adapter-b"}, level: "distinct_provider", mutate: func(t *testing.T, d *[]runtimeconfig.RouteDefinition) { (*d)[1].Quota = provider.RouteQuotaUnknown }},
		{name: "capacity", pin: true, preferred: []string{"adapter-b"}, level: "distinct_provider", mutate: func(t *testing.T, d *[]runtimeconfig.RouteDefinition) {
			(*d)[1].Capabilities, _ = provider.NewModelCapabilities(16000, 8192, []provider.ModelFeature{provider.ModelFeatureStructuredOutput})
		}},
		{name: "output", pin: true, preferred: []string{"adapter-b"}, level: "distinct_provider", mutate: func(t *testing.T, d *[]runtimeconfig.RouteDefinition) {
			(*d)[1].Capabilities, _ = provider.NewModelCapabilities(128000, 1000, []provider.ModelFeature{provider.ModelFeatureStructuredOutput})
		}},
		{name: "features", pin: true, preferred: []string{"adapter-b"}, level: "distinct_provider", mutate: func(t *testing.T, d *[]runtimeconfig.RouteDefinition) {
			(*d)[1].Capabilities, _ = provider.NewModelCapabilities(128000, 8192, nil)
		}},
		{name: "cost", pin: true, preferred: []string{"adapter-b"}, level: "distinct_provider", mutate: func(t *testing.T, d *[]runtimeconfig.RouteDefinition) {
			(*d)[1].Pricing, _ = provider.NewRoutePricing(1000000000, 1000000000)
		}},
		{name: "unknown price", pin: true, preferred: []string{"adapter-b"}, level: "distinct_provider", mutate: func(t *testing.T, d *[]runtimeconfig.RouteDefinition) {
			(*d)[1].Pricing = provider.NewUnknownRoutePricing()
		}},
		{name: "same effective reference as verifier grant", pin: true, preferred: []string{"adapter-b"}, level: "distinct_route", policyChange: func(doc map[string]any) {
			doc["verification_route_record_identity"] = doc["pinned_route_record_identity"]
		}},
		{name: "logging allowed by policy", pin: true, preferred: []string{"adapter-b"}, level: "distinct_provider", policyChange: func(doc map[string]any) { doc["content_logging_allowed"] = true }},
		{name: "remote endpoint", pin: true, preferred: []string{"adapter-b"}, level: "distinct_provider", policyChange: func(doc map[string]any) {
			connections := doc["connections"].([]map[string]string)
			connections[1]["endpoint"] = "https://provider-b.invalid"
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defs := localPairDefinitions(t)
			if tc.mutate != nil {
				tc.mutate(t, &defs)
			}
			inventory, err := runtimeconfig.NewRouteInventory(context.Background(), defs)
			if err != nil {
				t.Fatal(err)
			}
			// Some invalid connections cannot pass the runtime policy decoder: that is also fail-closed.
			policy := localPairPolicy(t, inventory, tc.pin, tc.preferred, tc.level, tc.policyChange, tc.name == "duplicate effective route" || tc.name == "remote endpoint" || tc.name == "unknown verifier grant" || tc.name == "missing verifier" || tc.name == "same effective reference as verifier grant")
			if _, err := ResolveLocalGenerationRoutePair(policy, inventory); err == nil {
				t.Fatal("accepted ineligible pair")
			}
		})
	}
	inventory, err := runtimeconfig.NewRouteInventory(context.Background(), localPairDefinitions(t))
	if err != nil {
		t.Fatal(err)
	}
	policy := localPairPolicy(t, inventory, true, []string{"adapter-b"}, "distinct_provider", nil)
	other := localPairDefinitions(t)
	other[1].Health = provider.RouteHealthUnhealthy
	stale, err := runtimeconfig.NewRouteInventory(context.Background(), other)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveLocalGenerationRoutePair(policy, stale); err == nil || stale.Identity() == inventory.Identity() {
		t.Fatal("accepted stale policy/inventory")
	}
}

func TestResolveLocalGenerationRoutePairRequiresExplicitVerifierGrant(t *testing.T) {
	definitions := localPairDefinitions(t)
	extra := definitions[1]
	extra.Route, _ = provider.NewRouteReference(provider.ProviderZoneLocal, "provider-c", "adapter-c", "connection-c", "model-c", "1")
	definitions = append(definitions, extra)
	inventory, err := runtimeconfig.NewRouteInventory(context.Background(), definitions)
	if err != nil {
		t.Fatal(err)
	}
	addConnection := func(doc map[string]any) {
		doc["connections"] = append(doc["connections"].([]map[string]string), map[string]string{"implementation": "openai_responses", "adapter_id": "adapter-c", "endpoint": "http://127.0.0.1:11436/v1", "credential_environment": "OPEN_TRESTLE_PROVIDER_FIXTURE_C"})
	}
	old := localPairPolicy(t, inventory, true, []string{"adapter-b"}, "distinct_provider", func(doc map[string]any) {
		doc["schema_version"] = 1
		delete(doc, "verification_route_record_identity")
		addConnection(doc)
	})
	if _, err := ResolveLocalGenerationRoutePair(old, inventory); err == nil {
		t.Fatal("v1 preference incorrectly granted verifier route")
	}
	for _, preferences := range [][]string{nil, {"adapter-c"}} {
		current := localPairPolicy(t, inventory, true, preferences, "distinct_provider", addConnection)
		pair, err := ResolveLocalGenerationRoutePair(current, inventory)
		if err != nil {
			t.Fatalf("v2 grant ignored when preferences=%v: %v", preferences, err)
		}
		if pair.VerificationRecordIdentity() == pair.GenerationRecordIdentity() {
			t.Fatal("not the exact verifier record")
		}
	}
}
