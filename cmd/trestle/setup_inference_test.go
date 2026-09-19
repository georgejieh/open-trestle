package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/runtimeconfig"
)

func setupInferenceRuntime(t *testing.T, zone string, endpoints []string) (runtimeconfig.RouteInventory, runtimeconfig.RuntimePolicy) {
	t.Helper()
	routes := make([]map[string]any, len(endpoints))
	connections := make([]map[string]any, len(endpoints))
	for i, endpoint := range endpoints {
		suffix := string(rune('a' + i))
		routes[i] = map[string]any{"zone": zone, "provider_id": "provider-" + suffix, "adapter_id": "adapter-" + suffix, "connection_id": "connection-" + suffix, "model_id": "model-" + suffix, "model_version": "v1", "max_context_tokens": 64000, "max_output_tokens": 8192, "features": []string{"structured_output"}, "content_logging": "disabled", "pricing_known": true, "input_micro_usd_per_million_tokens": 0, "output_micro_usd_per_million_tokens": 0, "quality": "tier_3", "registry_revision": 1, "registry_status": "approved", "evidence_manifest_base64": base64.StdEncoding.EncodeToString([]byte(`{"approved":true}`)), "operational_revision": 1, "health": "healthy", "quota": "available", "performance_revision": 1, "latency_known": false, "p95_latency_milliseconds": 0, "latency_sample_count": 0}
		connections[i] = map[string]any{"implementation": "openai_responses", "adapter_id": "adapter-" + suffix, "endpoint": endpoint, "credential_environment": "OPEN_TRESTLE_PROVIDER_LOCAL_" + strings.ToUpper(suffix)}
	}
	inventoryBytes, _ := json.Marshal(map[string]any{"schema_version": 1, "routes": routes})
	inventory, err := runtimeconfig.DecodeRouteInventory(context.Background(), bytes.NewReader(inventoryBytes))
	if err != nil {
		t.Fatal(err)
	}
	policyBytes, _ := json.Marshal(map[string]any{"schema_version": 1, "inventory_identity": inventory.Identity(), "review_policy_identity": strings.Repeat("a", 64), "min_context_tokens": 32000, "min_output_tokens": 4096, "required_features": []string{"structured_output"}, "classification": "confidential", "allowed_zones": []string{zone}, "content_logging_allowed": false, "estimated_input_tokens": 1000, "max_output_tokens": 4096, "max_cost_micro_usd": 0, "pinned_route_record_identity": "", "preferred_route_record_identities": []string{}, "verification_independence": "distinct_provider", "publication_minimum_severity": "medium", "publication_max_inline_findings": 20, "publication_minimum_independence": "distinct_provider", "publication_block_on_inconclusive": true, "connections": connections})
	policy, err := runtimeconfig.DecodeRuntimePolicy(context.Background(), bytes.NewReader(policyBytes), inventory)
	if err != nil {
		t.Fatal(err)
	}
	return inventory, policy
}
func TestSetupLocalInferenceFactoryBuildsWithoutReadingCredentials(t *testing.T) {
	calls := 0
	factory, err := newSetupLocalInferenceFactory(func(string) string { calls++; return "secret" })
	if err != nil {
		t.Fatal(err)
	}
	inventory, policy := setupInferenceRuntime(t, "local", []string{"http://127.0.0.1:11434/v1", "http://[::1]:11435/v1"})
	catalog, err := factory.Build(context.Background(), inventory, policy)
	if err != nil || catalog.Len() != 2 || calls != 0 || factory.FactoryIdentity() == "" {
		t.Fatalf("build=%v len=%d calls=%d", err, catalog.Len(), calls)
	}
}
func TestSetupLocalInferenceFactoryRejectsRemoteOrNilEnvironment(t *testing.T) {
	if factory, err := newSetupLocalInferenceFactory(nil); err == nil || factory != nil {
		t.Fatalf("nil=%#v %v", factory, err)
	}
	factory, _ := newSetupLocalInferenceFactory(func(string) string { return "secret" })
	inventory, policy := setupInferenceRuntime(t, "private_remote", []string{"https://one.example/v1", "https://two.example/v1"})
	if _, err := factory.Build(context.Background(), inventory, policy); err == nil {
		t.Fatal("remote accepted")
	}
}
