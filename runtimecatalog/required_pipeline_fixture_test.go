package runtimecatalog_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

func requiredCheck(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func requiredDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

type requiredClock struct{ at time.Time }

func (c *requiredClock) Now() time.Time { return c.at }

func (c *requiredClock) step() time.Time {
	c.at = c.at.Add(time.Millisecond)
	return c.at
}

type requiredRequestSource struct {
	ID        string `json:"source_id"`
	Stage     string `json:"stage"`
	Path      string `json:"path"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
	Content   string `json:"content"`
}

func requiredRuntimePolicy(t *testing.T, approvedVerifier bool) (runtimeconfig.RuntimePolicy, runtimeconfig.RouteInventory) {
	t.Helper()
	capabilities, err := provider.NewModelCapabilities(128000, 8192, []provider.ModelFeature{provider.ModelFeatureStructuredOutput})
	requiredCheck(t, err)
	pricing, err := provider.NewRoutePricing(0, 0)
	requiredCheck(t, err)
	definitions := make([]runtimeconfig.RouteDefinition, 2)
	for i, name := range []string{"a", "b"} {
		route, err := provider.NewRouteReference(provider.ProviderZonePrivateRemote, "provider-"+name, "adapter-"+name, "connection-"+name, "model-"+name, "")
		requiredCheck(t, err)
		status := provider.RouteRegistryApproved
		if i == 1 && !approvedVerifier {
			status = provider.RouteRegistryPending
		}
		definitions[i] = runtimeconfig.RouteDefinition{Route: route, Capabilities: capabilities, ContentLogging: provider.ContentLoggingDisabled, Pricing: pricing, Quality: provider.RouteQualityTier3, RegistryRevision: 7, RegistryStatus: status, EvidenceManifest: []byte(`{"fixture":"operator-reviewed local adapter contract"}`), OperationalRevision: 9, Health: provider.RouteHealthHealthy, Quota: provider.RouteQuotaAvailable, PerformanceRevision: 11, P95LatencyMilliseconds: 2500, LatencySampleCount: 100}
	}
	inventory, err := runtimeconfig.NewRouteInventory(context.Background(), definitions)
	requiredCheck(t, err)
	records := map[string]string{}
	for _, candidate := range inventory.Candidates() {
		record := candidate.ResolvedRecord().RouteRegistryRecord()
		records[record.RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference().AdapterID()] = record.Identity()
	}
	document, err := json.Marshal(map[string]any{
		"schema_version": 1, "inventory_identity": inventory.Identity(), "review_policy_identity": requiredDigest("review-policy"),
		"min_context_tokens": 32000, "min_output_tokens": 4096, "required_features": []string{"structured_output"},
		"classification": "confidential", "allowed_zones": []string{"private_remote"}, "content_logging_allowed": false,
		"estimated_input_tokens": 1000, "max_output_tokens": 4096, "max_cost_micro_usd": 0,
		"pinned_route_record_identity": records["adapter-a"], "preferred_route_record_identities": []string{records["adapter-b"]},
		"verification_independence": "distinct_provider", "publication_minimum_severity": "medium", "publication_max_inline_findings": 20,
		"publication_minimum_independence": "distinct_provider", "publication_block_on_inconclusive": true,
		"connections": []map[string]string{
			{"implementation": "openai_responses", "adapter_id": "adapter-a", "endpoint": "https://provider-a.invalid", "credential_environment": "OPEN_TRESTLE_PROVIDER_FIXTURE_A"},
			{"implementation": "openai_responses", "adapter_id": "adapter-b", "endpoint": "https://provider-b.invalid", "credential_environment": "OPEN_TRESTLE_PROVIDER_FIXTURE_B"},
		},
	})
	requiredCheck(t, err)
	configuration, err := runtimeconfig.DecodeRuntimePolicy(context.Background(), bytes.NewReader(document), inventory)
	requiredCheck(t, err)
	return configuration, inventory
}

func requiredEvent(t *testing.T, events []audit.Event, kind audit.EventKind, subject string) audit.Event {
	t.Helper()
	var found audit.Event
	for _, event := range events {
		if event.Kind() == kind && event.SubjectIdentity() == subject {
			if found.Identity() != "" {
				t.Fatalf("duplicate %s event", kind)
			}
			found = event
		}
	}
	if found.Identity() == "" {
		t.Fatalf("missing %s event for actual artifact lineage", kind)
	}
	return found
}
