package runtimecatalog

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

func TestRuntimeGenerationPinDoesNotPinIndependentVerifier(t *testing.T) {
	ctx := context.Background()
	capabilities, err := provider.NewModelCapabilities(128000, 8192, []provider.ModelFeature{provider.ModelFeatureStructuredOutput})
	if err != nil {
		t.Fatal(err)
	}
	pricing, err := provider.NewRoutePricing(0, 0)
	if err != nil {
		t.Fatal(err)
	}
	routes := make([]provider.RouteReference, 2)
	definitions := make([]runtimeconfig.RouteDefinition, 2)
	for i, name := range []string{"a", "b"} {
		routes[i], err = provider.NewRouteReference(provider.ProviderZonePrivateRemote, "provider-"+name, "adapter-"+name, "connection-"+name, "model-"+name, "")
		if err != nil {
			t.Fatal(err)
		}
		definitions[i] = runtimeconfig.RouteDefinition{Route: routes[i], Capabilities: capabilities, ContentLogging: provider.ContentLoggingDisabled, Pricing: pricing, Quality: provider.RouteQualityTier3, RegistryRevision: 7, RegistryStatus: provider.RouteRegistryApproved, EvidenceManifest: []byte(`{"fixture":"approved"}`), OperationalRevision: 9, Health: provider.RouteHealthHealthy, Quota: provider.RouteQuotaAvailable, PerformanceRevision: 11, P95LatencyMilliseconds: 2500, LatencySampleCount: 100}
	}
	inventory, err := runtimeconfig.NewRouteInventory(ctx, definitions)
	if err != nil {
		t.Fatal(err)
	}
	records := map[string]string{}
	for _, candidate := range inventory.Candidates() {
		record := candidate.ResolvedRecord().RouteRegistryRecord()
		records[record.RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference().AdapterID()] = record.Identity()
	}
	document, err := json.Marshal(map[string]any{
		"schema_version": 1, "inventory_identity": inventory.Identity(), "review_policy_identity": strings.Repeat("a", 64),
		"min_context_tokens": 32000, "min_output_tokens": 4096, "required_features": []string{"structured_output"},
		"classification": "confidential", "allowed_zones": []string{"private_remote"}, "content_logging_allowed": false,
		"estimated_input_tokens": 1000, "max_output_tokens": 4096, "max_cost_micro_usd": 0,
		"pinned_route_record_identity": records["adapter-a"], "preferred_route_record_identities": []string{records["adapter-b"]},
		"verification_independence": "distinct_provider", "publication_minimum_severity": "medium", "publication_max_inline_findings": 20,
		"publication_minimum_independence": "distinct_provider", "publication_block_on_inconclusive": true,
		"connections": []map[string]string{
			{"implementation": "openai_responses", "adapter_id": "adapter-a", "endpoint": "https://provider-a.invalid", "credential_environment": "OPEN_TRESTLE_PROVIDER_A"},
			{"implementation": "openai_responses", "adapter_id": "adapter-b", "endpoint": "https://provider-b.invalid", "credential_environment": "OPEN_TRESTLE_PROVIDER_B"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	configuration, err := runtimeconfig.DecodeRuntimePolicy(ctx, bytes.NewReader(document), inventory)
	if err != nil {
		t.Fatal(err)
	}
	ledger := audit.NewMemoryLedger()
	generation, err := NewGenerationPolicyAuthorizerFromRuntimePolicy(configuration, inventory, ledger)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := audit.NewReviewScope("tenant-a", "repo-a", "run-pin")
	if err != nil {
		t.Fatal(err)
	}
	request, verificationRequest := readableModelRequests(t, scope)
	authorization, err := generation.Authorize(ctx, scope, request, configuration.ReviewPolicyIdentity(), time.UnixMilli(100))
	if err != nil || authorization.RouteReference() != routes[0] {
		t.Fatalf("generation pin failed: %v", err)
	}
	usage, err := provider.NewRouteTokenUsage(1, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := gateway.NewSuccessfulRouteAttemptOutcome(authorization, strings.Repeat("b", 64), usage, 1)
	if err != nil {
		t.Fatal(err)
	}
	reconciliation, err := gateway.ReconcileAuthorizedRouteAttemptCost(authorization, outcome)
	if err != nil {
		t.Fatal(err)
	}
	output, err := gateway.NewSuccessfulRouteOutputReceipt(gateway.RouteOutputCandidateBatch, strings.Repeat("c", 64), strings.Repeat("d", 64), request, authorization, outcome)
	if err != nil {
		t.Fatal(err)
	}
	execution, err := gateway.NewRouteExecutionRecord(authorization, outcome, reconciliation, output)
	if err != nil {
		t.Fatal(err)
	}
	verifierInventory, err := NewStaticVerificationRouteInventory(inventory)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewVerificationPolicyAuthorizerFromRuntimePolicy(configuration, verifierInventory, ledger, catalogFixedClock{at: time.UnixMilli(200)})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := verifier.Authorize(ctx, scope, verificationRequest, execution)
	if err != nil || verified.Authorization().RouteReference() != routes[1] {
		t.Fatalf("generation pin blocked independent verifier: %v", err)
	}
	if err := gateway.VerifyIndependentRouteAuthorizations(configuration.Independence(), authorization, verified.Authorization()); err != nil {
		t.Fatalf("independence weakened: %v", err)
	}
	if pin, present := configuration.Ranking().PinnedRoute(); !present || pin != routes[0] {
		t.Fatal("generation pin was removed")
	}
}
