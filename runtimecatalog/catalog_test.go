package runtimecatalog

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/policy"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

type handler struct {
	kind     controlplane.TaskKind
	identity string
}

func (h handler) Kind() controlplane.TaskKind { return h.kind }
func (h handler) HandlerIdentity() string     { return h.identity }
func (h handler) Execute(context.Context, controlplane.TaskExecutionRequest) controlplane.TaskCompletion {
	value, _ := controlplane.NewTaskFailure(controlplane.RunFailurePolicy)
	return value
}
func TestPipelineCatalogRequiresExactModeKinds(t *testing.T) {
	kinds := []controlplane.TaskKind{controlplane.TaskAcquireSource, controlplane.TaskBuildChange, controlplane.TaskInspectDeterministic, controlplane.TaskRetrieveContext, controlplane.TaskAssembleContext, controlplane.TaskGenerateCandidates, controlplane.TaskVerifyCandidates, controlplane.TaskEvaluatePublication}
	handlers := make([]controlplane.TaskHandler, len(kinds))
	for i, kind := range kinds {
		handlers[i] = handler{kind, strings.Repeat(string("12345678"[i]), 64)}
	}
	catalog, err := NewPipelineCatalog(controlplane.ReviewRunAdvisory, handlers)
	if err != nil || catalog.Validate() != nil || catalog.Catalog().Len() != 8 || len(catalog.Bindings()) != 8 {
		t.Fatalf("catalog=(%#v,%v)", catalog, err)
	}
	if required, err := NewPipelineCatalog(controlplane.ReviewRunRequired, handlers); err == nil || required.Identity() != "" {
		t.Fatal("required catalog accepted without publisher")
	}
}

func TestRouteAuthorityFactoriesBindOneInventory(t *testing.T) {
	route, err := provider.NewRouteReference(provider.ProviderZonePrivateRemote, "provider-a", "adapter-a", "connection-a", "model-a", "2026-01")
	if err != nil {
		t.Fatal(err)
	}
	capabilities, err := provider.NewModelCapabilities(128000, 8192, []provider.ModelFeature{provider.ModelFeatureStructuredOutput})
	if err != nil {
		t.Fatal(err)
	}
	pricing, err := provider.NewRoutePricing(1000, 2000)
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := runtimeconfig.NewRouteInventory(context.Background(), []runtimeconfig.RouteDefinition{{Route: route, Capabilities: capabilities, ContentLogging: provider.ContentLoggingDisabled, Pricing: pricing, Quality: provider.RouteQualityTier3, RegistryRevision: 7, RegistryStatus: provider.RouteRegistryApproved, EvidenceManifest: []byte(`{"benchmark":"approved"}`), OperationalRevision: 9, Health: provider.RouteHealthHealthy, Quota: provider.RouteQuotaAvailable, PerformanceRevision: 11, P95LatencyMilliseconds: 2500, LatencySampleCount: 100}})
	if err != nil {
		t.Fatal(err)
	}
	requirements, err := provider.NewModelRequirements(32000, 4096, []provider.ModelFeature{provider.ModelFeatureStructuredOutput})
	if err != nil {
		t.Fatal(err)
	}
	zones, err := policy.NewAllowedProviderZones(provider.ProviderZonePrivateRemote)
	if err != nil {
		t.Fatal(err)
	}
	constraints, err := policy.NewProviderDataConstraints(policy.DataClassificationConfidential, zones, false)
	if err != nil {
		t.Fatal(err)
	}
	budget, err := provider.NewModelCostBudget(8000, 4096, 100000)
	if err != nil {
		t.Fatal(err)
	}
	ranking, err := gateway.NewRouteRankingPolicy(nil)
	if err != nil {
		t.Fatal(err)
	}
	policyID := strings.Repeat("a", 64)
	ledger := audit.NewMemoryLedger()
	generation, err := NewGenerationPolicyAuthorizer(policyID, requirements, constraints, budget, inventory, ranking, ledger)
	if err != nil || generation.Validate() != nil {
		t.Fatalf("generation=(%#v,%v)", generation, err)
	}
	otherRoute, err := provider.NewRouteReference(provider.ProviderZonePrivateRemote, "provider-b", "adapter-b", "connection-b", "model-b", "2026-01")
	if err != nil {
		t.Fatal(err)
	}
	mixedDefinitions := []runtimeconfig.RouteDefinition{
		{Route: route, Capabilities: capabilities, ContentLogging: provider.ContentLoggingDisabled, Pricing: pricing, Quality: provider.RouteQualityTier3, RegistryRevision: 7, RegistryStatus: provider.RouteRegistryApproved, EvidenceManifest: []byte(`{"benchmark":"approved"}`), OperationalRevision: 9, Health: provider.RouteHealthHealthy, Quota: provider.RouteQuotaAvailable, PerformanceRevision: 11, P95LatencyMilliseconds: 2500, LatencySampleCount: 100},
		{Route: otherRoute, Capabilities: capabilities, ContentLogging: provider.ContentLoggingDisabled, Pricing: pricing, Quality: provider.RouteQualityTier3, RegistryRevision: 7, RegistryStatus: provider.RouteRegistryApproved, EvidenceManifest: []byte(`{"benchmark":"approved"}`), OperationalRevision: 9, Health: provider.RouteHealthUnhealthy, Quota: provider.RouteQuotaAvailable, PerformanceRevision: 11, P95LatencyMilliseconds: 2500, LatencySampleCount: 100},
	}
	mixedInventory, err := runtimeconfig.NewRouteInventory(context.Background(), mixedDefinitions)
	if err != nil {
		t.Fatal(err)
	}
	mixedAuthorizer, err := NewGenerationPolicyAuthorizer(policyID, requirements, constraints, budget, mixedInventory, ranking, audit.NewMemoryLedger())
	if err != nil {
		t.Fatal(err)
	}
	verificationInventory, err := NewStaticVerificationRouteInventory(inventory)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
	if err != nil {
		t.Fatal(err)
	}
	request, _ := readableModelRequests(t, scope)
	mixedAuthorization, err := mixedAuthorizer.Authorize(context.Background(), scope, request, policyID, time.UnixMilli(100))
	if err != nil || mixedAuthorization.RouteReference() != route {
		t.Fatalf("rejected route blocked healthy alternative: err=%v", err)
	}
	authorization, err := generation.Authorize(context.Background(), scope, request, policyID, time.UnixMilli(100))
	if err != nil {
		t.Fatal(err)
	}
	if _, acquired, err := gateway.ClaimRouteAttempt(context.Background(), ledger, scope, authorization, time.UnixMilli(101)); err != nil || !acquired {
		t.Fatalf("production generation authorization is not claimable: acquired=%t err=%v", acquired, err)
	}
	blocked, err := NewGenerationPolicyAuthorizer(policyID, requirements, constraints, budget, inventory, ranking, failedSelectionLedger{audit.NewMemoryLedger()})
	if err != nil {
		t.Fatal(err)
	}
	if authorization, err := blocked.Authorize(context.Background(), scope, request, policyID, time.UnixMilli(100)); err == nil || authorization.Identity() != "" {
		t.Fatalf("authority escaped failed selection persistence: %v", err)
	}
	if authorizer, err := NewGenerationPolicyAuthorizer(policyID, requirements, constraints, budget, inventory, ranking, nil); err == nil || authorizer != nil {
		t.Fatal("generation authorizer accepted missing ledger")
	}
	snapshot, err := verificationInventory.Snapshot(context.Background(), scope)
	if err != nil || snapshot.Validate() != nil || snapshot.Identity() == "" {
		t.Fatalf("snapshot=(%#v,%v)", snapshot, err)
	}
	independence, err := gateway.NewRouteIndependencePolicy(gateway.RouteIndependenceDistinctProvider)
	if err != nil {
		t.Fatal(err)
	}
	verification, err := NewVerificationPolicyAuthorizer(verificationInventory, requirements, constraints, budget, ranking, independence, audit.NewMemoryLedger(), catalogFixedClock{time.Unix(1, 0).UTC()})
	if err != nil || verification.Validate() != nil {
		t.Fatalf("verification=(%#v,%v)", verification, err)
	}
}

type failedSelectionLedger struct{ audit.Ledger }

func (failedSelectionLedger) Append(context.Context, string, audit.Event) error {
	return errors.New("selection persistence unavailable")
}

type catalogFixedClock struct{ at time.Time }

func (c catalogFixedClock) Now() time.Time { return c.at }

func TestRequiredPipelineCatalogIncludesPublicationAuthority(t *testing.T) {
	kinds := []controlplane.TaskKind{controlplane.TaskAcquireSource, controlplane.TaskBuildChange, controlplane.TaskInspectDeterministic, controlplane.TaskRetrieveContext, controlplane.TaskAssembleContext, controlplane.TaskGenerateCandidates, controlplane.TaskVerifyCandidates, controlplane.TaskEvaluatePublication, controlplane.TaskPublishResult}
	handlers := make([]controlplane.TaskHandler, len(kinds))
	for i, kind := range kinds {
		handlers[i] = handler{kind, strings.Repeat(string("123456789"[i]), 64)}
	}
	catalog, err := NewPipelineCatalog(controlplane.ReviewRunRequired, handlers)
	if err != nil || catalog.Validate() != nil || catalog.Catalog().Len() != 9 || len(catalog.Bindings()) != 9 {
		t.Fatalf("catalog=(%#v,%v)", catalog, err)
	}
}
