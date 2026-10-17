package runtimecatalog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/memory"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

func TestPlanLocalGenerationRouteBindsActualSanitizedRequest(t *testing.T) {
	scope, request := readableGenerationRequest(t)
	inventory, err := runtimeconfig.NewRouteInventory(context.Background(), localPairDefinitions(t))
	if err != nil {
		t.Fatal(err)
	}
	policy := localPairPolicy(t, inventory, true, []string{"adapter-b"}, "distinct_provider", nil)
	pair, err := ResolveLocalGenerationRoutePair(policy, inventory)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := PlanLocalGenerationRoute(context.Background(), scope, request, policy, inventory, pair)
	if err != nil {
		t.Fatal(err)
	}
	budget, err := review.ModelRequestBudget(request, policy.Budget())
	if err != nil {
		t.Fatal(err)
	}
	if plan.routingInput.RequestIdentity() != request.Identity() || plan.eligibility.CostBudget() != budget || plan.selection.SelectedRecordIdentity() != pair.GenerationRecordIdentity() || plan.authorization.RouteRecordIdentity() != pair.GenerationRecordIdentity() || plan.authorization.RouteReference() != pair.GenerationRoute() || plan.authorization.ContentLoggingMode() != provider.ContentLoggingDisabled || plan.authorization.RouteReference().Zone() != provider.ProviderZoneLocal || plan.authorization.Kind() != 1 || plan.authorization.AttemptOrdinal() != 1 || plan.authorization.RouteAttemptOrdinal() != 1 || plan.PolicyIdentity() != policy.Identity() || plan.InventoryIdentity() != inventory.Identity() || plan.PairIdentity() != pair.Identity() || plan.RegistryRevision() != inventory.RegistryRevision() || plan.PerformanceRevision() != inventory.PerformanceRevision() {
		t.Fatal("plan did not bind actual request and exact local pair")
	}
	if len(plan.eligibility.EligibleRoutes()) != 1 || len(plan.ranking.RankedRoutes()) != 1 || len(plan.selection.CandidateScores()) != 1 || len(plan.selection.Rejections()) != 0 {
		t.Fatal("planner included extra routes")
	}
	if plan.ranking.RankingPolicyIdentity() != policy.Ranking().Identity() || plan.selection.RankingPolicyIdentity() != policy.Ranking().Identity() || plan.RankingPolicyIdentity() != policy.Ranking().Identity() {
		t.Fatal("ranking and selection must retain the configured ranking policy identity")
	}
	if plan.RequestIdentity() != plan.routingInput.RequestIdentity() || plan.RoutingInputIdentity() != plan.routingInput.Identity() || plan.RoutingInputIdentity() != plan.selection.RoutingInputIdentity() || plan.SelectionIdentity() != plan.selection.Identity() || plan.SelectedRecordIdentity() != plan.selection.SelectedRecordIdentity() || plan.authorization.SelectionReceiptIdentity() != plan.SelectionIdentity() || plan.authorization.RequestIdentity() != plan.RequestIdentity() {
		t.Fatal("public identities and private typed objects do not join")
	}
}

type failingSelectionLedger struct{ audit.Ledger }

func (failingSelectionLedger) Append(context.Context, string, audit.Event) error {
	return audit.ErrAuditHeadConflict
}

func TestGrantLocalGenerationRouteRecordsOnlyExactPlannedSelection(t *testing.T) {
	ctx := context.Background()
	scope, request := readableGenerationRequest(t)
	inventory, err := runtimeconfig.NewRouteInventory(ctx, localPairDefinitions(t))
	if err != nil {
		t.Fatal(err)
	}
	policy := localPairPolicy(t, inventory, true, []string{"adapter-b"}, "distinct_provider", nil)
	pair, err := ResolveLocalGenerationRoutePair(policy, inventory)
	if err != nil {
		t.Fatal(err)
	}
	ledger := audit.NewMemoryLedger()
	plan, err := PlanLocalGenerationRoute(ctx, scope, request, policy, inventory, pair)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := GrantLocalGenerationRoute(ctx, scope, request, policy, inventory, pair, plan, ledger, time.UnixMilli(100))
	if err != nil || grant.Validate() != nil || grant.RequestIdentity() != request.Identity() || grant.RouteRecordIdentity() != pair.GenerationRecordIdentity() || grant.SelectionReceiptIdentity() != plan.SelectionIdentity() {
		t.Fatalf("actual request grant: %v", err)
	}
	events, err := ledger.Read(ctx, scope, 0, 10)
	if err != nil || len(events) != 1 || events[0].Kind() != audit.EventRouteSelected || events[0].SubjectIdentity() != plan.SelectionIdentity() {
		t.Fatalf("selection not recorded: %v", err)
	}
	again, err := GrantLocalGenerationRoute(ctx, scope, request, policy, inventory, pair, plan, ledger, time.UnixMilli(101))
	if err != nil || again.Identity() != grant.Identity() {
		t.Fatalf("idempotent grant: %v", err)
	}
	changed := plan
	changed.authorization = gateway.RouteAttemptAuthorization{}
	if value, err := GrantLocalGenerationRoute(ctx, scope, request, policy, inventory, pair, changed, ledger, time.UnixMilli(102)); err == nil || value.Identity() != "" {
		t.Fatalf("changed plan granted: %v", err)
	}
	if value, err := GrantLocalGenerationRoute(ctx, scope, request, policy, inventory, pair, plan, nil, time.UnixMilli(102)); err == nil || value.Identity() != "" {
		t.Fatalf("missing ledger granted: %v", err)
	}
	var typedNil *audit.MemoryLedger
	if value, err := GrantLocalGenerationRoute(ctx, scope, request, policy, inventory, pair, plan, typedNil, time.UnixMilli(102)); err == nil || value.Identity() != "" {
		t.Fatalf("typed nil ledger granted: %v", err)
	}
	if value, err := GrantLocalGenerationRoute(ctx, scope, request, policy, inventory, pair, plan, failingSelectionLedger{audit.NewMemoryLedger()}, time.UnixMilli(102)); err == nil || value.Identity() != "" {
		t.Fatalf("failed selection write granted: %v", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if value, err := GrantLocalGenerationRoute(canceled, scope, request, policy, inventory, pair, plan, ledger, time.UnixMilli(102)); err == nil || value.Identity() != "" {
		t.Fatalf("canceled grant: %v", err)
	}
	other, _ := audit.NewReviewScope("tenant", "repository", "run-other")
	if value, err := GrantLocalGenerationRoute(ctx, other, request, policy, inventory, pair, plan, ledger, time.UnixMilli(102)); err == nil || value.Identity() != "" {
		t.Fatalf("cross-scope grant: %v", err)
	}
	stored, err := ledger.Read(ctx, scope, 0, 10)
	if err != nil || len(stored) != 1 {
		t.Fatalf("invalid grant wrote selection: %v", err)
	}
}

func TestLocalGenerationRoutePlanPublicSurfaceIsIdentityOnly(t *testing.T) {
	typeOfPlan := reflect.TypeOf(LocalGenerationRoutePlan{})
	for index := 0; index < typeOfPlan.NumField(); index++ {
		field := typeOfPlan.Field(index)
		if field.IsExported() {
			t.Fatalf("plan exports field %s (%s)", field.Name, field.Type)
		}
	}
	allowed := map[string]reflect.Kind{
		"RequestIdentity":        reflect.String,
		"RoutingInputIdentity":   reflect.String,
		"SelectionIdentity":      reflect.String,
		"RankingPolicyIdentity":  reflect.String,
		"SelectedRecordIdentity": reflect.String,
		"PolicyIdentity":         reflect.String,
		"InventoryIdentity":      reflect.String,
		"PairIdentity":           reflect.String,
		"RegistryRevision":       reflect.Uint64,
		"PerformanceRevision":    reflect.Uint64,
	}
	if typeOfPlan.NumMethod() != len(allowed) {
		t.Fatalf("plan exports %d methods, want %d identity/revision getters", typeOfPlan.NumMethod(), len(allowed))
	}
	for index := 0; index < typeOfPlan.NumMethod(); index++ {
		method := typeOfPlan.Method(index)
		if method.Type.NumIn() != 1 || method.Type.NumOut() != 1 {
			t.Fatalf("plan exports non-getter %s", method.Name)
		}
		result := method.Type.Out(0)
		kind, allowedName := allowed[method.Name]
		if !allowedName || result.Kind() != kind {
			t.Fatalf("plan exports non-projection getter %s: %s", method.Name, result)
		}
	}
}

func largeSanitizedGenerationRequest(t *testing.T, scope audit.ReviewScope) provider.Request {
	t.Helper()
	memoryScope, err := memory.NewScope(scope.TenantID(), scope.RepositoryID(), "actor", memory.RefVisibilityExact, strings.Repeat("a", 64), []string{"src"})
	if err != nil {
		t.Fatal(err)
	}
	content := []byte(strings.Repeat("x", 35000))
	sourceRange, err := evidence.NewSourceRange("src/main.go", 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := review.NewReviewSnapshot("workspace", strings.Repeat("b", 64), []evidence.SourceRange{sourceRange})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	item, err := evidence.NewEvidenceItem("source-1", evidence.EvidenceKindSource, hex.EncodeToString(digest[:]), sourceRange)
	if err != nil {
		t.Fatal(err)
	}
	source, err := review.NewContextSource(review.ContextStageChangedHunk, memory.TaintRepositoryControlled, item, content)
	if err != nil {
		t.Fatal(err)
	}
	index := memory.NewLexicalIndex()
	query, err := memory.NewLexicalQuery(memoryScope, "src/main.go", nil, nil, time.UnixMilli(100), 5)
	if err != nil {
		t.Fatal(err)
	}
	retrieval, err := index.Search(context.Background(), memoryScope, query)
	if err != nil {
		t.Fatal(err)
	}
	limits, err := review.NewContextLimits(1<<20, 0)
	if err != nil {
		t.Fatal(err)
	}
	generation, err := review.NewContextPacket(scope, memoryScope, snapshot, review.ContextTaskCandidateGeneration, []review.ContextSource{source}, retrieval, limits)
	if err != nil {
		t.Fatal(err)
	}
	rawGenerationRequest, err := generation.ProviderRequest()
	if err != nil {
		t.Fatal(err)
	}
	sanitizedGenerationRequest, err := review.NewSanitizedModelRequest(scope.Identity(), rawGenerationRequest, rawGenerationRequest)
	if err != nil {
		t.Fatal(err)
	}
	generationRequest, err := sanitizedGenerationRequest.ProviderRequest()
	if err != nil {
		t.Fatal(err)
	}
	return generationRequest
}

func TestPlanLocalGenerationRouteRejectsRequestThatVerifierCannotFit(t *testing.T) {
	scope, small := readableGenerationRequest(t)
	large := largeSanitizedGenerationRequest(t, scope)
	definitions := localPairDefinitions(t)
	definitions[1].Capabilities, _ = provider.NewModelCapabilities(32000, 8192, []provider.ModelFeature{provider.ModelFeatureStructuredOutput})
	inventory, err := runtimeconfig.NewRouteInventory(context.Background(), definitions)
	if err != nil {
		t.Fatal(err)
	}
	policy := localPairPolicy(t, inventory, true, []string{"adapter-b"}, "distinct_provider", nil)
	pair, err := ResolveLocalGenerationRoutePair(policy, inventory)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PlanLocalGenerationRoute(context.Background(), scope, small, policy, inventory, pair); err != nil {
		t.Fatalf("small request should fit both routes: %v", err)
	}
	budget, err := review.ModelRequestBudget(large, policy.Budget())
	if err != nil || uint64(budget.EstimatedInputTokens())+uint64(budget.MaxOutputTokens()) <= 32000 {
		t.Fatalf("large request must exceed verifier context: %v", err)
	}
	plan, err := PlanLocalGenerationRoute(context.Background(), scope, large, policy, inventory, pair)
	if err == nil || plan.SelectionIdentity() != "" {
		t.Fatal("generation planned despite unavailable bound verifier")
	}
}

func TestPlanLocalGenerationRouteNeverFallsBackFromIneligiblePinnedRecord(t *testing.T) {
	scope, small := readableGenerationRequest(t)
	large := largeSanitizedGenerationRequest(t, scope)
	if review.ValidateCandidateEgressRequest(large, scope.Identity()) != nil || large.Identity() == small.Identity() {
		t.Fatal("test request is not distinct sanitized egress")
	}
	defs := localPairDefinitions(t)
	defs[0].Capabilities, _ = provider.NewModelCapabilities(32000, 8192, []provider.ModelFeature{provider.ModelFeatureStructuredOutput})
	third := defs[1]
	third.Route, _ = provider.NewRouteReference(provider.ProviderZoneLocal, "provider-c", "adapter-c", "connection-c", "model-c", "1")
	defs = append(defs, third)
	inventory, err := runtimeconfig.NewRouteInventory(context.Background(), defs)
	if err != nil {
		t.Fatal(err)
	}
	policy := localPairPolicy(t, inventory, true, []string{"adapter-b"}, "distinct_provider", func(doc map[string]any) {
		doc["connections"] = append(doc["connections"].([]map[string]string), map[string]string{"implementation": "openai_responses", "adapter_id": "adapter-c", "endpoint": "http://127.0.0.1:11436/v1", "credential_environment": "OPEN_TRESTLE_PROVIDER_FIXTURE_C"})
	})
	pair, err := ResolveLocalGenerationRoutePair(policy, inventory)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PlanLocalGenerationRoute(context.Background(), scope, small, policy, inventory, pair); err != nil {
		t.Fatalf("small request should fit pin: %v", err)
	}
	budget, err := review.ModelRequestBudget(large, policy.Budget())
	if err != nil {
		t.Fatal(err)
	}
	if uint64(budget.EstimatedInputTokens())+uint64(budget.MaxOutputTokens()) <= 32000 {
		t.Fatal("large request does not exceed pin")
	}
	if uint64(budget.EstimatedInputTokens())+uint64(budget.MaxOutputTokens()) >= 128000 {
		t.Fatal("third route cannot fit")
	}
	input, err := gateway.NewReviewRoutingInput(scope, large, policy.Requirements(), policy.Constraints())
	if err != nil {
		t.Fatal(err)
	}
	all, err := gateway.FilterEligibleRoutes(input, budget, inventory.RegistryRevision(), inventory.Candidates())
	if err != nil {
		t.Fatal(err)
	}
	thirdEligible := false
	for _, route := range all.EligibleRoutes() {
		if route.ResolvedRecord().RouteRegistryRecord().RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference().AdapterID() == "adapter-c" {
			thirdEligible = true
		}
	}
	if !thirdEligible {
		t.Fatal("third candidate must be eligible to prove no fallback")
	}
	if plan, err := PlanLocalGenerationRoute(context.Background(), scope, large, policy, inventory, pair); err == nil || plan.authorization.Identity() != "" {
		t.Fatal("ineligible pin fell back to third route")
	}
}

func TestPlanLocalGenerationRouteRejectsChangedBindingsAndMalformedInventory(t *testing.T) {
	scope, request := readableGenerationRequest(t)
	inventory, err := runtimeconfig.NewRouteInventory(context.Background(), localPairDefinitions(t))
	if err != nil {
		t.Fatal(err)
	}
	policy := localPairPolicy(t, inventory, true, []string{"adapter-b"}, "distinct_provider", nil)
	pair, err := ResolveLocalGenerationRoutePair(policy, inventory)
	if err != nil {
		t.Fatal(err)
	}
	otherScope, _ := audit.NewReviewScope("tenant", "repository", "other-run")
	otherRequest, _ := readableModelRequests(t, otherScope)
	rawPayload, err := review.SanitizedCandidatePayload(request, scope.Identity())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := provider.NewRequest(provider.CapabilityReviewV1, "application/json", rawPayload)
	staleDefinitions := localPairDefinitions(t)
	for index := range staleDefinitions {
		staleDefinitions[index].PerformanceRevision++
	}
	staleInventory, err := runtimeconfig.NewRouteInventory(context.Background(), staleDefinitions)
	if err != nil {
		t.Fatal(err)
	}
	alteredPolicy := localPairPolicy(t, inventory, true, nil, "distinct_provider", nil)
	alteredPair := pair
	alteredPair.registryRevision++
	alteredPair.identity = localPairIdentity(alteredPair)
	wrongReference := pair
	wrongReference.generationRoute = pair.VerificationRoute()
	wrongReference.identity = localPairIdentity(wrongReference)
	unknownPriceDefinitions := localPairDefinitions(t)
	unknownPriceDefinitions[0].Pricing = provider.NewUnknownRoutePricing()
	unknownPriceInventory, err := runtimeconfig.NewRouteInventory(context.Background(), unknownPriceDefinitions)
	if err != nil {
		t.Fatal(err)
	}
	unknownQuotaDefinitions := localPairDefinitions(t)
	unknownQuotaDefinitions[0].Quota = provider.RouteQuotaUnknown
	unknownQuotaInventory, err := runtimeconfig.NewRouteInventory(context.Background(), unknownQuotaDefinitions)
	if err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	cases := []struct {
		name      string
		ctx       context.Context
		scope     audit.ReviewScope
		request   provider.Request
		policy    runtimeconfig.RuntimePolicy
		inventory runtimeconfig.RouteInventory
		pair      LocalGenerationRoutePair
	}{
		{"wrong scope", context.Background(), otherScope, request, policy, inventory, pair},
		{"request for other scope", context.Background(), scope, otherRequest, policy, inventory, pair},
		{"raw unwrapped request", context.Background(), scope, raw, policy, inventory, pair},
		{"stale inventory", context.Background(), scope, request, policy, staleInventory, pair},
		{"changed policy", context.Background(), scope, request, alteredPolicy, inventory, pair},
		{"changed pair revision", context.Background(), scope, request, policy, inventory, alteredPair},
		{"wrong pair reference", context.Background(), scope, request, policy, inventory, wrongReference},
		{"unknown pinned price", context.Background(), scope, request, policy, unknownPriceInventory, pair},
		{"unknown pinned quota", context.Background(), scope, request, policy, unknownQuotaInventory, pair},
		{"canceled context", canceled, scope, request, policy, inventory, pair},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan, err := PlanLocalGenerationRoute(tc.ctx, tc.scope, tc.request, tc.policy, tc.inventory, tc.pair)
			if err == nil || plan.authorization.Identity() != "" || plan.selection.Identity() != "" {
				t.Fatalf("invalid input accepted: %v", err)
			}
		})
	}
}
