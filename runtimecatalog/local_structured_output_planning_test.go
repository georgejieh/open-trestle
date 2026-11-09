package runtimecatalog

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	modelhandler "github.com/georgejieh/open-trestle/handlers/model"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/internal/testsupport"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

// structuredDispatch sends request through the policy's real OpenAI-compatible
// adapter for authorization, over a recording transport.
func structuredDispatch(t *testing.T, inventory runtimeconfig.RouteInventory, policy runtimeconfig.RuntimePolicy, authorization gateway.RouteAttemptAuthorization, request provider.Request) (gateway.RouteDispatchResult, *structuredTransport) {
	t.Helper()
	resolver, err := NewEnvironmentOpenAICredentialResolver(func(string) string { return "test-secret" })
	if err != nil {
		t.Fatal(err)
	}
	transport := &structuredTransport{}
	catalog, err := NewOpenAIRouteDispatcherCatalogWithOptions(inventory, policy, resolver, OpenAICatalogOptions{HTTPClient: &http.Client{Transport: transport}, HTTPClientIdentity: strings.Repeat("a", 64)})
	if err != nil {
		t.Fatal(err)
	}
	adapter, ok := catalog.Resolve(authorization.RouteReference().AdapterID())
	if !ok {
		t.Fatal("missing adapter")
	}
	result, err := gateway.DispatchAuthorizedRoute(context.Background(), adapter, authorization, request)
	if err != nil {
		t.Fatal(err)
	}
	return result, transport
}

// Generation planning must reserve everything the structured-output adapter
// checks and sends, so a policy that declares only a nominal input estimate is
// dispatched instead of refused.
func TestLocalStructuredOutputGenerationPlanningReservesTheSchemaFraming(t *testing.T) {
	ctx := context.Background()
	scope, request := readableGenerationRequest(t)
	inventory, err := runtimeconfig.NewRouteInventory(ctx, localPairDefinitions(t))
	if err != nil {
		t.Fatal(err)
	}
	structured := structuredPolicy(t, inventory, true, 1)
	want, err := review.ModelRequestBudgetForTransport(request, structured.Budget(), review.ModelRequestTransportLocalStructuredOutput)
	if err != nil {
		t.Fatal(err)
	}
	standard, err := review.ModelRequestBudget(request, structured.Budget())
	if err != nil || want.EstimatedInputTokens() <= standard.EstimatedInputTokens() {
		t.Fatal("fixture does not expose the schema framing")
	}
	authorizer, err := NewGenerationPolicyAuthorizerFromRuntimePolicy(structured, inventory, audit.NewMemoryLedger())
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := authorizer.Authorize(ctx, scope, request, structured.ReviewPolicyIdentity(), time.UnixMilli(100))
	if err != nil {
		t.Fatal(err)
	}
	pair, err := ResolveLocalGenerationRoutePair(structured, inventory)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := PlanLocalGenerationRoute(ctx, scope, request, structured, inventory, pair)
	if err != nil {
		t.Fatal(err)
	}
	for name, planned := range map[string]gateway.RouteAttemptAuthorization{"route authorizer": authorization, "local generation route planner": plan.authorization} {
		if planned.CostBudget() != want {
			t.Fatalf("%s reserved %d input, want %d", name, planned.CostBudget().EstimatedInputTokens(), want.EstimatedInputTokens())
		}
		result, transport := structuredDispatch(t, inventory, structured, planned, request)
		if result.Status() != gateway.RouteDispatchSucceeded || transport.calls != 1 {
			t.Fatalf("%s reservation refused by the structured-output adapter: %#v", name, result)
		}
	}
	// The standard transport keeps its estimate, and its authorizer keeps the
	// identity of one built without a runtime policy; the structured authorizer
	// binds its transport.
	disabled := structuredPolicy(t, inventory, false, 1)
	plain, err := NewGenerationPolicyAuthorizerFromRuntimePolicy(disabled, inventory, audit.NewMemoryLedger())
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := NewGenerationPolicyAuthorizer(disabled.ReviewPolicyIdentity(), disabled.Requirements(), disabled.Constraints(), disabled.Budget(), inventory, disabled.Ranking(), audit.NewMemoryLedger())
	if err != nil {
		t.Fatal(err)
	}
	if plain.Identity() != baseline.Identity() || authorizer.Identity() == baseline.Identity() {
		t.Fatal("authorizer identity does not bind exactly the structured transport")
	}
	standardAuthorization, err := plain.Authorize(ctx, scope, request, disabled.ReviewPolicyIdentity(), time.UnixMilli(100))
	if err != nil || standardAuthorization.CostBudget() != standard {
		t.Fatal("standard transport reservation changed")
	}
	disabledPair, err := ResolveLocalGenerationRoutePair(disabled, inventory)
	if err != nil {
		t.Fatal(err)
	}
	standardPlan, err := PlanLocalGenerationRoute(ctx, scope, request, disabled, inventory, disabledPair)
	if err != nil || standardPlan.authorization.CostBudget() != standard {
		t.Fatal("standard local generation reservation changed")
	}
}

// Verification planning must reserve the schema framing the structured-output
// adapter sends with the sanitized verification request.
func TestLocalStructuredOutputVerificationPlanningReservesTheSchemaFraming(t *testing.T) {
	ctx := context.Background()
	scope, err := audit.NewReviewScope("tenant", "repository", "run")
	if err != nil {
		t.Fatal(err)
	}
	request, rawVerification := readableModelRequests(t, scope)
	sanitized, _, err := testsupport.NewCleanVerificationSanitizer().SanitizeVerification(ctx, rawVerification, scope.Identity())
	if err != nil {
		t.Fatal(err)
	}
	verification, err := sanitized.ProviderRequest()
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := runtimeconfig.NewRouteInventory(ctx, localPairDefinitions(t))
	if err != nil {
		t.Fatal(err)
	}
	view, err := NewStaticVerificationRouteInventory(inventory)
	if err != nil {
		t.Fatal(err)
	}
	authorize := func(policy runtimeconfig.RuntimePolicy) (gateway.RouteAttemptAuthorization, string) {
		t.Helper()
		generation, err := NewGenerationPolicyAuthorizerFromRuntimePolicy(policy, inventory, audit.NewMemoryLedger())
		if err != nil {
			t.Fatal(err)
		}
		authorization, err := generation.Authorize(ctx, scope, request, policy.ReviewPolicyIdentity(), time.UnixMilli(100))
		if err != nil {
			t.Fatal(err)
		}
		usage, _ := provider.NewRouteTokenUsage(1, 1, 0)
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
		verifier, err := NewVerificationPolicyAuthorizerFromRuntimePolicy(policy, view, audit.NewMemoryLedger(), catalogFixedClock{at: time.UnixMilli(200)})
		if err != nil {
			t.Fatal(err)
		}
		authority, err := verifier.Authorize(ctx, scope, verification, execution)
		if err != nil {
			t.Fatal(err)
		}
		return authority.Authorization(), verifier.Identity()
	}
	structured := structuredPolicy(t, inventory, true, 1)
	want, err := review.ModelRequestBudgetForTransport(verification, structured.Budget(), review.ModelRequestTransportLocalStructuredOutput)
	if err != nil {
		t.Fatal(err)
	}
	standard, err := review.ModelRequestBudget(verification, structured.Budget())
	if err != nil || want.EstimatedInputTokens() <= standard.EstimatedInputTokens() {
		t.Fatal("fixture does not expose the schema framing")
	}
	authorization, structuredIdentity := authorize(structured)
	if authorization.CostBudget() != want {
		t.Fatalf("verification authorizer reserved %d input, want %d", authorization.CostBudget().EstimatedInputTokens(), want.EstimatedInputTokens())
	}
	result, transport := structuredDispatch(t, inventory, structured, authorization, verification)
	if result.Status() != gateway.RouteDispatchSucceeded || transport.calls != 1 {
		t.Fatalf("verification reservation refused by the structured-output adapter: %#v", result)
	}
	// The standard transport keeps its estimate and its version 2 identity.
	disabled := structuredPolicy(t, inventory, false, 1)
	standardAuthorization, standardIdentity := authorize(disabled)
	if standardAuthorization.CostBudget() != standard {
		t.Fatal("standard verification reservation changed")
	}
	pinned, err := gateway.NewRouteRankingPolicy(disabled.Ranking().PreferredRoutes())
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := NewVerificationPolicyAuthorizer(StaticVerificationRouteInventory{inventory: inventory, selected: verifierSnapshot(t, inventory, disabled)}, disabled.Requirements(), disabled.Constraints(), disabled.Budget(), pinned, disabled.Independence(), audit.NewMemoryLedger(), catalogFixedClock{at: time.UnixMilli(200)})
	if err != nil {
		t.Fatal(err)
	}
	if standardIdentity != baseline.Identity() || structuredIdentity == standardIdentity {
		t.Fatal("verification authorizer identity does not bind exactly the structured transport")
	}
}

// verifierSnapshot is the explicit verifier route view that
// NewVerificationPolicyAuthorizerFromRuntimePolicy selects.
func verifierSnapshot(t *testing.T, inventory runtimeconfig.RouteInventory, policy runtimeconfig.RuntimePolicy) *modelhandler.VerificationRouteSnapshot {
	t.Helper()
	for index, candidate := range inventory.Candidates() {
		if candidate.ResolvedRecord().RouteRegistryRecord().Identity() == policy.VerificationRouteRecordIdentity() {
			snapshot, err := modelhandler.NewVerificationRouteSnapshot(inventory.RegistryRevision(), inventory.PerformanceRevision(), []gateway.ObservedRouteCandidate{candidate}, []provider.RoutePerformanceObservation{inventory.PerformanceObservations()[index]})
			if err != nil {
				t.Fatal(err)
			}
			return &snapshot
		}
	}
	t.Fatal("policy verifier is not in the inventory")
	return nil
}
