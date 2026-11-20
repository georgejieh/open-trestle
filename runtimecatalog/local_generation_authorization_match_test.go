package runtimecatalog

import (
	"context"
	"testing"

	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

func TestMatchesLocalGenerationAuthorizationChecksCompleteGrant(t *testing.T) {
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
	if !MatchesLocalGenerationAuthorization(plan, plan.authorization) {
		t.Fatal("exact planned grant refused")
	}
	if MatchesLocalGenerationAuthorization(LocalGenerationRoutePlan{}, plan.authorization) || MatchesLocalGenerationAuthorization(plan, gateway.RouteAttemptAuthorization{}) {
		t.Fatal("empty grant or plan admitted")
	}
	zero, err := provider.NewRouteTokenUsage(0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	failed, err := gateway.NewFailedRouteAttemptOutcome(plan.authorization, gateway.RouteFailureRateLimited, gateway.RouteReplayNoSideEffect, zero, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	cost, err := gateway.ReconcileAuthorizedRouteAttemptCost(plan.authorization, failed)
	if err != nil {
		t.Fatal(err)
	}
	retryPolicy, err := gateway.NewRateLimitRetryPolicy(100)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := gateway.EvaluateRouteAttemptRetry(retryPolicy, plan.authorization, failed)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := gateway.NewRateLimitedRetryAttemptAuthorization(plan.authorization, failed, cost, decision)
	if err != nil {
		t.Fatal(err)
	}
	if MatchesLocalGenerationAuthorization(plan, retry) {
		t.Fatal("coherent retry grant admitted")
	}
	changedPolicy := localPairPolicy(t, inventory, true, []string{"adapter-b"}, "distinct_provider", func(doc map[string]any) { doc["max_cost_micro_usd"] = uint64(2000000) })
	changedPair, err := ResolveLocalGenerationRoutePair(changedPolicy, inventory)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := PlanLocalGenerationRoute(context.Background(), scope, request, changedPolicy, inventory, changedPair)
	if err != nil {
		t.Fatal(err)
	}
	if changed.authorization.Validate() != nil || MatchesLocalGenerationAuthorization(plan, changed.authorization) {
		t.Fatal("changed reservation admitted")
	}
}
