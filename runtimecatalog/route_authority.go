package runtimecatalog

import (
	"context"
	"errors"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	contexthandler "github.com/georgejieh/open-trestle/handlers/context"
	modelhandler "github.com/georgejieh/open-trestle/handlers/model"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/policy"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

var ErrInvalidRouteAuthority = errors.New("invalid runtime route authority")

func NewGenerationPolicyAuthorizer(policyIdentity string, requirements provider.ModelRequirements, constraints policy.ProviderDataConstraints, budget provider.ModelCostBudget, inventory runtimeconfig.RouteInventory, ranking gateway.RouteRankingPolicy, ledger audit.Ledger) (*contexthandler.PolicyAuthorizer, error) {
	if inventory.Validate() != nil {
		return nil, ErrInvalidRouteAuthority
	}
	authorizer, err := contexthandler.NewPolicyAuthorizer(policyIdentity, requirements, constraints, budget, inventory.RegistryRevision(), inventory.Candidates(), ranking, inventory.PerformanceRevision(), inventory.PerformanceObservations(), ledger)
	if err != nil {
		return nil, ErrInvalidRouteAuthority
	}
	return authorizer, nil
}

type StaticVerificationRouteInventory struct{ inventory runtimeconfig.RouteInventory }

func NewStaticVerificationRouteInventory(inventory runtimeconfig.RouteInventory) (StaticVerificationRouteInventory, error) {
	if inventory.Validate() != nil {
		return StaticVerificationRouteInventory{}, ErrInvalidRouteAuthority
	}
	return StaticVerificationRouteInventory{inventory}, nil
}
func (i StaticVerificationRouteInventory) Identity() string { return i.inventory.Identity() }
func (i StaticVerificationRouteInventory) Snapshot(ctx context.Context, scope audit.ReviewScope) (modelhandler.VerificationRouteSnapshot, error) {
	if ctx == nil || ctx.Err() != nil || scope.Validate() != nil || i.inventory.Validate() != nil {
		return modelhandler.VerificationRouteSnapshot{}, ErrInvalidRouteAuthority
	}
	snapshot, err := modelhandler.NewVerificationRouteSnapshot(i.inventory.RegistryRevision(), i.inventory.PerformanceRevision(), i.inventory.Candidates(), i.inventory.PerformanceObservations())
	if err != nil {
		return modelhandler.VerificationRouteSnapshot{}, ErrInvalidRouteAuthority
	}
	return snapshot, nil
}
func NewVerificationPolicyAuthorizer(inventory StaticVerificationRouteInventory, requirements provider.ModelRequirements, constraints policy.ProviderDataConstraints, budget provider.ModelCostBudget, ranking gateway.RouteRankingPolicy, independence gateway.RouteIndependencePolicy, ledger audit.Ledger, clock artifact.Clock) (*modelhandler.PolicyVerificationAuthorizer, error) {
	if inventory.inventory.Validate() != nil {
		return nil, ErrInvalidRouteAuthority
	}
	authorizer, err := modelhandler.NewPolicyVerificationAuthorizer(inventory, requirements, constraints, budget, ranking, independence, ledger, clock)
	if err != nil {
		return nil, ErrInvalidRouteAuthority
	}
	return authorizer, nil
}

func NewGenerationPolicyAuthorizerFromRuntimePolicy(configuration runtimeconfig.RuntimePolicy, inventory runtimeconfig.RouteInventory, ledger audit.Ledger) (*contexthandler.PolicyAuthorizer, error) {
	if configuration.Validate() != nil || configuration.ValidateAgainstInventory(inventory) != nil || configuration.InventoryIdentity() != inventory.Identity() {
		return nil, ErrInvalidRouteAuthority
	}
	return NewGenerationPolicyAuthorizer(configuration.ReviewPolicyIdentity(), configuration.Requirements(), configuration.Constraints(), configuration.Budget(), inventory, configuration.Ranking(), ledger)
}
func NewVerificationPolicyAuthorizerFromRuntimePolicy(configuration runtimeconfig.RuntimePolicy, inventory StaticVerificationRouteInventory, ledger audit.Ledger, clock artifact.Clock) (*modelhandler.PolicyVerificationAuthorizer, error) {
	if configuration.Validate() != nil || configuration.ValidateAgainstInventory(inventory.inventory) != nil || configuration.InventoryIdentity() != inventory.Identity() {
		return nil, ErrInvalidRouteAuthority
	}
	// A generation pin cannot also pin a route that independence excludes.
	ranking, err := gateway.NewRouteRankingPolicy(configuration.Ranking().PreferredRoutes())
	if err != nil {
		return nil, ErrInvalidRouteAuthority
	}
	return NewVerificationPolicyAuthorizer(inventory, configuration.Requirements(), configuration.Constraints(), configuration.Budget(), ranking, configuration.Independence(), ledger, clock)
}
