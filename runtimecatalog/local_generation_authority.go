package runtimecatalog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

var ErrInvalidLocalGenerationRoutePair = errors.New("invalid local generation route pair")

// LocalGenerationRoutePair pins two inventory records; it is not an actual-request authorization.
type LocalGenerationRoutePair struct {
	identity, policyIdentity, inventoryIdentity, generationRecordIdentity, verificationRecordIdentity string
	generationRoute, verificationRoute                                                                provider.RouteReference
	independence                                                                                      gateway.RouteIndependencePolicy
	registryRevision, performanceRevision                                                             uint64
}

func (p LocalGenerationRoutePair) Identity() string            { return p.identity }
func (p LocalGenerationRoutePair) RegistryRevision() uint64    { return p.registryRevision }
func (p LocalGenerationRoutePair) PerformanceRevision() uint64 { return p.performanceRevision }
func (p LocalGenerationRoutePair) PolicyIdentity() string      { return p.policyIdentity }
func (p LocalGenerationRoutePair) InventoryIdentity() string   { return p.inventoryIdentity }
func (p LocalGenerationRoutePair) GenerationRecordIdentity() string {
	return p.generationRecordIdentity
}
func (p LocalGenerationRoutePair) VerificationRecordIdentity() string {
	return p.verificationRecordIdentity
}
func (p LocalGenerationRoutePair) GenerationRoute() provider.RouteReference { return p.generationRoute }
func (p LocalGenerationRoutePair) VerificationRoute() provider.RouteReference {
	return p.verificationRoute
}
func (p LocalGenerationRoutePair) Independence() gateway.RouteIndependencePolicy {
	return p.independence
}
func (p LocalGenerationRoutePair) Validate() error {
	if p.policyIdentity == "" || p.inventoryIdentity == "" || p.generationRecordIdentity == "" || p.verificationRecordIdentity == "" || p.generationRecordIdentity == p.verificationRecordIdentity || p.registryRevision == 0 || p.performanceRevision == 0 || p.generationRoute.Validate() != nil || p.verificationRoute.Validate() != nil || p.generationRoute == p.verificationRoute || p.independence.Validate() != nil || p.identity != localPairIdentity(p) {
		return ErrInvalidLocalGenerationRoutePair
	}
	return nil
}

func localPairIdentity(p LocalGenerationRoutePair) string {
	type route struct{ Zone, Provider, Adapter, Connection, Model, Version string }
	ref := func(r provider.RouteReference) route {
		return route{r.Zone().String(), r.ProviderID(), r.AdapterID(), r.ConnectionID(), r.ModelID(), r.ModelVersion()}
	}
	payload, _ := json.Marshal(struct {
		Contract                                                              string
		Version                                                               int
		Policy, Inventory, GenerationRecord, VerificationRecord, Independence string
		RegistryRevision, PerformanceRevision                                 uint64
		GenerationRoute, VerificationRoute                                    route
		LocalOnly, LoggingDisabled                                            bool
	}{"open-trestle/local-generation-route-pair", 1, p.policyIdentity, p.inventoryIdentity, p.generationRecordIdentity, p.verificationRecordIdentity, p.independence.Identity(), p.registryRevision, p.performanceRevision, ref(p.generationRoute), ref(p.verificationRoute), true, true})
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// ResolveLocalGenerationRoutePair is preliminary startup gating. Dispatch must recheck
// eligibility against each actual sanitized request and constrain selection to these records.
func ResolveLocalGenerationRoutePair(configuration runtimeconfig.RuntimePolicy, inventory runtimeconfig.RouteInventory) (LocalGenerationRoutePair, error) {
	fail := func() (LocalGenerationRoutePair, error) {
		return LocalGenerationRoutePair{}, ErrInvalidLocalGenerationRoutePair
	}
	if configuration.Validate() != nil || inventory.Validate() != nil || configuration.ValidateAgainstInventory(inventory) != nil || configuration.InventoryIdentity() != inventory.Identity() || configuration.Constraints().ContentLoggingAllowed() || !configuration.Constraints().AllowedProviderZones().Allows(provider.ProviderZoneLocal) {
		return fail()
	}
	for zone := provider.ProviderZoneLocal + 1; zone <= provider.ProviderZoneSubscriptionOAuth; zone++ {
		if configuration.Constraints().AllowedProviderZones().Allows(zone) {
			return fail()
		}
	}
	pinned, hasPin := configuration.Ranking().PinnedRoute()
	verificationID := configuration.VerificationRouteRecordIdentity()
	if !hasPin || verificationID == "" {
		return fail()
	}
	candidates := inventory.Candidates()
	observations := inventory.PerformanceObservations()
	var generation, verification gateway.ObservedRouteCandidate
	var generationObservation provider.RoutePerformanceObservation
	counts := [2]int{}
	for index, candidate := range candidates {
		record := candidate.ResolvedRecord().RouteRegistryRecord()
		reference := record.RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference()
		if reference == pinned {
			generation = candidate
			generationObservation = observations[index]
			counts[0]++
		}
		if record.Identity() == verificationID {
			verification = candidate
			counts[1]++
		}
	}
	if counts != [2]int{1, 1} {
		return fail()
	}
	for _, candidate := range []gateway.ObservedRouteCandidate{generation, verification} {
		declaration := candidate.ResolvedRecord().RouteRegistryRecord().RouteCandidateDeclaration()
		reference := declaration.RouteCapabilityDeclaration().RouteReference()
		if reference.Zone() != provider.ProviderZoneLocal || declaration.ContentLoggingMode() != provider.ContentLoggingDisabled {
			return fail()
		}
		connections := 0
		for _, connection := range configuration.Connections() {
			if connection.AdapterID() == reference.AdapterID() {
				locality, err := provider.ClassifyServiceEndpoint(connection.Endpoint())
				if err != nil || locality != provider.ServiceEndpointLoopback || connection.Implementation() != "openai_responses" {
					return fail()
				}
				connections++
			}
		}
		if connections != 1 {
			return fail()
		}
	}
	// A synthetic local envelope establishes only startup readiness, never dispatch authority.
	scope, err := audit.NewReviewScope("local-preflight", "route-pair", "startup")
	if err != nil {
		return fail()
	}
	request, err := provider.NewRequest(provider.CapabilityReviewV1, "application/json", []byte(`{"preflight":true}`))
	if err != nil {
		return fail()
	}
	input, err := gateway.NewReviewRoutingInput(scope, request, configuration.Requirements(), configuration.Constraints())
	if err != nil {
		return fail()
	}
	eligible, err := gateway.FilterEligibleRoutes(input, configuration.Budget(), inventory.RegistryRevision(), []gateway.ObservedRouteCandidate{generation, verification})
	if err != nil || len(eligible.EligibleRoutes()) != 2 {
		return fail()
	}
	rankingPolicy, err := gateway.NewPinnedRouteRankingPolicy(pinned, nil)
	if err != nil {
		return fail()
	}
	generationEligibility, err := gateway.FilterEligibleRoutes(input, configuration.Budget(), inventory.RegistryRevision(), []gateway.ObservedRouteCandidate{generation})
	if err != nil {
		return fail()
	}
	ranked, err := gateway.RankEligibleRoutes(generationEligibility, rankingPolicy, inventory.PerformanceRevision(), []provider.RoutePerformanceObservation{generationObservation})
	if err != nil {
		return fail()
	}
	selection, err := gateway.NewRouteSelectionReceipt(generationEligibility, ranked)
	if err != nil {
		return fail()
	}
	authorization, err := gateway.NewInitialRouteAttemptAuthorization(request, selection, ranked)
	if err != nil || gateway.VerifyIndependentRouteCandidate(configuration.Independence(), authorization, verification) != nil {
		return fail()
	}
	value := LocalGenerationRoutePair{policyIdentity: configuration.Identity(), inventoryIdentity: inventory.Identity(), generationRecordIdentity: generation.ResolvedRecord().RouteRegistryRecord().Identity(), verificationRecordIdentity: verification.ResolvedRecord().RouteRegistryRecord().Identity(), generationRoute: pinned, verificationRoute: verification.ResolvedRecord().RouteRegistryRecord().RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference(), independence: configuration.Independence(), registryRevision: inventory.RegistryRevision(), performanceRevision: inventory.PerformanceRevision()}
	value.identity = localPairIdentity(value)
	if value.Validate() != nil {
		return fail()
	}
	return value, nil
}

// LocalGenerationRoutePlan exposes only identities for an unaudited decision.
// It is not dispatch authority; typed routing and attempt objects remain private
// until a separate audited grant enforces selection and claim prerequisites.
type LocalGenerationRoutePlan struct {
	routingInput                                    gateway.ReviewRoutingInput
	eligibility                                     gateway.RouteEligibilityResult
	ranking                                         gateway.RouteRankingResult
	selection                                       gateway.RouteSelectionReceipt
	authorization                                   gateway.RouteAttemptAuthorization
	policyIdentity, inventoryIdentity, pairIdentity string
	registryRevision, performanceRevision           uint64
}

func (p LocalGenerationRoutePlan) RequestIdentity() string { return p.routingInput.RequestIdentity() }
func (p LocalGenerationRoutePlan) RoutingInputIdentity() string {
	return p.selection.RoutingInputIdentity()
}
func (p LocalGenerationRoutePlan) SelectionIdentity() string { return p.selection.Identity() }
func (p LocalGenerationRoutePlan) RankingPolicyIdentity() string {
	return p.ranking.RankingPolicyIdentity()
}
func (p LocalGenerationRoutePlan) SelectedRecordIdentity() string {
	return p.selection.SelectedRecordIdentity()
}
func (p LocalGenerationRoutePlan) PolicyIdentity() string      { return p.policyIdentity }
func (p LocalGenerationRoutePlan) InventoryIdentity() string   { return p.inventoryIdentity }
func (p LocalGenerationRoutePlan) PairIdentity() string        { return p.pairIdentity }
func (p LocalGenerationRoutePlan) RegistryRevision() uint64    { return p.registryRevision }
func (p LocalGenerationRoutePlan) PerformanceRevision() uint64 { return p.performanceRevision }

// PlanLocalGenerationRoute checks the actual sanitized request against only the bound generation record.
// It neither writes a selection event nor grants independently usable dispatch authority.
func PlanLocalGenerationRoute(ctx context.Context, scope audit.ReviewScope, request provider.Request, configuration runtimeconfig.RuntimePolicy, inventory runtimeconfig.RouteInventory, pair LocalGenerationRoutePair) (LocalGenerationRoutePlan, error) {
	fail := func() (LocalGenerationRoutePlan, error) {
		return LocalGenerationRoutePlan{}, ErrInvalidLocalGenerationRoutePair
	}
	if ctx == nil || ctx.Err() != nil || scope.Validate() != nil || review.ValidateCandidateEgressRequest(request, scope.Identity()) != nil || configuration.Validate() != nil || inventory.Validate() != nil || configuration.ValidateAgainstInventory(inventory) != nil || pair.Validate() != nil || configuration.Identity() != pair.PolicyIdentity() || inventory.Identity() != pair.InventoryIdentity() || inventory.RegistryRevision() != pair.RegistryRevision() || inventory.PerformanceRevision() != pair.PerformanceRevision() {
		return fail()
	}
	current, err := ResolveLocalGenerationRoutePair(configuration, inventory)
	if err != nil || current != pair {
		return fail()
	}
	var candidate, verifier gateway.ObservedRouteCandidate
	var observation provider.RoutePerformanceObservation
	candidateCount, verifierCount, observationCount := 0, 0, 0
	for _, route := range inventory.Candidates() {
		record := route.ResolvedRecord().RouteRegistryRecord()
		if record.Identity() == pair.GenerationRecordIdentity() {
			candidate = route
			candidateCount++
			if record.RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference() != pair.GenerationRoute() || record.RouteCandidateDeclaration().ContentLoggingMode() != provider.ContentLoggingDisabled || pair.GenerationRoute().Zone() != provider.ProviderZoneLocal {
				return fail()
			}
		}
		if record.Identity() == pair.VerificationRecordIdentity() {
			verifier = route
			verifierCount++
		}
	}
	for _, value := range inventory.PerformanceObservations() {
		if value.RecordIdentity() == pair.GenerationRecordIdentity() {
			observation = value
			observationCount++
		}
	}
	if candidateCount != 1 || verifierCount != 1 || observationCount != 1 || observation.ObservationRevision() != pair.PerformanceRevision() || ctx.Err() != nil {
		return fail()
	}
	budget, err := review.ModelRequestBudget(request, configuration.Budget())
	if err != nil {
		return fail()
	}
	input, err := gateway.NewReviewRoutingInput(scope, request, configuration.Requirements(), configuration.Constraints())
	if err != nil {
		return fail()
	}
	verifierEligibility, err := gateway.FilterEligibleRoutes(input, budget, inventory.RegistryRevision(), []gateway.ObservedRouteCandidate{verifier})
	if err != nil || len(verifierEligibility.EligibleRoutes()) != 1 || len(verifierEligibility.RejectedRoutes()) != 0 {
		return fail()
	}
	eligibility, err := gateway.FilterEligibleRoutes(input, budget, inventory.RegistryRevision(), []gateway.ObservedRouteCandidate{candidate})
	if err != nil || len(eligibility.EligibleRoutes()) != 1 || len(eligibility.RejectedRoutes()) != 0 {
		return fail()
	}
	ranking, err := gateway.RankEligibleRoutes(eligibility, configuration.Ranking(), inventory.PerformanceRevision(), []provider.RoutePerformanceObservation{observation})
	if err != nil || len(ranking.RankedRoutes()) != 1 {
		return fail()
	}
	selection, err := gateway.NewRouteSelectionReceipt(eligibility, ranking)
	if err != nil || selection.SelectedRecordIdentity() != pair.GenerationRecordIdentity() {
		return fail()
	}
	authorization, err := gateway.NewInitialRouteAttemptAuthorization(request, selection, ranking)
	if err != nil || authorization.RouteRecordIdentity() != pair.GenerationRecordIdentity() || authorization.RouteReference() != pair.GenerationRoute() || authorization.ContentLoggingMode() != provider.ContentLoggingDisabled || authorization.Kind() != gateway.RouteAttemptInitial || authorization.AttemptOrdinal() != 1 || authorization.RouteAttemptOrdinal() != 1 || authorization.ReservedCostMicroUSD() != authorization.MaximumCost().MaximumCostMicroUSD() || ctx.Err() != nil {
		return fail()
	}
	return LocalGenerationRoutePlan{input, eligibility, ranking, selection, authorization, configuration.Identity(), inventory.Identity(), pair.Identity(), inventory.RegistryRevision(), inventory.PerformanceRevision()}, nil
}
