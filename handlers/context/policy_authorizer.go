package context

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/policy"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
)

var ErrInvalidPolicyAuthorizer = errors.New("invalid context policy authorizer")

type PolicyAuthorizer struct {
	ledger                                audit.Ledger
	identity, policyIdentity              string
	requirements                          provider.ModelRequirements
	constraints                           policy.ProviderDataConstraints
	budget                                provider.ModelCostBudget
	registryRevision, performanceRevision uint64
	routes                                []gateway.ObservedRouteCandidate
	rankingPolicy                         gateway.RouteRankingPolicy
	observations                          []provider.RoutePerformanceObservation
}

func NewPolicyAuthorizer(policyIdentity string, requirements provider.ModelRequirements, constraints policy.ProviderDataConstraints, budget provider.ModelCostBudget, registryRevision uint64, routes []gateway.ObservedRouteCandidate, rankingPolicy gateway.RouteRankingPolicy, performanceRevision uint64, observations []provider.RoutePerformanceObservation, ledger audit.Ledger) (*PolicyAuthorizer, error) {
	a := &PolicyAuthorizer{ledger: ledger, policyIdentity: policyIdentity, requirements: requirements, constraints: constraints, budget: budget, registryRevision: registryRevision, routes: append([]gateway.ObservedRouteCandidate(nil), routes...), rankingPolicy: rankingPolicy, performanceRevision: performanceRevision, observations: append([]provider.RoutePerformanceObservation(nil), observations...)}
	sort.Slice(a.routes, func(i, j int) bool {
		return a.routes[i].ResolvedRecord().RouteRegistryRecord().Identity() < a.routes[j].ResolvedRecord().RouteRegistryRecord().Identity()
	})
	sort.Slice(a.observations, func(i, j int) bool { return a.observations[i].RecordIdentity() < a.observations[j].RecordIdentity() })
	if a.validateFields() != nil {
		return nil, ErrInvalidPolicyAuthorizer
	}
	a.identity = derivePolicyAuthorizerIdentity(a)
	return a, nil
}
func (a *PolicyAuthorizer) Identity() string {
	if a == nil {
		return ""
	}
	return a.identity
}
func (a *PolicyAuthorizer) Validate() error {
	if a == nil || a.validateFields() != nil || a.identity != derivePolicyAuthorizerIdentity(a) {
		return ErrInvalidPolicyAuthorizer
	}
	return nil
}
func (a *PolicyAuthorizer) validateFields() error {
	if nilInterface(a.ledger) || !validDigest(a.policyIdentity) || a.requirements.Validate() != nil || a.constraints.Validate() != nil || a.budget.Validate() != nil || a.registryRevision == 0 || a.performanceRevision == 0 || a.rankingPolicy.Validate() != nil || len(a.routes) == 0 || len(a.routes) > 256 || len(a.observations) != len(a.routes) {
		return ErrInvalidPolicyAuthorizer
	}
	previous := ""
	for _, route := range a.routes {
		id := route.ResolvedRecord().RouteRegistryRecord().Identity()
		if route.Validate() != nil || id <= previous || route.ResolvedRecord().RouteRegistryRecord().RegistryRevision() != a.registryRevision {
			return ErrInvalidPolicyAuthorizer
		}
		previous = id
	}
	previous = ""
	for index, observation := range a.observations {
		if observation.Validate() != nil || observation.RecordIdentity() <= previous || observation.ObservationRevision() != a.performanceRevision || observation.RecordIdentity() != a.routes[index].ResolvedRecord().RouteRegistryRecord().Identity() {
			return ErrInvalidPolicyAuthorizer
		}
		previous = observation.RecordIdentity()
	}
	return nil
}
func (a *PolicyAuthorizer) Authorize(ctx context.Context, scope audit.ReviewScope, request provider.Request, policyIdentity string, at time.Time) (gateway.RouteAttemptAuthorization, error) {
	if ctx == nil || ctx.Err() != nil || a.Validate() != nil || scope.Validate() != nil || request.Validate() != nil || policyIdentity != a.policyIdentity {
		return gateway.RouteAttemptAuthorization{}, ErrInvalidPolicyAuthorizer
	}
	if review.ValidateCandidateModelRequest(request, scope.Identity()) != nil {
		return gateway.RouteAttemptAuthorization{}, ErrInvalidPolicyAuthorizer
	}
	budget, err := review.ModelRequestBudget(request, a.budget)
	if err != nil {
		return gateway.RouteAttemptAuthorization{}, err
	}
	input, err := gateway.NewReviewRoutingInput(scope, request, a.requirements, a.constraints)
	if err != nil {
		return gateway.RouteAttemptAuthorization{}, err
	}
	eligibility, err := gateway.FilterEligibleRoutes(input, budget, a.registryRevision, a.routes)
	if err != nil {
		return gateway.RouteAttemptAuthorization{}, err
	}
	eligibleRecords := make(map[string]bool, len(eligibility.EligibleRoutes()))
	for _, candidate := range eligibility.EligibleRoutes() {
		eligibleRecords[candidate.ResolvedRecord().RouteRegistryRecord().Identity()] = true
	}
	observations := make([]provider.RoutePerformanceObservation, 0, len(eligibleRecords))
	for _, observation := range a.observations {
		if eligibleRecords[observation.RecordIdentity()] {
			observations = append(observations, observation)
		}
	}
	ranking, err := gateway.RankEligibleRoutes(eligibility, a.rankingPolicy, a.performanceRevision, observations)
	if err != nil {
		return gateway.RouteAttemptAuthorization{}, err
	}
	selection, err := gateway.NewRouteSelectionReceipt(eligibility, ranking)
	if err != nil {
		return gateway.RouteAttemptAuthorization{}, err
	}
	authorization, err := gateway.NewInitialRouteAttemptAuthorization(request, selection, ranking)
	if err != nil {
		return gateway.RouteAttemptAuthorization{}, err
	}
	if _, err := gateway.RecordRouteSelection(ctx, a.ledger, scope, selection, at); err != nil {
		return gateway.RouteAttemptAuthorization{}, err
	}
	return authorization, nil
}
func derivePolicyAuthorizerIdentity(a *PolicyAuthorizer) string {
	type routeWire struct {
		Record              string `json:"record"`
		OperationalRevision uint64 `json:"operational_revision"`
	}
	type observationWire struct {
		Record   string `json:"record"`
		Revision uint64 `json:"revision"`
		Known    bool   `json:"known"`
		P95      uint32 `json:"p95"`
		Samples  uint32 `json:"samples"`
	}
	routes := make([]routeWire, len(a.routes))
	for i, v := range a.routes {
		routes[i] = routeWire{v.ResolvedRecord().RouteRegistryRecord().Identity(), v.OperationalState().ObservationRevision()}
	}
	observations := make([]observationWire, len(a.observations))
	for i, v := range a.observations {
		observations[i] = observationWire{v.RecordIdentity(), v.ObservationRevision(), v.LatencyKnown(), v.P95LatencyMilliseconds(), v.SampleCount()}
	}
	features := a.requirements.RequiredFeatures()
	featureTokens := make([]string, len(features))
	for i, v := range features {
		featureTokens[i] = v.String()
	}
	zones := make([]string, 0, 4)
	allowed := a.constraints.AllowedProviderZones()
	for zone := provider.ProviderZoneLocal; zone <= provider.ProviderZoneSubscriptionOAuth; zone++ {
		if allowed.Allows(zone) {
			zones = append(zones, zone.String())
		}
	}
	encoded, _ := json.Marshal(struct {
		Contract             string            `json:"contract"`
		Version              int               `json:"version"`
		Policy               string            `json:"policy"`
		MinContext           uint32            `json:"min_context_tokens"`
		MinOutput            uint32            `json:"min_output_tokens"`
		Features             []string          `json:"features"`
		Classification       string            `json:"classification"`
		Zones                []string          `json:"zones"`
		Logging              bool              `json:"content_logging_allowed"`
		InputTokens          uint32            `json:"estimated_input_tokens"`
		InputEstimateVersion int               `json:"input_estimate_version"`
		MaxOutput            uint32            `json:"max_output_tokens"`
		Cost                 uint64            `json:"max_cost_micro_usd"`
		Registry             uint64            `json:"registry_revision"`
		Performance          uint64            `json:"performance_revision"`
		Ranking              string            `json:"ranking_policy"`
		Routes               []routeWire       `json:"routes"`
		Observations         []observationWire `json:"observations"`
	}{Contract: "open-trestle/context-policy-authorizer", Version: 3, InputEstimateVersion: review.ModelRequestBudgetVersion, Policy: a.policyIdentity, MinContext: a.requirements.MinContextTokens(), MinOutput: a.requirements.MinOutputTokens(), Features: featureTokens, Classification: string(a.constraints.Classification()), Zones: zones, Logging: a.constraints.ContentLoggingAllowed(), InputTokens: a.budget.EstimatedInputTokens(), MaxOutput: a.budget.MaxOutputTokens(), Cost: a.budget.MaxCostMicroUSD(), Registry: a.registryRevision, Performance: a.performanceRevision, Ranking: a.rankingPolicy.Identity(), Routes: routes, Observations: observations})
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

var _ GenerationAuthorizer = (*PolicyAuthorizer)(nil)
