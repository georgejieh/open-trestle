package model

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/policy"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
)

const maximumVerificationRoutes = 64

// VerificationRouteInventory supplies one bounded point-in-time approved route view.
type VerificationRouteInventory interface {
	Identity() string
	Snapshot(context.Context, audit.ReviewScope) (VerificationRouteSnapshot, error)
}

// VerificationRouteSnapshot binds registry and performance revisions to exact candidates.
type VerificationRouteSnapshot struct {
	identity                              string
	registryRevision, performanceRevision uint64
	routes                                []gateway.ObservedRouteCandidate
	observations                          []provider.RoutePerformanceObservation
}

// NewVerificationRouteSnapshot validates and canonicalizes one route inventory view.
func NewVerificationRouteSnapshot(registryRevision, performanceRevision uint64, routes []gateway.ObservedRouteCandidate, observations []provider.RoutePerformanceObservation) (VerificationRouteSnapshot, error) {
	snapshot := VerificationRouteSnapshot{registryRevision: registryRevision, performanceRevision: performanceRevision, routes: append([]gateway.ObservedRouteCandidate(nil), routes...), observations: append([]provider.RoutePerformanceObservation(nil), observations...)}
	sort.Slice(snapshot.routes, func(i, j int) bool {
		return verificationRouteRecordIdentity(snapshot.routes[i]) < verificationRouteRecordIdentity(snapshot.routes[j])
	})
	sort.Slice(snapshot.observations, func(i, j int) bool {
		return snapshot.observations[i].RecordIdentity() < snapshot.observations[j].RecordIdentity()
	})
	snapshot.identity = deriveVerificationRouteSnapshotIdentity(snapshot)
	if err := snapshot.Validate(); err != nil {
		return VerificationRouteSnapshot{}, err
	}
	return snapshot, nil
}
func (s VerificationRouteSnapshot) Identity() string            { return s.identity }
func (s VerificationRouteSnapshot) RegistryRevision() uint64    { return s.registryRevision }
func (s VerificationRouteSnapshot) PerformanceRevision() uint64 { return s.performanceRevision }
func (s VerificationRouteSnapshot) Routes() []gateway.ObservedRouteCandidate {
	return append([]gateway.ObservedRouteCandidate(nil), s.routes...)
}
func (s VerificationRouteSnapshot) Observations() []provider.RoutePerformanceObservation {
	return append([]provider.RoutePerformanceObservation(nil), s.observations...)
}
func (s VerificationRouteSnapshot) Validate() error {
	if s.registryRevision == 0 || s.performanceRevision == 0 || len(s.routes) > maximumVerificationRoutes || len(s.observations) != len(s.routes) {
		return ErrInvalidVerificationAuthority
	}
	for index, route := range s.routes {
		if route.Validate() != nil {
			return ErrInvalidVerificationAuthority
		}
		record := route.ResolvedRecord().RouteRegistryRecord()
		observation := s.observations[index]
		if record.RegistryRevision() != s.registryRevision || observation.Validate() != nil || observation.RecordIdentity() != record.Identity() || observation.ObservationRevision() != s.performanceRevision || index > 0 && verificationRouteRecordIdentity(s.routes[index-1]) >= record.Identity() {
			return ErrInvalidVerificationAuthority
		}
	}
	if s.identity != deriveVerificationRouteSnapshotIdentity(s) {
		return ErrInvalidVerificationAuthority
	}
	return nil
}
func verificationRouteRecordIdentity(route gateway.ObservedRouteCandidate) string {
	return route.ResolvedRecord().RouteRegistryRecord().Identity()
}
func deriveVerificationRouteSnapshotIdentity(snapshot VerificationRouteSnapshot) string {
	routes := make([]string, len(snapshot.routes))
	observations := make([]string, len(snapshot.observations))
	for i, route := range snapshot.routes {
		routes[i] = verificationRouteRecordIdentity(route)
	}
	for i, observation := range snapshot.observations {
		observations[i] = verificationPerformanceIdentity(observation)
	}
	encoded, err := json.Marshal(struct {
		Contract            string   `json:"contract"`
		SchemaVersion       int      `json:"schema_version"`
		RegistryRevision    uint64   `json:"registry_revision"`
		PerformanceRevision uint64   `json:"performance_revision"`
		Routes              []string `json:"routes"`
		Observations        []string `json:"observations"`
	}{"open-trestle/verification-route-snapshot", 1, snapshot.registryRevision, snapshot.performanceRevision, routes, observations})
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
func verificationPerformanceIdentity(value provider.RoutePerformanceObservation) string {
	encoded, err := json.Marshal(struct {
		Record   string `json:"record"`
		Revision uint64 `json:"revision"`
		Known    bool   `json:"known"`
		Latency  uint32 `json:"latency"`
		Samples  uint32 `json:"samples"`
	}{value.RecordIdentity(), value.ObservationRevision(), value.LatencyKnown(), value.P95LatencyMilliseconds(), value.SampleCount()})
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
func (s VerificationRouteSnapshot) String() string { return "verification route snapshot" }
func (s VerificationRouteSnapshot) GoString() string {
	return "model.VerificationRouteSnapshot{<redacted>}"
}
func (s VerificationRouteSnapshot) Format(state fmt.State, verb rune) {
	writeModelRedacted(state, verb, "verification route snapshot", "model.VerificationRouteSnapshot{<redacted>}")
}

// PolicyVerificationAuthorizer selects a privacy-filtered independent route and audits selection.
type PolicyVerificationAuthorizer struct {
	identity     string
	inventory    VerificationRouteInventory
	requirements provider.ModelRequirements
	constraints  policy.ProviderDataConstraints
	budget       provider.ModelCostBudget
	ranking      gateway.RouteRankingPolicy
	independence gateway.RouteIndependencePolicy
	ledger       audit.Ledger
	clock        artifact.Clock
}

// NewPolicyVerificationAuthorizer binds exact route policy, inventory, accounting, and audit inputs.
func NewPolicyVerificationAuthorizer(inventory VerificationRouteInventory, requirements provider.ModelRequirements, constraints policy.ProviderDataConstraints, budget provider.ModelCostBudget, ranking gateway.RouteRankingPolicy, independence gateway.RouteIndependencePolicy, ledger audit.Ledger, clock artifact.Clock) (*PolicyVerificationAuthorizer, error) {
	if nilInterface(inventory) || !validDigest(inventory.Identity()) || requirements.Validate() != nil || constraints.Validate() != nil || budget.Validate() != nil || ranking.Validate() != nil || independence.Validate() != nil || nilInterface(ledger) || nilInterface(clock) {
		return nil, ErrInvalidVerificationAuthority
	}
	a := &PolicyVerificationAuthorizer{inventory: inventory, requirements: requirements, constraints: constraints, budget: budget, ranking: ranking, independence: independence, ledger: ledger, clock: clock}
	a.identity = derivePolicyVerificationAuthorizerIdentity(a)
	if a.Validate() != nil {
		return nil, ErrInvalidVerificationAuthority
	}
	return a, nil
}
func (a *PolicyVerificationAuthorizer) Identity() string {
	if a == nil {
		return ""
	}
	return a.identity
}
func (a *PolicyVerificationAuthorizer) Validate() error {
	if a == nil || nilInterface(a.inventory) || !validDigest(a.inventory.Identity()) || a.requirements.Validate() != nil || a.constraints.Validate() != nil || a.budget.Validate() != nil || a.ranking.Validate() != nil || a.independence.Validate() != nil || nilInterface(a.ledger) || nilInterface(a.clock) || a.identity != derivePolicyVerificationAuthorizerIdentity(a) {
		return ErrInvalidVerificationAuthority
	}
	return nil
}
func (a *PolicyVerificationAuthorizer) Authorize(ctx context.Context, scope audit.ReviewScope, request provider.Request, generation gateway.RouteExecutionRecord) (VerificationAuthority, error) {
	if a.Validate() != nil || ctx == nil || ctx.Err() != nil || scope.Validate() != nil || request.Validate() != nil || generation.Validate() != nil || generation.Authorization().ReviewScopeIdentity() != scope.Identity() {
		return VerificationAuthority{}, ErrInvalidVerificationAuthority
	}
	if review.ValidateVerificationModelRequest(request, scope.Identity()) != nil {
		return VerificationAuthority{}, ErrInvalidVerificationAuthority
	}
	budget, err := review.ModelRequestBudget(request, a.budget)
	if err != nil {
		return VerificationAuthority{}, ErrInvalidVerificationAuthority
	}
	snapshot, err := a.inventory.Snapshot(ctx, scope)
	if err != nil {
		return VerificationAuthority{}, ErrVerificationAuthorizationUnavailable
	}
	if snapshot.Validate() != nil {
		return VerificationAuthority{}, ErrInvalidVerificationAuthority
	}
	independent := make([]gateway.ObservedRouteCandidate, 0, len(snapshot.routes))
	for _, route := range snapshot.routes {
		if gateway.VerifyIndependentRouteCandidate(a.independence, generation.Authorization(), route) == nil {
			independent = append(independent, route)
		}
	}
	if len(independent) == 0 {
		return VerificationAuthority{}, ErrInvalidVerificationAuthority
	}
	routing, err := gateway.NewReviewRoutingInput(scope, request, a.requirements, a.constraints)
	if err != nil {
		return VerificationAuthority{}, ErrInvalidVerificationAuthority
	}
	eligibility, err := gateway.FilterEligibleRoutes(routing, budget, snapshot.registryRevision, independent)
	if err != nil {
		return VerificationAuthority{}, ErrInvalidVerificationAuthority
	}
	eligibleIDs := make(map[string]struct{})
	for _, route := range eligibility.EligibleRoutes() {
		eligibleIDs[verificationRouteRecordIdentity(route)] = struct{}{}
	}
	observations := make([]provider.RoutePerformanceObservation, 0, len(eligibleIDs))
	for _, observation := range snapshot.observations {
		if _, ok := eligibleIDs[observation.RecordIdentity()]; ok {
			observations = append(observations, observation)
		}
	}
	if len(observations) == 0 {
		return VerificationAuthority{}, ErrInvalidVerificationAuthority
	}
	ranking, err := gateway.RankEligibleRoutes(eligibility, a.ranking, snapshot.performanceRevision, observations)
	if err != nil {
		return VerificationAuthority{}, ErrInvalidVerificationAuthority
	}
	selection, err := gateway.NewRouteSelectionReceipt(eligibility, ranking)
	if err != nil {
		return VerificationAuthority{}, ErrInvalidVerificationAuthority
	}
	authorization, err := gateway.NewInitialRouteAttemptAuthorization(request, selection, ranking)
	if err != nil || gateway.VerifyIndependentRouteAuthorizations(a.independence, generation.Authorization(), authorization) != nil {
		return VerificationAuthority{}, ErrInvalidVerificationAuthority
	}
	at := a.clock.Now().UTC()
	if at.UnixMilli() <= 0 {
		return VerificationAuthority{}, ErrVerificationAuthorizationUnavailable
	}
	if _, err := gateway.RecordRouteSelection(ctx, a.ledger, scope, selection, at); err != nil {
		return VerificationAuthority{}, ErrVerificationAuthorizationUnavailable
	}
	return NewVerificationAuthority(request, generation, authorization, a.independence)
}
func derivePolicyVerificationAuthorizerIdentity(a *PolicyVerificationAuthorizer) string {
	if a == nil {
		return ""
	}
	features := make([]string, 0)
	for _, feature := range a.requirements.RequiredFeatures() {
		features = append(features, feature.String())
	}
	zones := make([]string, 0)
	for zone := provider.ProviderZoneLocal; zone <= provider.ProviderZoneSubscriptionOAuth; zone++ {
		if a.constraints.AllowedProviderZones().Allows(zone) {
			zones = append(zones, zone.String())
		}
	}
	encoded, err := json.Marshal(struct {
		Contract             string   `json:"contract"`
		SchemaVersion        int      `json:"schema_version"`
		Inventory            string   `json:"inventory"`
		MinContext           uint32   `json:"min_context"`
		MinOutput            uint32   `json:"min_output"`
		Features             []string `json:"features"`
		Classification       string   `json:"classification"`
		Zones                []string `json:"zones"`
		Logging              bool     `json:"logging"`
		EstimatedInput       uint32   `json:"estimated_input"`
		InputEstimateVersion int      `json:"input_estimate_version"`
		MaxOutput            uint32   `json:"max_output"`
		MaxCost              uint64   `json:"max_cost"`
		Ranking              string   `json:"ranking"`
		Independence         string   `json:"independence"`
	}{"open-trestle/policy-verification-authorizer", 2, a.inventory.Identity(), a.requirements.MinContextTokens(), a.requirements.MinOutputTokens(), features, string(a.constraints.Classification()), zones, a.constraints.ContentLoggingAllowed(), a.budget.EstimatedInputTokens(), review.ModelRequestBudgetVersion, a.budget.MaxOutputTokens(), a.budget.MaxCostMicroUSD(), a.ranking.Identity(), a.independence.Identity()})
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
func (a *PolicyVerificationAuthorizer) String() string { return "policy verification authorizer" }
func (a *PolicyVerificationAuthorizer) GoString() string {
	return "model.PolicyVerificationAuthorizer{<redacted>}"
}
func (a *PolicyVerificationAuthorizer) Format(state fmt.State, verb rune) {
	writeModelRedacted(state, verb, "policy verification authorizer", "model.PolicyVerificationAuthorizer{<redacted>}")
}

var _ VerificationAuthorizer = (*PolicyVerificationAuthorizer)(nil)
