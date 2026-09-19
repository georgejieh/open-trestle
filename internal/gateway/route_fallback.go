package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/georgejieh/open-trestle/internal/provider"
)

const (
	maxRouteFallbacks       uint8 = 4
	maxRouteZoneTransitions       = 16
)

var (
	// ErrInvalidRouteFallbackReason identifies an unknown fallback outcome.
	ErrInvalidRouteFallbackReason = errors.New("invalid route fallback reason")
	// ErrInvalidRouteZoneTransition identifies a same-zone or otherwise malformed explicit transition.
	ErrInvalidRouteZoneTransition = errors.New("invalid route zone transition")
	// ErrInvalidRouteFallbackLimit identifies an unsupported fallback count.
	ErrInvalidRouteFallbackLimit = errors.New("invalid route fallback limit")
	// ErrTooManyRouteZoneTransitions identifies a policy beyond the transition bound.
	ErrTooManyRouteZoneTransitions = errors.New("too many route zone transitions")
	// ErrDuplicateRouteZoneTransition identifies a repeated directed transition.
	ErrDuplicateRouteZoneTransition = errors.New("duplicate route zone transition")
	// ErrInvalidRouteFallbackPolicyIdentity identifies a policy identity that does not match its fields.
	ErrInvalidRouteFallbackPolicyIdentity = errors.New("invalid route fallback policy identity")
	// ErrRouteFallbackSelectionMismatch identifies ranking data that does not match its selection receipt.
	ErrRouteFallbackSelectionMismatch = errors.New("route fallback selection mismatch")
	// ErrInvalidRouteFallbackAttempts identifies a malformed, repeated, or unknown attempt path.
	ErrInvalidRouteFallbackAttempts = errors.New("invalid route fallback attempts")
	// ErrInvalidRouteFallbackRemainingBudget identifies remaining cost outside the original hard cap.
	ErrInvalidRouteFallbackRemainingBudget = errors.New("invalid route fallback remaining budget")
	// ErrInvalidRouteFallbackDecision identifies inconsistent fallback decision fields.
	ErrInvalidRouteFallbackDecision = errors.New("invalid route fallback decision")
	// ErrInvalidRouteFallbackDecisionIdentity identifies a decision identity that does not match its fields.
	ErrInvalidRouteFallbackDecisionIdentity = errors.New("invalid route fallback decision identity")
)

// RouteFallbackReason identifies the stable outcome of fallback planning.
type RouteFallbackReason uint8

const (
	RouteFallbackSelected RouteFallbackReason = iota + 1
	RouteFallbackDisabled
	RouteFallbackLimitReached
	RouteFallbackNoCompatibleRoute
	RouteFallbackInsufficientBudget
	RouteFallbackUnsafeReplay
	RouteFallbackFailureNotEligible
)

// String returns the stable fallback token or an empty string for unknown values.
func (r RouteFallbackReason) String() string {
	switch r {
	case RouteFallbackSelected:
		return "fallback_selected"
	case RouteFallbackDisabled:
		return "fallback_disabled"
	case RouteFallbackLimitReached:
		return "fallback_limit_reached"
	case RouteFallbackNoCompatibleRoute:
		return "no_compatible_fallback"
	case RouteFallbackInsufficientBudget:
		return "insufficient_remaining_budget"
	case RouteFallbackUnsafeReplay:
		return "unsafe_replay"
	case RouteFallbackFailureNotEligible:
		return "failure_not_eligible"
	default:
		return ""
	}
}

// ParseRouteFallbackReason parses one exact stable fallback token.
func ParseRouteFallbackReason(value string) (RouteFallbackReason, error) {
	for candidate := RouteFallbackSelected; candidate <= RouteFallbackFailureNotEligible; candidate++ {
		if candidate.String() == value {
			return candidate, nil
		}
	}
	return 0, fmt.Errorf("parse route fallback reason: %w", ErrInvalidRouteFallbackReason)
}

// Validate verifies that the fallback reason is recognized.
func (r RouteFallbackReason) Validate() error {
	if r.String() == "" {
		return ErrInvalidRouteFallbackReason
	}
	return nil
}

// RouteZoneTransition is one explicit directed cross-zone fallback permission.
type RouteZoneTransition struct {
	from provider.ProviderZone
	to   provider.ProviderZone
}

// NewRouteZoneTransition creates a directed cross-zone transition.
func NewRouteZoneTransition(from, to provider.ProviderZone) (RouteZoneTransition, error) {
	transition := RouteZoneTransition{from: from, to: to}
	if err := transition.Validate(); err != nil {
		return RouteZoneTransition{}, err
	}
	return transition, nil
}

// From returns the source zone.
func (t RouteZoneTransition) From() provider.ProviderZone { return t.from }

// To returns the destination zone.
func (t RouteZoneTransition) To() provider.ProviderZone { return t.to }

// Validate verifies both zones and rejects redundant same-zone transitions.
func (t RouteZoneTransition) Validate() error {
	if t.from.String() == "" || t.to.String() == "" {
		return provider.ErrInvalidProviderZone
	}
	if t.from == t.to {
		return ErrInvalidRouteZoneTransition
	}
	return nil
}

// RouteFallbackPolicy binds an explicit route-change cap and directed cross-zone permissions.
type RouteFallbackPolicy struct {
	identity               string
	enabled                bool
	maxFallbacks           uint8
	allowedZoneTransitions []RouteZoneTransition
}

// NewRouteFallbackPolicy creates an enabled fallback policy.
func NewRouteFallbackPolicy(maxFallbacks uint8, transitions []RouteZoneTransition) (RouteFallbackPolicy, error) {
	if maxFallbacks == 0 || maxFallbacks > maxRouteFallbacks {
		return RouteFallbackPolicy{}, ErrInvalidRouteFallbackLimit
	}
	policy := RouteFallbackPolicy{enabled: true, maxFallbacks: maxFallbacks, allowedZoneTransitions: append([]RouteZoneTransition(nil), transitions...)}
	sort.Slice(policy.allowedZoneTransitions, func(i, j int) bool {
		if policy.allowedZoneTransitions[i].from != policy.allowedZoneTransitions[j].from {
			return policy.allowedZoneTransitions[i].from < policy.allowedZoneTransitions[j].from
		}
		return policy.allowedZoneTransitions[i].to < policy.allowedZoneTransitions[j].to
	})
	if err := validateRouteFallbackPolicyFields(policy); err != nil {
		return RouteFallbackPolicy{}, err
	}
	policy.identity = deriveRouteFallbackPolicyIdentity(policy)
	return policy, nil
}

// NewNoRouteFallbackPolicy creates the canonical disabled policy.
func NewNoRouteFallbackPolicy() RouteFallbackPolicy {
	policy := RouteFallbackPolicy{}
	policy.identity = deriveRouteFallbackPolicyIdentity(policy)
	return policy
}

// Identity returns the canonical SHA-256 policy identity.
func (p RouteFallbackPolicy) Identity() string { return p.identity }

// Enabled reports whether fallback is allowed.
func (p RouteFallbackPolicy) Enabled() bool { return p.enabled }

// MaxFallbacks returns the number of allowed route changes.
func (p RouteFallbackPolicy) MaxFallbacks() uint8 { return p.maxFallbacks }

// AllowedZoneTransitions returns a defensive copy of directed permissions.
func (p RouteFallbackPolicy) AllowedZoneTransitions() []RouteZoneTransition {
	if len(p.allowedZoneTransitions) == 0 {
		return nil
	}
	return append([]RouteZoneTransition(nil), p.allowedZoneTransitions...)
}

// AllowsZoneTransition reports whether two zones are equal or explicitly permitted in this direction.
func (p RouteFallbackPolicy) AllowsZoneTransition(from, to provider.ProviderZone) bool {
	if p.Validate() != nil || from.String() == "" || to.String() == "" {
		return false
	}
	if from == to {
		return true
	}
	for _, transition := range p.allowedZoneTransitions {
		if transition.from == from && transition.to == to {
			return true
		}
	}
	return false
}

// String returns a redacted fallback-policy description.
func (p RouteFallbackPolicy) String() string { return "route fallback policy" }

// GoString returns a redacted Go-syntax fallback-policy description.
func (p RouteFallbackPolicy) GoString() string { return "gateway.RouteFallbackPolicy{<redacted>}" }

// Format writes a redacted representation for verbs dispatched through fmt.Formatter.
func (p RouteFallbackPolicy) Format(state fmt.State, verb rune) {
	formatted := "route fallback policy"
	if verb == 'q' {
		formatted = `"route fallback policy"`
	} else if verb == 'v' && state.Flag('#') {
		formatted = "gateway.RouteFallbackPolicy{<redacted>}"
	}
	_, _ = state.Write([]byte(formatted))
}

// Validate verifies policy fields and their content-derived identity.
func (p RouteFallbackPolicy) Validate() error {
	if err := validateRouteFallbackPolicyFields(p); err != nil {
		return err
	}
	if p.identity != deriveRouteFallbackPolicyIdentity(p) {
		return ErrInvalidRouteFallbackPolicyIdentity
	}
	return nil
}

func validateRouteFallbackPolicyFields(policy RouteFallbackPolicy) error {
	if !policy.enabled {
		if policy.maxFallbacks != 0 || len(policy.allowedZoneTransitions) != 0 {
			return ErrInvalidRouteFallbackPolicyIdentity
		}
		return nil
	}
	if policy.maxFallbacks == 0 || policy.maxFallbacks > maxRouteFallbacks {
		return ErrInvalidRouteFallbackLimit
	}
	if len(policy.allowedZoneTransitions) > maxRouteZoneTransitions {
		return ErrTooManyRouteZoneTransitions
	}
	seen := make(map[RouteZoneTransition]struct{}, len(policy.allowedZoneTransitions))
	for _, transition := range policy.allowedZoneTransitions {
		if err := transition.Validate(); err != nil {
			return err
		}
		if _, exists := seen[transition]; exists {
			return ErrDuplicateRouteZoneTransition
		}
		seen[transition] = struct{}{}
	}
	return nil
}

func deriveRouteFallbackPolicyIdentity(policy RouteFallbackPolicy) string {
	type canonicalTransition struct {
		From string `json:"from"`
		To   string `json:"to"`
	}
	preimage := struct {
		Contract     string                `json:"contract"`
		Version      int                   `json:"version"`
		Enabled      bool                  `json:"enabled"`
		MaxFallbacks uint8                 `json:"max_fallbacks"`
		Transitions  []canonicalTransition `json:"zone_transitions"`
	}{Contract: "open-trestle/route-fallback-policy", Version: 1, Enabled: policy.enabled, MaxFallbacks: policy.maxFallbacks}
	if len(policy.allowedZoneTransitions) > 0 {
		preimage.Transitions = make([]canonicalTransition, len(policy.allowedZoneTransitions))
		for index, transition := range policy.allowedZoneTransitions {
			preimage.Transitions[index] = canonicalTransition{From: transition.from.String(), To: transition.to.String()}
		}
	}
	encoded, _ := json.Marshal(preimage)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

// RouteFallbackDecision is a content-addressed fallback selection or denial receipt.
type RouteFallbackDecision struct {
	identity                    string
	selectionReceiptIdentity    string
	fallbackPolicyIdentity      string
	requestIdentity             string
	registryRevision            uint64
	failure                     RouteFailureClass
	replaySafety                RouteReplaySafety
	attemptedRecordIdentities   []string
	fromRecordIdentity          string
	nextRecordIdentity          string
	reason                      RouteFallbackReason
	remainingCostBeforeMicroUSD uint64
	reservedCostMicroUSD        uint64
	remainingCostAfterMicroUSD  uint64
}

// Identity returns the canonical SHA-256 decision identity.
func (d RouteFallbackDecision) Identity() string { return d.identity }

// SelectionReceiptIdentity returns the bound initial selection receipt identity.
func (d RouteFallbackDecision) SelectionReceiptIdentity() string { return d.selectionReceiptIdentity }

// FallbackPolicyIdentity returns the bound fallback policy identity.
func (d RouteFallbackDecision) FallbackPolicyIdentity() string { return d.fallbackPolicyIdentity }

// RequestIdentity returns the bound request identity.
func (d RouteFallbackDecision) RequestIdentity() string { return d.requestIdentity }

// RegistryRevision returns the bound registry revision.
func (d RouteFallbackDecision) RegistryRevision() uint64 { return d.registryRevision }

// Failure returns the adapter-classified failure that prompted planning.
func (d RouteFallbackDecision) Failure() RouteFailureClass { return d.failure }

// ReplaySafety returns the effect replay guarantee used by planning.
func (d RouteFallbackDecision) ReplaySafety() RouteReplaySafety { return d.replaySafety }

// AttemptedRecordIdentities returns a defensive copy of the attempt path before this decision.
func (d RouteFallbackDecision) AttemptedRecordIdentities() []string {
	if len(d.attemptedRecordIdentities) == 0 {
		return nil
	}
	return append([]string(nil), d.attemptedRecordIdentities...)
}

// FromRecordIdentity returns the most recently attempted record.
func (d RouteFallbackDecision) FromRecordIdentity() string { return d.fromRecordIdentity }

// NextRecordIdentity returns the selected fallback record or an empty string for denial.
func (d RouteFallbackDecision) NextRecordIdentity() string { return d.nextRecordIdentity }

// Reason returns the stable planning outcome.
func (d RouteFallbackDecision) Reason() RouteFallbackReason { return d.reason }

// ShouldFallback reports whether a next route was selected.
func (d RouteFallbackDecision) ShouldFallback() bool { return d.reason == RouteFallbackSelected }

// RemainingCostBeforeMicroUSD returns the caller-supplied cumulative budget balance.
func (d RouteFallbackDecision) RemainingCostBeforeMicroUSD() uint64 {
	return d.remainingCostBeforeMicroUSD
}

// ReservedCostMicroUSD returns the pessimistic reservation for the selected fallback.
func (d RouteFallbackDecision) ReservedCostMicroUSD() uint64 { return d.reservedCostMicroUSD }

// RemainingCostAfterMicroUSD returns the balance after the reservation.
func (d RouteFallbackDecision) RemainingCostAfterMicroUSD() uint64 {
	return d.remainingCostAfterMicroUSD
}

// String returns a redacted fallback-decision description.
func (d RouteFallbackDecision) String() string { return "route fallback decision" }

// GoString returns a redacted Go-syntax fallback-decision description.
func (d RouteFallbackDecision) GoString() string {
	return "gateway.RouteFallbackDecision{<redacted>}"
}

// Format writes a redacted representation for verbs dispatched through fmt.Formatter.
func (d RouteFallbackDecision) Format(state fmt.State, verb rune) {
	formatted := "route fallback decision"
	if verb == 'q' {
		formatted = `"route fallback decision"`
	} else if verb == 'v' && state.Flag('#') {
		formatted = "gateway.RouteFallbackDecision{<redacted>}"
	}
	_, _ = state.Write([]byte(formatted))
}

// Validate verifies decision bindings, path, budget arithmetic, and content-derived identity.
func (d RouteFallbackDecision) Validate() error {
	if !validRequestIdentity(d.selectionReceiptIdentity) || !validRequestIdentity(d.fallbackPolicyIdentity) || !validRequestIdentity(d.requestIdentity) || d.registryRevision == 0 {
		return ErrInvalidRouteFallbackDecision
	}
	if err := d.failure.Validate(); err != nil {
		return err
	}
	if err := d.replaySafety.Validate(); err != nil {
		return err
	}
	if err := d.reason.Validate(); err != nil {
		return err
	}
	if len(d.attemptedRecordIdentities) == 0 || len(d.attemptedRecordIdentities) > int(maxRouteFallbacks)+1 {
		return ErrInvalidRouteFallbackAttempts
	}
	seen := make(map[string]struct{}, len(d.attemptedRecordIdentities)+1)
	for _, identity := range d.attemptedRecordIdentities {
		if !validRequestIdentity(identity) {
			return ErrInvalidRouteFallbackAttempts
		}
		if _, exists := seen[identity]; exists {
			return ErrInvalidRouteFallbackAttempts
		}
		seen[identity] = struct{}{}
	}
	if d.fromRecordIdentity != d.attemptedRecordIdentities[len(d.attemptedRecordIdentities)-1] {
		return ErrInvalidRouteFallbackDecision
	}
	if d.ShouldFallback() {
		if !validRequestIdentity(d.nextRecordIdentity) || d.nextRecordIdentity == d.fromRecordIdentity {
			return ErrInvalidRouteFallbackDecision
		}
		if _, exists := seen[d.nextRecordIdentity]; exists || d.reservedCostMicroUSD > d.remainingCostBeforeMicroUSD || d.remainingCostAfterMicroUSD != d.remainingCostBeforeMicroUSD-d.reservedCostMicroUSD {
			return ErrInvalidRouteFallbackDecision
		}
	} else if d.nextRecordIdentity != "" || d.reservedCostMicroUSD != 0 || d.remainingCostAfterMicroUSD != d.remainingCostBeforeMicroUSD {
		return ErrInvalidRouteFallbackDecision
	}
	if d.identity != deriveRouteFallbackDecisionIdentity(d) {
		return ErrInvalidRouteFallbackDecisionIdentity
	}
	return nil
}

// PlanRouteFallback selects the first safe, compatible, affordable untried route.
func planRouteFallback(selection RouteSelectionReceipt, ranking RouteRankingResult, fallbackPolicy RouteFallbackPolicy, failure RouteFailureClass, safety RouteReplaySafety, attemptedRecordIdentities []string, remainingCostMicroUSD uint64) (RouteFallbackDecision, error) {
	if err := selection.Validate(); err != nil {
		return RouteFallbackDecision{}, err
	}
	if err := ranking.Validate(); err != nil {
		return RouteFallbackDecision{}, err
	}
	if !fallbackSelectionMatchesRanking(selection, ranking) {
		return RouteFallbackDecision{}, ErrRouteFallbackSelectionMismatch
	}
	if err := fallbackPolicy.Validate(); err != nil {
		return RouteFallbackDecision{}, err
	}
	if err := failure.Validate(); err != nil {
		return RouteFallbackDecision{}, err
	}
	if err := safety.Validate(); err != nil {
		return RouteFallbackDecision{}, err
	}
	if remainingCostMicroUSD > selection.CostBudget().MaxCostMicroUSD() {
		return RouteFallbackDecision{}, ErrInvalidRouteFallbackRemainingBudget
	}
	rankedByIdentity := make(map[string]RankedRoute, len(ranking.rankedRoutes))
	for _, ranked := range ranking.rankedRoutes {
		rankedByIdentity[observedRouteIdentity(ranked.route)] = ranked
	}
	if len(attemptedRecordIdentities) == 0 || len(attemptedRecordIdentities) > len(ranking.rankedRoutes) || attemptedRecordIdentities[0] != selection.SelectedRecordIdentity() {
		return RouteFallbackDecision{}, ErrInvalidRouteFallbackAttempts
	}
	seen := make(map[string]struct{}, len(attemptedRecordIdentities))
	for _, identity := range attemptedRecordIdentities {
		if _, exists := rankedByIdentity[identity]; !exists {
			return RouteFallbackDecision{}, ErrInvalidRouteFallbackAttempts
		}
		if _, exists := seen[identity]; exists {
			return RouteFallbackDecision{}, ErrInvalidRouteFallbackAttempts
		}
		seen[identity] = struct{}{}
	}
	fromIdentity := attemptedRecordIdentities[len(attemptedRecordIdentities)-1]
	base := RouteFallbackDecision{
		selectionReceiptIdentity:    selection.Identity(),
		fallbackPolicyIdentity:      fallbackPolicy.Identity(),
		requestIdentity:             selection.RequestIdentity(),
		registryRevision:            selection.RegistryRevision(),
		failure:                     failure,
		replaySafety:                safety,
		attemptedRecordIdentities:   append([]string(nil), attemptedRecordIdentities...),
		fromRecordIdentity:          fromIdentity,
		remainingCostBeforeMicroUSD: remainingCostMicroUSD,
		remainingCostAfterMicroUSD:  remainingCostMicroUSD,
	}
	if !fallbackPolicy.Enabled() {
		return finalizeRouteFallbackDecision(base, RouteFallbackDisabled, RankedRoute{})
	}
	if len(attemptedRecordIdentities)-1 >= int(fallbackPolicy.MaxFallbacks()) {
		return finalizeRouteFallbackDecision(base, RouteFallbackLimitReached, RankedRoute{})
	}
	if !safety.permitsAutomaticRetry() {
		return finalizeRouteFallbackDecision(base, RouteFallbackUnsafeReplay, RankedRoute{})
	}
	if failure == RouteFailureCancelled || failure == RouteFailurePolicyDenied || failure == RouteFailureBudgetExhausted {
		return finalizeRouteFallbackDecision(base, RouteFallbackFailureNotEligible, RankedRoute{})
	}
	from := rankedByIdentity[fromIdentity]
	budgetBlocked := false
	for _, candidate := range ranking.rankedRoutes {
		identity := observedRouteIdentity(candidate.route)
		if _, attempted := seen[identity]; attempted {
			continue
		}
		if !fallbackRouteTransitionAllowed(fallbackPolicy, from.route, candidate.route) {
			continue
		}
		cost := candidate.maximumCost.MaximumCostMicroUSD()
		if cost > remainingCostMicroUSD {
			budgetBlocked = true
			continue
		}
		return finalizeRouteFallbackDecision(base, RouteFallbackSelected, candidate)
	}
	if budgetBlocked {
		return finalizeRouteFallbackDecision(base, RouteFallbackInsufficientBudget, RankedRoute{})
	}
	return finalizeRouteFallbackDecision(base, RouteFallbackNoCompatibleRoute, RankedRoute{})
}

func fallbackSelectionMatchesRanking(selection RouteSelectionReceipt, ranking RouteRankingResult) bool {
	if selection.RequestIdentity() != ranking.RequestIdentity() || selection.ReviewScopeIdentity() != ranking.ReviewScopeIdentity() || selection.RoutingInputIdentity() != ranking.RoutingInputIdentity() || selection.RegistryRevision() != ranking.RegistryRevision() || selection.PerformanceRevision() != ranking.PerformanceRevision() || selection.CostBudget() != ranking.CostBudget() || selection.RankingPolicyIdentity() != ranking.RankingPolicyIdentity() || selection.SelectedRecordIdentity() != observedRouteIdentity(ranking.rankedRoutes[0].route) {
		return false
	}
	scores := selection.CandidateScores()
	if len(scores) != len(ranking.rankedRoutes) {
		return false
	}
	for index, ranked := range ranking.rankedRoutes {
		score := scores[index]
		if score.RecordIdentity() != observedRouteIdentity(ranked.route) || score.OperationalRevision() != ranked.route.OperationalState().ObservationRevision() || score.Performance() != ranked.performance || score.IsPinned() != ranked.pinned || score.preferenceRank != ranked.preferenceRank || score.QualityTier() != ranked.QualityTier() || score.MaximumCost() != ranked.maximumCost {
			return false
		}
	}
	return true
}

func fallbackRouteTransitionAllowed(policy RouteFallbackPolicy, from, to ObservedRouteCandidate) bool {
	fromCandidate := from.ResolvedRecord().RouteRegistryRecord().RouteCandidateDeclaration()
	toCandidate := to.ResolvedRecord().RouteRegistryRecord().RouteCandidateDeclaration()
	if !policy.AllowsZoneTransition(fromCandidate.RouteCapabilityDeclaration().RouteReference().Zone(), toCandidate.RouteCapabilityDeclaration().RouteReference().Zone()) {
		return false
	}
	return fromCandidate.ContentLoggingMode() != provider.ContentLoggingDisabled || toCandidate.ContentLoggingMode() == provider.ContentLoggingDisabled
}

func finalizeRouteFallbackDecision(base RouteFallbackDecision, reason RouteFallbackReason, selected RankedRoute) (RouteFallbackDecision, error) {
	base.reason = reason
	if reason == RouteFallbackSelected {
		base.nextRecordIdentity = observedRouteIdentity(selected.route)
		base.reservedCostMicroUSD = selected.maximumCost.MaximumCostMicroUSD()
		base.remainingCostAfterMicroUSD = base.remainingCostBeforeMicroUSD - base.reservedCostMicroUSD
	}
	base.identity = deriveRouteFallbackDecisionIdentity(base)
	if err := base.Validate(); err != nil {
		return RouteFallbackDecision{}, err
	}
	return base, nil
}

func deriveRouteFallbackDecisionIdentity(decision RouteFallbackDecision) string {
	preimage := struct {
		Contract                    string   `json:"contract"`
		Version                     int      `json:"version"`
		SelectionReceiptIdentity    string   `json:"selection_receipt_identity"`
		FallbackPolicyIdentity      string   `json:"fallback_policy_identity"`
		RequestIdentity             string   `json:"request_identity"`
		RegistryRevision            uint64   `json:"registry_revision"`
		Failure                     string   `json:"failure"`
		ReplaySafety                string   `json:"replay_safety"`
		AttemptedRecordIdentities   []string `json:"attempted_record_identities"`
		FromRecordIdentity          string   `json:"from_record_identity"`
		NextRecordIdentity          string   `json:"next_record_identity"`
		Reason                      string   `json:"reason"`
		RemainingCostBeforeMicroUSD uint64   `json:"remaining_cost_before_micro_usd"`
		ReservedCostMicroUSD        uint64   `json:"reserved_cost_micro_usd"`
		RemainingCostAfterMicroUSD  uint64   `json:"remaining_cost_after_micro_usd"`
	}{
		Contract:                    "open-trestle/route-fallback-decision",
		Version:                     1,
		SelectionReceiptIdentity:    decision.selectionReceiptIdentity,
		FallbackPolicyIdentity:      decision.fallbackPolicyIdentity,
		RequestIdentity:             decision.requestIdentity,
		RegistryRevision:            decision.registryRevision,
		Failure:                     decision.failure.String(),
		ReplaySafety:                decision.replaySafety.String(),
		AttemptedRecordIdentities:   decision.attemptedRecordIdentities,
		FromRecordIdentity:          decision.fromRecordIdentity,
		NextRecordIdentity:          decision.nextRecordIdentity,
		Reason:                      decision.reason.String(),
		RemainingCostBeforeMicroUSD: decision.remainingCostBeforeMicroUSD,
		ReservedCostMicroUSD:        decision.reservedCostMicroUSD,
		RemainingCostAfterMicroUSD:  decision.remainingCostAfterMicroUSD,
	}
	encoded, _ := json.Marshal(preimage)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
