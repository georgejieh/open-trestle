package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/georgejieh/open-trestle/internal/provider"
)

var (
	// ErrRouteSelectionBindingMismatch identifies eligibility and ranking results from different decisions.
	ErrRouteSelectionBindingMismatch = errors.New("route selection binding mismatch")
	// ErrInvalidRouteSelectionReceiptIdentity identifies a receipt identity that does not match its fields.
	ErrInvalidRouteSelectionReceiptIdentity = errors.New("invalid route selection receipt identity")
	// ErrInvalidRouteSelectionReceiptCandidates identifies malformed or noncanonical candidate scores.
	ErrInvalidRouteSelectionReceiptCandidates = errors.New("invalid route selection receipt candidates")
)

// RouteSelectionCandidateScore is a content-safe projection of one ranked route and its component scores.
type RouteSelectionCandidateScore struct {
	recordIdentity      string
	operationalRevision uint64
	performance         provider.RoutePerformanceObservation
	pinned              bool
	preferenceRank      uint8
	qualityTier         provider.RouteQualityTier
	maxContextTokens    uint32
	maxOutputTokens     uint32
	maximumCost         provider.RouteCostEstimate
}

// RecordIdentity returns the ranked registry-record identity.
func (s RouteSelectionCandidateScore) RecordIdentity() string { return s.recordIdentity }

// OperationalRevision returns the readiness observation revision used by eligibility.
func (s RouteSelectionCandidateScore) OperationalRevision() uint64 { return s.operationalRevision }

// Performance returns the exact-record latency observation used by ranking.
func (s RouteSelectionCandidateScore) Performance() provider.RoutePerformanceObservation {
	return s.performance
}

// IsPinned reports whether the route matched the exact pin.
func (s RouteSelectionCandidateScore) IsPinned() bool { return s.pinned }

// PreferenceRank returns the one-based preference position and whether one matched.
func (s RouteSelectionCandidateScore) PreferenceRank() (uint8, bool) {
	return s.preferenceRank, s.preferenceRank != 0
}

// QualityTier returns the registry-bound evaluated quality tier.
func (s RouteSelectionCandidateScore) QualityTier() provider.RouteQualityTier { return s.qualityTier }

// MaxContextTokens returns the approved total token capacity.
func (s RouteSelectionCandidateScore) MaxContextTokens() uint32 { return s.maxContextTokens }

// MaxOutputTokens returns the approved output token capacity.
func (s RouteSelectionCandidateScore) MaxOutputTokens() uint32 { return s.maxOutputTokens }

// MaximumCost returns the pessimistic request cost used by ranking.
func (s RouteSelectionCandidateScore) MaximumCost() provider.RouteCostEstimate { return s.maximumCost }

// String returns a redacted candidate-score description.
func (s RouteSelectionCandidateScore) String() string { return "route selection candidate score" }

// GoString returns a redacted Go-syntax candidate-score description.
func (s RouteSelectionCandidateScore) GoString() string {
	return "gateway.RouteSelectionCandidateScore{<redacted>}"
}

// Format writes a redacted representation for verbs dispatched through fmt.Formatter.
func (s RouteSelectionCandidateScore) Format(state fmt.State, verb rune) {
	formatted := "route selection candidate score"
	if verb == 'q' {
		formatted = `"route selection candidate score"`
	} else if verb == 'v' && state.Flag('#') {
		formatted = "gateway.RouteSelectionCandidateScore{<redacted>}"
	}
	_, _ = state.Write([]byte(formatted))
}

// RouteSelectionReceipt is a content-addressed, content-free routing audit record.
type RouteSelectionReceipt struct {
	identity               string
	requestIdentity        string
	reviewScopeIdentity    string
	routingInputIdentity   string
	registryRevision       uint64
	performanceRevision    uint64
	costBudget             provider.ModelCostBudget
	rankingPolicyIdentity  string
	selectedRecordIdentity string
	candidateScores        []RouteSelectionCandidateScore
	rejections             []RouteRejection
}

// NewRouteSelectionReceipt binds one eligibility result to its deterministic ranking.
func NewRouteSelectionReceipt(eligibility RouteEligibilityResult, ranking RouteRankingResult) (RouteSelectionReceipt, error) {
	if err := eligibility.Validate(); err != nil {
		return RouteSelectionReceipt{}, err
	}
	if err := ranking.Validate(); err != nil {
		return RouteSelectionReceipt{}, err
	}
	if eligibility.RequestIdentity() != ranking.RequestIdentity() || eligibility.ReviewScopeIdentity() != ranking.ReviewScopeIdentity() || eligibility.RoutingInputIdentity() != ranking.RoutingInputIdentity() || eligibility.RegistryRevision() != ranking.RegistryRevision() || eligibility.CostBudget() != ranking.CostBudget() {
		return RouteSelectionReceipt{}, ErrRouteSelectionBindingMismatch
	}
	eligible := eligibility.EligibleRoutes()
	if len(eligible) != len(ranking.rankedRoutes) {
		return RouteSelectionReceipt{}, ErrRouteSelectionBindingMismatch
	}
	eligibleIdentities := make(map[string]struct{}, len(eligible))
	for _, route := range eligible {
		eligibleIdentities[observedRouteIdentity(route)] = struct{}{}
	}
	scores := make([]RouteSelectionCandidateScore, len(ranking.rankedRoutes))
	for index, ranked := range ranking.rankedRoutes {
		identity := observedRouteIdentity(ranked.route)
		if _, exists := eligibleIdentities[identity]; !exists {
			return RouteSelectionReceipt{}, ErrRouteSelectionBindingMismatch
		}
		delete(eligibleIdentities, identity)
		scores[index] = RouteSelectionCandidateScore{
			recordIdentity:      identity,
			operationalRevision: ranked.route.OperationalState().ObservationRevision(),
			performance:         ranked.performance,
			pinned:              ranked.pinned,
			preferenceRank:      ranked.preferenceRank,
			qualityTier:         ranked.QualityTier(),
			maxContextTokens:    ranked.route.ResolvedRecord().RouteRegistryRecord().RouteCandidateDeclaration().RouteCapabilityDeclaration().ModelCapabilities().MaxContextTokens(),
			maxOutputTokens:     ranked.route.ResolvedRecord().RouteRegistryRecord().RouteCandidateDeclaration().RouteCapabilityDeclaration().ModelCapabilities().MaxOutputTokens(),
			maximumCost:         ranked.maximumCost,
		}
	}
	if len(eligibleIdentities) != 0 {
		return RouteSelectionReceipt{}, ErrRouteSelectionBindingMismatch
	}
	receipt := RouteSelectionReceipt{
		requestIdentity:        ranking.RequestIdentity(),
		reviewScopeIdentity:    ranking.ReviewScopeIdentity(),
		routingInputIdentity:   ranking.RoutingInputIdentity(),
		registryRevision:       ranking.RegistryRevision(),
		performanceRevision:    ranking.PerformanceRevision(),
		costBudget:             ranking.CostBudget(),
		rankingPolicyIdentity:  ranking.RankingPolicyIdentity(),
		selectedRecordIdentity: scores[0].recordIdentity,
		candidateScores:        scores,
		rejections:             eligibility.RejectedRoutes(),
	}
	identity, err := deriveRouteSelectionReceiptIdentity(receipt)
	if err != nil {
		return RouteSelectionReceipt{}, err
	}
	receipt.identity = identity
	if err := receipt.Validate(); err != nil {
		return RouteSelectionReceipt{}, err
	}
	return receipt, nil
}

// Identity returns the canonical SHA-256 receipt identity.
func (r RouteSelectionReceipt) Identity() string { return r.identity }

// RequestIdentity returns the request identity.
func (r RouteSelectionReceipt) RequestIdentity() string { return r.requestIdentity }

// ReviewScopeIdentity returns the tenant-owned review scope identity.
func (r RouteSelectionReceipt) ReviewScopeIdentity() string { return r.reviewScopeIdentity }

// RoutingInputIdentity returns the bound request, requirement, and policy input identity.
func (r RouteSelectionReceipt) RoutingInputIdentity() string { return r.routingInputIdentity }

// RegistryRevision returns the registry snapshot revision.
func (r RouteSelectionReceipt) RegistryRevision() uint64 { return r.registryRevision }

// PerformanceRevision returns the latency snapshot revision.
func (r RouteSelectionReceipt) PerformanceRevision() uint64 { return r.performanceRevision }

// CostBudget returns the hard budget used by eligibility and ranking.
func (r RouteSelectionReceipt) CostBudget() provider.ModelCostBudget { return r.costBudget }

// RankingPolicyIdentity returns the pin and preference policy identity.
func (r RouteSelectionReceipt) RankingPolicyIdentity() string { return r.rankingPolicyIdentity }

// SelectedRecordIdentity returns the first ranked record identity.
func (r RouteSelectionReceipt) SelectedRecordIdentity() string { return r.selectedRecordIdentity }

// CandidateScores returns a defensive copy in final selection order.
func (r RouteSelectionReceipt) CandidateScores() []RouteSelectionCandidateScore {
	if len(r.candidateScores) == 0 {
		return nil
	}
	return append([]RouteSelectionCandidateScore(nil), r.candidateScores...)
}

// Rejections returns a defensive copy in canonical record-identity order.
func (r RouteSelectionReceipt) Rejections() []RouteRejection {
	if len(r.rejections) == 0 {
		return nil
	}
	return append([]RouteRejection(nil), r.rejections...)
}

// String returns a redacted receipt description.
func (r RouteSelectionReceipt) String() string { return "route selection receipt" }

// GoString returns a redacted Go-syntax receipt description.
func (r RouteSelectionReceipt) GoString() string {
	return "gateway.RouteSelectionReceipt{<redacted>}"
}

// Format writes a redacted representation for verbs dispatched through fmt.Formatter.
func (r RouteSelectionReceipt) Format(state fmt.State, verb rune) {
	formatted := "route selection receipt"
	if verb == 'q' {
		formatted = `"route selection receipt"`
	} else if verb == 'v' && state.Flag('#') {
		formatted = "gateway.RouteSelectionReceipt{<redacted>}"
	}
	_, _ = state.Write([]byte(formatted))
}

// Validate verifies receipt fields, ordering, uniqueness, and content-derived identity.
func (r RouteSelectionReceipt) Validate() error {
	if !validRequestIdentity(r.requestIdentity) {
		return ErrInvalidRequestIdentity
	}
	if !validRequestIdentity(r.reviewScopeIdentity) {
		return ErrInvalidReviewRoutingInputIdentity
	}
	if !validRequestIdentity(r.routingInputIdentity) {
		return ErrInvalidReviewRoutingInputIdentity
	}
	if r.registryRevision == 0 {
		return ErrInvalidRouteFilterRevision
	}
	if r.performanceRevision == 0 {
		return provider.ErrInvalidRoutePerformanceRevision
	}
	if err := r.costBudget.Validate(); err != nil {
		return err
	}
	if !validRequestIdentity(r.rankingPolicyIdentity) {
		return ErrInvalidRouteRankingPolicyIdentity
	}
	if len(r.candidateScores) == 0 || len(r.candidateScores)+len(r.rejections) > maxRouteFilterCandidates {
		return ErrInvalidRouteSelectionReceiptCandidates
	}
	if r.selectedRecordIdentity != r.candidateScores[0].recordIdentity {
		return ErrInvalidRouteSelectionReceiptCandidates
	}
	seen := make(map[string]struct{}, len(r.candidateScores)+len(r.rejections))
	seenPreferenceRanks := make(map[uint8]struct{}, len(r.candidateScores))
	pinnedCount := 0
	for index, score := range r.candidateScores {
		if err := validateRouteSelectionCandidateScore(score, r.performanceRevision, r.costBudget); err != nil {
			return err
		}
		if _, exists := seen[score.recordIdentity]; exists {
			return ErrDuplicateRouteCandidate
		}
		seen[score.recordIdentity] = struct{}{}
		if score.pinned {
			pinnedCount++
		}
		if score.preferenceRank != 0 {
			if _, exists := seenPreferenceRanks[score.preferenceRank]; exists {
				return ErrInvalidRouteSelectionReceiptCandidates
			}
			seenPreferenceRanks[score.preferenceRank] = struct{}{}
		}
		if index > 0 && routeSelectionScoreLess(score, r.candidateScores[index-1]) {
			return ErrInvalidRouteSelectionReceiptCandidates
		}
	}
	if pinnedCount > 1 {
		return ErrInvalidRouteSelectionReceiptCandidates
	}
	previousRejection := ""
	for _, rejection := range r.rejections {
		if !validRequestIdentity(rejection.RecordIdentity()) || rejection.OperationalRevision() == 0 || rejection.Reason().Validate() != nil {
			return ErrInvalidRouteSelectionReceiptCandidates
		}
		if previousRejection != "" && rejection.RecordIdentity() <= previousRejection {
			return ErrInvalidRouteSelectionReceiptCandidates
		}
		if _, exists := seen[rejection.RecordIdentity()]; exists {
			return ErrDuplicateRouteCandidate
		}
		seen[rejection.RecordIdentity()] = struct{}{}
		previousRejection = rejection.RecordIdentity()
	}
	identity, err := deriveRouteSelectionReceiptIdentity(r)
	if err != nil {
		return err
	}
	if r.identity != identity {
		return ErrInvalidRouteSelectionReceiptIdentity
	}
	return nil
}

func validateRouteSelectionCandidateScore(score RouteSelectionCandidateScore, performanceRevision uint64, budget provider.ModelCostBudget) error {
	if !validRequestIdentity(score.recordIdentity) || score.operationalRevision == 0 {
		return ErrInvalidRouteSelectionReceiptCandidates
	}
	if err := score.performance.Validate(); err != nil {
		return err
	}
	if score.performance.RecordIdentity() != score.recordIdentity || score.performance.ObservationRevision() != performanceRevision {
		return ErrInvalidRouteSelectionReceiptCandidates
	}
	if score.pinned && score.preferenceRank != 0 || score.preferenceRank > maxRouteRankingPreferences {
		return ErrInvalidRouteSelectionReceiptCandidates
	}
	if err := score.qualityTier.Validate(); err != nil {
		return err
	}
	if score.maxContextTokens == 0 || score.maxOutputTokens == 0 || score.maxOutputTokens > score.maxContextTokens || budget.MaxOutputTokens() > score.maxOutputTokens || uint64(budget.EstimatedInputTokens())+uint64(budget.MaxOutputTokens()) > uint64(score.maxContextTokens) {
		return ErrInvalidRouteSelectionReceiptCandidates
	}
	if err := score.maximumCost.Validate(); err != nil {
		return err
	}
	if score.maximumCost.MaximumCostMicroUSD() > budget.MaxCostMicroUSD() {
		return ErrRouteCostExceedsBudget
	}
	return nil
}

func routeSelectionScoreLess(left, right RouteSelectionCandidateScore) bool {
	if left.pinned != right.pinned {
		return left.pinned
	}
	leftPreferred := left.preferenceRank != 0
	rightPreferred := right.preferenceRank != 0
	if leftPreferred != rightPreferred {
		return leftPreferred
	}
	if leftPreferred && left.preferenceRank != right.preferenceRank {
		return left.preferenceRank < right.preferenceRank
	}
	if left.qualityTier != right.qualityTier {
		return left.qualityTier > right.qualityTier
	}
	leftCost := left.maximumCost.MaximumCostMicroUSD()
	rightCost := right.maximumCost.MaximumCostMicroUSD()
	if leftCost != rightCost {
		return leftCost < rightCost
	}
	if left.performance.LatencyKnown() != right.performance.LatencyKnown() {
		return left.performance.LatencyKnown()
	}
	if left.performance.LatencyKnown() && left.performance.P95LatencyMilliseconds() != right.performance.P95LatencyMilliseconds() {
		return left.performance.P95LatencyMilliseconds() < right.performance.P95LatencyMilliseconds()
	}
	return left.recordIdentity < right.recordIdentity
}

type canonicalRouteSelectionScore struct {
	RecordIdentity         string `json:"record_identity"`
	OperationalRevision    uint64 `json:"operational_revision"`
	Pinned                 bool   `json:"pinned"`
	PreferenceRank         uint8  `json:"preference_rank"`
	QualityTier            string `json:"quality_tier"`
	MaxContextTokens       uint32 `json:"max_context_tokens"`
	MaxOutputTokens        uint32 `json:"max_output_tokens"`
	InputCostMicroUSD      uint64 `json:"input_cost_micro_usd"`
	OutputCostMicroUSD     uint64 `json:"output_cost_micro_usd"`
	MaximumCostMicroUSD    uint64 `json:"maximum_cost_micro_usd"`
	LatencyKnown           bool   `json:"latency_known"`
	P95LatencyMilliseconds uint32 `json:"p95_latency_milliseconds"`
	LatencySampleCount     uint32 `json:"latency_sample_count"`
}

type canonicalRouteSelectionRejection struct {
	RecordIdentity      string `json:"record_identity"`
	OperationalRevision uint64 `json:"operational_revision"`
	Reason              string `json:"reason"`
}

func deriveRouteSelectionReceiptIdentity(receipt RouteSelectionReceipt) (string, error) {
	preimage := struct {
		Contract               string                             `json:"contract"`
		Version                int                                `json:"version"`
		RequestIdentity        string                             `json:"request_identity"`
		ReviewScopeIdentity    string                             `json:"review_scope_identity"`
		RoutingInputIdentity   string                             `json:"routing_input_identity"`
		RegistryRevision       uint64                             `json:"registry_revision"`
		PerformanceRevision    uint64                             `json:"performance_revision"`
		EstimatedInputTokens   uint32                             `json:"estimated_input_tokens"`
		MaximumOutputTokens    uint32                             `json:"maximum_output_tokens"`
		MaximumCostMicroUSD    uint64                             `json:"maximum_cost_micro_usd"`
		RankingPolicyIdentity  string                             `json:"ranking_policy_identity"`
		SelectedRecordIdentity string                             `json:"selected_record_identity"`
		CandidateScores        []canonicalRouteSelectionScore     `json:"candidate_scores"`
		Rejections             []canonicalRouteSelectionRejection `json:"rejections"`
	}{
		Contract:               "open-trestle/route-selection-receipt",
		Version:                1,
		RequestIdentity:        receipt.requestIdentity,
		ReviewScopeIdentity:    receipt.reviewScopeIdentity,
		RoutingInputIdentity:   receipt.routingInputIdentity,
		RegistryRevision:       receipt.registryRevision,
		PerformanceRevision:    receipt.performanceRevision,
		EstimatedInputTokens:   receipt.costBudget.EstimatedInputTokens(),
		MaximumOutputTokens:    receipt.costBudget.MaxOutputTokens(),
		MaximumCostMicroUSD:    receipt.costBudget.MaxCostMicroUSD(),
		RankingPolicyIdentity:  receipt.rankingPolicyIdentity,
		SelectedRecordIdentity: receipt.selectedRecordIdentity,
		CandidateScores:        make([]canonicalRouteSelectionScore, len(receipt.candidateScores)),
		Rejections:             make([]canonicalRouteSelectionRejection, len(receipt.rejections)),
	}
	for index, score := range receipt.candidateScores {
		preimage.CandidateScores[index] = canonicalRouteSelectionScore{
			RecordIdentity:         score.recordIdentity,
			OperationalRevision:    score.operationalRevision,
			Pinned:                 score.pinned,
			PreferenceRank:         score.preferenceRank,
			QualityTier:            score.qualityTier.String(),
			MaxContextTokens:       score.maxContextTokens,
			MaxOutputTokens:        score.maxOutputTokens,
			InputCostMicroUSD:      score.maximumCost.InputCostMicroUSD(),
			OutputCostMicroUSD:     score.maximumCost.OutputCostMicroUSD(),
			MaximumCostMicroUSD:    score.maximumCost.MaximumCostMicroUSD(),
			LatencyKnown:           score.performance.LatencyKnown(),
			P95LatencyMilliseconds: score.performance.P95LatencyMilliseconds(),
			LatencySampleCount:     score.performance.SampleCount(),
		}
	}
	for index, rejection := range receipt.rejections {
		preimage.Rejections[index] = canonicalRouteSelectionRejection{RecordIdentity: rejection.RecordIdentity(), OperationalRevision: rejection.OperationalRevision(), Reason: rejection.Reason().String()}
	}
	encoded, err := json.Marshal(preimage)
	if err != nil {
		return "", fmt.Errorf("encode route selection receipt identity: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}
