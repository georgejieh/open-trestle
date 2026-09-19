package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/georgejieh/open-trestle/internal/provider"
)

const (
	maxRouteAttemptOrdinal              uint8  = 25
	maxRouteAttemptDurationMilliseconds uint64 = 86_400_000
)

var (
	// ErrInvalidRouteAttemptKind identifies an unknown initial, retry, or fallback attempt.
	ErrInvalidRouteAttemptKind = errors.New("invalid route attempt kind")
	// ErrRouteAttemptRequestMismatch identifies request content that does not match the routing decision.
	ErrRouteAttemptRequestMismatch = errors.New("route attempt request mismatch")
	// ErrInvalidRouteAttemptAuthorization identifies inconsistent attempt fields.
	ErrInvalidRouteAttemptAuthorization = errors.New("invalid route attempt authorization")
	// ErrInvalidRouteAttemptAuthorizationIdentity identifies an authorization identity that does not match its fields.
	ErrInvalidRouteAttemptAuthorizationIdentity = errors.New("invalid route attempt authorization identity")
	// ErrInvalidRouteAttemptOutcomeStatus identifies an unknown terminal attempt state.
	ErrInvalidRouteAttemptOutcomeStatus = errors.New("invalid route attempt outcome status")
	// ErrInvalidRouteAttemptDuration identifies an attempt duration beyond the supported bound.
	ErrInvalidRouteAttemptDuration = errors.New("invalid route attempt duration")
	// ErrInvalidRouteAttemptOutcome identifies inconsistent terminal outcome fields.
	ErrInvalidRouteAttemptOutcome = errors.New("invalid route attempt outcome")
	// ErrInvalidRouteAttemptResponseIdentity identifies a missing or malformed successful response identity.
	ErrInvalidRouteAttemptResponseIdentity = errors.New("invalid route attempt response identity")
	// ErrInvalidRouteAttemptOutcomeIdentity identifies an outcome identity that does not match its fields.
	ErrInvalidRouteAttemptOutcomeIdentity = errors.New("invalid route attempt outcome identity")
	// ErrRouteAttemptOutcomeMismatch identifies an outcome produced for another authorization.
	ErrRouteAttemptOutcomeMismatch = errors.New("route attempt outcome mismatch")
)

// RouteAttemptKind identifies why an authorized provider attempt exists.
type RouteAttemptKind uint8

const (
	RouteAttemptInitial RouteAttemptKind = iota + 1
	RouteAttemptRetry
	RouteAttemptFallback
)

// String returns the stable attempt-kind token or an empty string for unknown values.
func (k RouteAttemptKind) String() string {
	switch k {
	case RouteAttemptInitial:
		return "initial"
	case RouteAttemptRetry:
		return "retry"
	case RouteAttemptFallback:
		return "fallback"
	default:
		return ""
	}
}

// ParseRouteAttemptKind parses one exact stable attempt-kind token.
func ParseRouteAttemptKind(value string) (RouteAttemptKind, error) {
	for candidate := RouteAttemptInitial; candidate <= RouteAttemptFallback; candidate++ {
		if candidate.String() == value {
			return candidate, nil
		}
	}
	return 0, fmt.Errorf("parse route attempt kind: %w", ErrInvalidRouteAttemptKind)
}

// Validate verifies that the attempt kind is recognized.
func (k RouteAttemptKind) Validate() error {
	if k.String() == "" {
		return ErrInvalidRouteAttemptKind
	}
	return nil
}

// RouteAttemptAuthorization is a content-addressed grant for one exact provider attempt.
type RouteAttemptAuthorization struct {
	identity                     string
	kind                         RouteAttemptKind
	reviewScopeIdentity          string
	requestIdentity              string
	selectionReceiptIdentity     string
	registryRevision             uint64
	routeRecordIdentity          string
	attemptOrdinal               uint8
	routeAttemptOrdinal          uint8
	previousOutcomeIdentity      string
	continuationDecisionIdentity string
	routeReference               provider.RouteReference
	contentLoggingMode           provider.ContentLoggingMode
	pricing                      provider.RoutePricing
	costBudget                   provider.ModelCostBudget
	maximumCost                  provider.RouteCostEstimate
	remainingCostBeforeMicroUSD  uint64
	reservedCostMicroUSD         uint64
	remainingCostAfterMicroUSD   uint64
}

// NewInitialRouteAttemptAuthorization authorizes only the first selected route and reserves its maximum cost.
func NewInitialRouteAttemptAuthorization(request provider.Request, selection RouteSelectionReceipt, ranking RouteRankingResult) (RouteAttemptAuthorization, error) {
	if err := request.Validate(); err != nil {
		return RouteAttemptAuthorization{}, err
	}
	if err := selection.Validate(); err != nil {
		return RouteAttemptAuthorization{}, err
	}
	if err := ranking.Validate(); err != nil {
		return RouteAttemptAuthorization{}, err
	}
	if !fallbackSelectionMatchesRanking(selection, ranking) {
		return RouteAttemptAuthorization{}, ErrRouteSelectionBindingMismatch
	}
	if request.Identity() != selection.RequestIdentity() {
		return RouteAttemptAuthorization{}, ErrRouteAttemptRequestMismatch
	}
	selected := ranking.rankedRoutes[0]
	candidate := selected.route.ResolvedRecord().RouteRegistryRecord().RouteCandidateDeclaration()
	maximum := selected.maximumCost.MaximumCostMicroUSD()
	authorization := RouteAttemptAuthorization{
		kind: RouteAttemptInitial, reviewScopeIdentity: selection.ReviewScopeIdentity(), requestIdentity: request.Identity(), selectionReceiptIdentity: selection.Identity(), registryRevision: selection.RegistryRevision(),
		routeRecordIdentity: observedRouteIdentity(selected.route), attemptOrdinal: 1, routeAttemptOrdinal: 1,
		routeReference: candidate.RouteCapabilityDeclaration().RouteReference(), contentLoggingMode: candidate.ContentLoggingMode(), pricing: candidate.RoutePricing(),
		costBudget: selection.CostBudget(), maximumCost: selected.maximumCost,
		remainingCostBeforeMicroUSD: selection.CostBudget().MaxCostMicroUSD(), reservedCostMicroUSD: maximum, remainingCostAfterMicroUSD: selection.CostBudget().MaxCostMicroUSD() - maximum,
	}
	authorization.identity = deriveRouteAttemptAuthorizationIdentity(authorization)
	if err := authorization.Validate(); err != nil {
		return RouteAttemptAuthorization{}, err
	}
	return authorization, nil
}

func (a RouteAttemptAuthorization) Identity() string            { return a.identity }
func (a RouteAttemptAuthorization) Kind() RouteAttemptKind      { return a.kind }
func (a RouteAttemptAuthorization) ReviewScopeIdentity() string { return a.reviewScopeIdentity }
func (a RouteAttemptAuthorization) RequestIdentity() string     { return a.requestIdentity }
func (a RouteAttemptAuthorization) SelectionReceiptIdentity() string {
	return a.selectionReceiptIdentity
}
func (a RouteAttemptAuthorization) RegistryRevision() uint64        { return a.registryRevision }
func (a RouteAttemptAuthorization) RouteRecordIdentity() string     { return a.routeRecordIdentity }
func (a RouteAttemptAuthorization) AttemptOrdinal() uint8           { return a.attemptOrdinal }
func (a RouteAttemptAuthorization) RouteAttemptOrdinal() uint8      { return a.routeAttemptOrdinal }
func (a RouteAttemptAuthorization) PreviousOutcomeIdentity() string { return a.previousOutcomeIdentity }
func (a RouteAttemptAuthorization) ContinuationDecisionIdentity() string {
	return a.continuationDecisionIdentity
}
func (a RouteAttemptAuthorization) RouteReference() provider.RouteReference { return a.routeReference }
func (a RouteAttemptAuthorization) ContentLoggingMode() provider.ContentLoggingMode {
	return a.contentLoggingMode
}
func (a RouteAttemptAuthorization) Pricing() provider.RoutePricing          { return a.pricing }
func (a RouteAttemptAuthorization) CostBudget() provider.ModelCostBudget    { return a.costBudget }
func (a RouteAttemptAuthorization) MaxOutputTokens() uint32                 { return a.costBudget.MaxOutputTokens() }
func (a RouteAttemptAuthorization) MaximumCost() provider.RouteCostEstimate { return a.maximumCost }
func (a RouteAttemptAuthorization) RemainingCostBeforeMicroUSD() uint64 {
	return a.remainingCostBeforeMicroUSD
}
func (a RouteAttemptAuthorization) ReservedCostMicroUSD() uint64 { return a.reservedCostMicroUSD }
func (a RouteAttemptAuthorization) RemainingCostAfterMicroUSD() uint64 {
	return a.remainingCostAfterMicroUSD
}
func (a RouteAttemptAuthorization) String() string { return "route attempt authorization" }
func (a RouteAttemptAuthorization) GoString() string {
	return "gateway.RouteAttemptAuthorization{<redacted>}"
}
func (a RouteAttemptAuthorization) Format(state fmt.State, verb rune) {
	formatted := "route attempt authorization"
	if verb == 'q' {
		formatted = `"route attempt authorization"`
	} else if verb == 'v' && state.Flag('#') {
		formatted = "gateway.RouteAttemptAuthorization{<redacted>}"
	}
	_, _ = state.Write([]byte(formatted))
}

// Validate verifies attempt lineage, route data, reservation arithmetic, and content-derived identity.
func (a RouteAttemptAuthorization) Validate() error {
	if err := a.kind.Validate(); err != nil {
		return err
	}
	if !validRequestIdentity(a.reviewScopeIdentity) || !validRequestIdentity(a.requestIdentity) || !validRequestIdentity(a.selectionReceiptIdentity) || !validRequestIdentity(a.routeRecordIdentity) || a.registryRevision == 0 {
		return ErrInvalidRouteAttemptAuthorization
	}
	if a.attemptOrdinal == 0 || a.attemptOrdinal > maxRouteAttemptOrdinal || a.routeAttemptOrdinal == 0 || a.routeAttemptOrdinal > maxRouteRetryAttempts {
		return ErrInvalidRouteAttemptAuthorization
	}
	if err := a.routeReference.Validate(); err != nil {
		return err
	}
	if err := a.contentLoggingMode.Validate(); err != nil {
		return err
	}
	if err := a.pricing.Validate(); err != nil {
		return err
	}
	if !a.pricing.IsKnown() {
		return provider.ErrUnknownRoutePricing
	}
	if err := a.costBudget.Validate(); err != nil {
		return err
	}
	if err := a.maximumCost.Validate(); err != nil {
		return err
	}
	expectedMaximumCost, err := provider.EstimateMaximumRouteCost(a.pricing, a.costBudget)
	if err != nil {
		return err
	}
	if a.maximumCost != expectedMaximumCost {
		return ErrInvalidRouteAttemptAuthorization
	}
	if a.reservedCostMicroUSD != a.maximumCost.MaximumCostMicroUSD() || a.reservedCostMicroUSD > a.remainingCostBeforeMicroUSD || a.remainingCostAfterMicroUSD != a.remainingCostBeforeMicroUSD-a.reservedCostMicroUSD {
		return ErrInvalidRouteAttemptAuthorization
	}
	switch a.kind {
	case RouteAttemptInitial:
		if a.attemptOrdinal != 1 || a.routeAttemptOrdinal != 1 || a.previousOutcomeIdentity != "" || a.continuationDecisionIdentity != "" || a.remainingCostBeforeMicroUSD != a.costBudget.MaxCostMicroUSD() {
			return ErrInvalidRouteAttemptAuthorization
		}
	case RouteAttemptRetry, RouteAttemptFallback:
		if a.attemptOrdinal < 2 || !validRequestIdentity(a.previousOutcomeIdentity) || !validRequestIdentity(a.continuationDecisionIdentity) {
			return ErrInvalidRouteAttemptAuthorization
		}
		if a.kind == RouteAttemptRetry && a.routeAttemptOrdinal < 2 || a.kind == RouteAttemptFallback && a.routeAttemptOrdinal != 1 {
			return ErrInvalidRouteAttemptAuthorization
		}
	}
	if a.identity != deriveRouteAttemptAuthorizationIdentity(a) {
		return ErrInvalidRouteAttemptAuthorizationIdentity
	}
	return nil
}

func deriveRouteAttemptAuthorizationIdentity(a RouteAttemptAuthorization) string {
	route := a.routeReference
	preimage := struct {
		Contract                     string `json:"contract"`
		Version                      int    `json:"version"`
		Kind                         string `json:"kind"`
		ReviewScopeIdentity          string `json:"review_scope_identity"`
		RequestIdentity              string `json:"request_identity"`
		SelectionReceiptIdentity     string `json:"selection_receipt_identity"`
		RegistryRevision             uint64 `json:"registry_revision"`
		RouteRecordIdentity          string `json:"route_record_identity"`
		AttemptOrdinal               uint8  `json:"attempt_ordinal"`
		RouteAttemptOrdinal          uint8  `json:"route_attempt_ordinal"`
		PreviousOutcomeIdentity      string `json:"previous_outcome_identity"`
		ContinuationDecisionIdentity string `json:"continuation_decision_identity"`
		Zone                         string `json:"zone"`
		ProviderID                   string `json:"provider_id"`
		AdapterID                    string `json:"adapter_id"`
		ConnectionID                 string `json:"connection_id"`
		ModelID                      string `json:"model_id"`
		ModelVersion                 string `json:"model_version"`
		ContentLogging               string `json:"content_logging"`
		InputPrice                   uint64 `json:"input_price"`
		OutputPrice                  uint64 `json:"output_price"`
		EstimatedInputTokens         uint32 `json:"estimated_input_tokens"`
		MaxOutputTokens              uint32 `json:"max_output_tokens"`
		CostCap                      uint64 `json:"cost_cap"`
		MaximumCost                  uint64 `json:"maximum_cost"`
		RemainingBefore              uint64 `json:"remaining_before"`
		Reserved                     uint64 `json:"reserved"`
		RemainingAfter               uint64 `json:"remaining_after"`
	}{
		Contract: "open-trestle/route-attempt-authorization", Version: 1,
		Kind: a.kind.String(), ReviewScopeIdentity: a.reviewScopeIdentity, RequestIdentity: a.requestIdentity,
		SelectionReceiptIdentity: a.selectionReceiptIdentity, RegistryRevision: a.registryRevision,
		RouteRecordIdentity: a.routeRecordIdentity, AttemptOrdinal: a.attemptOrdinal,
		RouteAttemptOrdinal: a.routeAttemptOrdinal, PreviousOutcomeIdentity: a.previousOutcomeIdentity,
		ContinuationDecisionIdentity: a.continuationDecisionIdentity, Zone: route.Zone().String(),
		ProviderID: route.ProviderID(), AdapterID: route.AdapterID(), ConnectionID: route.ConnectionID(),
		ModelID: route.ModelID(), ModelVersion: route.ModelVersion(), ContentLogging: a.contentLoggingMode.String(),
		InputPrice: a.pricing.InputMicroUSDPerMillionTokens(), OutputPrice: a.pricing.OutputMicroUSDPerMillionTokens(),
		EstimatedInputTokens: a.costBudget.EstimatedInputTokens(), MaxOutputTokens: a.costBudget.MaxOutputTokens(),
		CostCap: a.costBudget.MaxCostMicroUSD(), MaximumCost: a.maximumCost.MaximumCostMicroUSD(),
		RemainingBefore: a.remainingCostBeforeMicroUSD, Reserved: a.reservedCostMicroUSD,
		RemainingAfter: a.remainingCostAfterMicroUSD,
	}
	encoded, _ := json.Marshal(preimage)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

// RouteAttemptOutcomeStatus identifies whether one authorized attempt succeeded or failed.
type RouteAttemptOutcomeStatus uint8

const (
	RouteAttemptSucceeded RouteAttemptOutcomeStatus = iota + 1
	RouteAttemptFailed
)

func (s RouteAttemptOutcomeStatus) String() string {
	if s == RouteAttemptSucceeded {
		return "succeeded"
	}
	if s == RouteAttemptFailed {
		return "failed"
	}
	return ""
}
func ParseRouteAttemptOutcomeStatus(value string) (RouteAttemptOutcomeStatus, error) {
	for c := RouteAttemptSucceeded; c <= RouteAttemptFailed; c++ {
		if c.String() == value {
			return c, nil
		}
	}
	return 0, fmt.Errorf("parse route attempt outcome status: %w", ErrInvalidRouteAttemptOutcomeStatus)
}
func (s RouteAttemptOutcomeStatus) Validate() error {
	if s.String() == "" {
		return ErrInvalidRouteAttemptOutcomeStatus
	}
	return nil
}

// RouteAttemptOutcome is a content-addressed terminal result for one authorization.
type RouteAttemptOutcome struct {
	identity               string
	authorizationIdentity  string
	status                 RouteAttemptOutcomeStatus
	responseIdentity       string
	usage                  provider.RouteTokenUsage
	failure                RouteFailureClass
	replaySafety           RouteReplaySafety
	retryAfterMilliseconds uint32
	durationMilliseconds   uint64
}

// NewSuccessfulRouteAttemptOutcome records a terminal successful adapter result.
func NewSuccessfulRouteAttemptOutcome(authorization RouteAttemptAuthorization, responseIdentity string, usage provider.RouteTokenUsage, durationMilliseconds uint64) (RouteAttemptOutcome, error) {
	return newRouteAttemptOutcome(authorization, RouteAttemptSucceeded, responseIdentity, usage, 0, 0, 0, durationMilliseconds)
}

// NewFailedRouteAttemptOutcome records a terminal adapter failure using closed classifications.
func NewFailedRouteAttemptOutcome(authorization RouteAttemptAuthorization, failure RouteFailureClass, safety RouteReplaySafety, usage provider.RouteTokenUsage, retryAfterMilliseconds uint32, durationMilliseconds uint64) (RouteAttemptOutcome, error) {
	return newRouteAttemptOutcome(authorization, RouteAttemptFailed, "", usage, failure, safety, retryAfterMilliseconds, durationMilliseconds)
}
func newRouteAttemptOutcome(a RouteAttemptAuthorization, status RouteAttemptOutcomeStatus, responseIdentity string, usage provider.RouteTokenUsage, failure RouteFailureClass, safety RouteReplaySafety, retryAfter uint32, duration uint64) (RouteAttemptOutcome, error) {
	if err := a.Validate(); err != nil {
		return RouteAttemptOutcome{}, err
	}
	o := RouteAttemptOutcome{authorizationIdentity: a.Identity(), status: status, responseIdentity: responseIdentity, usage: usage, failure: failure, replaySafety: safety, retryAfterMilliseconds: retryAfter, durationMilliseconds: duration}
	if err := validateRouteAttemptOutcomeFields(o); err != nil {
		return RouteAttemptOutcome{}, err
	}
	o.identity = deriveRouteAttemptOutcomeIdentity(o)
	return o, nil
}
func (o RouteAttemptOutcome) Identity() string                  { return o.identity }
func (o RouteAttemptOutcome) AuthorizationIdentity() string     { return o.authorizationIdentity }
func (o RouteAttemptOutcome) Status() RouteAttemptOutcomeStatus { return o.status }
func (o RouteAttemptOutcome) ResponseIdentity() string          { return o.responseIdentity }
func (o RouteAttemptOutcome) Usage() provider.RouteTokenUsage   { return o.usage }
func (o RouteAttemptOutcome) Failure() RouteFailureClass        { return o.failure }
func (o RouteAttemptOutcome) ReplaySafety() RouteReplaySafety   { return o.replaySafety }
func (o RouteAttemptOutcome) RetryAfterMilliseconds() uint32    { return o.retryAfterMilliseconds }
func (o RouteAttemptOutcome) DurationMilliseconds() uint64      { return o.durationMilliseconds }
func (o RouteAttemptOutcome) String() string                    { return "route attempt outcome" }
func (o RouteAttemptOutcome) GoString() string                  { return "gateway.RouteAttemptOutcome{<redacted>}" }
func (o RouteAttemptOutcome) Format(state fmt.State, verb rune) {
	formatted := "route attempt outcome"
	if verb == 'q' {
		formatted = `"route attempt outcome"`
	} else if verb == 'v' && state.Flag('#') {
		formatted = "gateway.RouteAttemptOutcome{<redacted>}"
	}
	_, _ = state.Write([]byte(formatted))
}
func (o RouteAttemptOutcome) Validate() error {
	if err := validateRouteAttemptOutcomeFields(o); err != nil {
		return err
	}
	if o.identity != deriveRouteAttemptOutcomeIdentity(o) {
		return ErrInvalidRouteAttemptOutcomeIdentity
	}
	return nil
}
func validateRouteAttemptOutcomeFields(o RouteAttemptOutcome) error {
	if !validRequestIdentity(o.authorizationIdentity) {
		return ErrInvalidRouteAttemptOutcome
	}
	if err := o.status.Validate(); err != nil {
		return err
	}
	if err := o.usage.Validate(); err != nil {
		return err
	}
	if o.durationMilliseconds > maxRouteAttemptDurationMilliseconds {
		return ErrInvalidRouteAttemptDuration
	}
	if o.status == RouteAttemptSucceeded {
		if !validRequestIdentity(o.responseIdentity) {
			return ErrInvalidRouteAttemptResponseIdentity
		}
		if o.failure != 0 || o.replaySafety != 0 || o.retryAfterMilliseconds != 0 {
			return ErrInvalidRouteAttemptOutcome
		}
		return nil
	}
	if o.responseIdentity != "" {
		return ErrInvalidRouteAttemptOutcome
	}
	if err := o.failure.Validate(); err != nil {
		return err
	}
	if err := o.replaySafety.Validate(); err != nil {
		return err
	}
	if o.retryAfterMilliseconds != 0 && o.failure != RouteFailureRateLimited {
		return ErrInvalidRouteRetryAfter
	}
	return nil
}
func deriveRouteAttemptOutcomeIdentity(o RouteAttemptOutcome) string {
	preimage := struct {
		Contract              string `json:"contract"`
		Version               int    `json:"version"`
		AuthorizationIdentity string `json:"authorization_identity"`
		Status                string `json:"status"`
		ResponseIdentity      string `json:"response_identity"`
		UsageKnown            bool   `json:"usage_known"`
		InputTokens           uint32 `json:"input_tokens"`
		OutputTokens          uint32 `json:"output_tokens"`
		CachedInputTokens     uint32 `json:"cached_input_tokens"`
		Failure               string `json:"failure"`
		ReplaySafety          string `json:"replay_safety"`
		RetryAfter            uint32 `json:"retry_after_milliseconds"`
		Duration              uint64 `json:"duration_milliseconds"`
	}{
		Contract: "open-trestle/route-attempt-outcome", Version: 1,
		AuthorizationIdentity: o.authorizationIdentity, Status: o.status.String(), ResponseIdentity: o.responseIdentity,
		UsageKnown:  o.usage.IsKnown(),
		InputTokens: o.usage.InputTokens(), OutputTokens: o.usage.OutputTokens(), CachedInputTokens: o.usage.CachedInputTokens(),
		Failure: o.failure.String(), ReplaySafety: o.replaySafety.String(),
		RetryAfter: o.retryAfterMilliseconds, Duration: o.durationMilliseconds,
	}
	encoded, _ := json.Marshal(preimage)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
