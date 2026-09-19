package gateway

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/georgejieh/open-trestle/internal/provider"
)

const maximumRouteRecordEncodingBytes = 64 << 10

var (
	// ErrInvalidRouteAttemptAuthorizationEncoding identifies malformed or noncanonical durable authority.
	ErrInvalidRouteAttemptAuthorizationEncoding = errors.New("invalid route attempt authorization encoding")
	// ErrInvalidRouteExecutionRecord identifies cross-wired successful route records.
	ErrInvalidRouteExecutionRecord = errors.New("invalid route execution record")
	// ErrInvalidRouteExecutionRecordEncoding identifies malformed or noncanonical durable execution records.
	ErrInvalidRouteExecutionRecordEncoding = errors.New("invalid route execution record encoding")
)

type routeAuthorizationWire struct {
	Contract                     string `json:"contract"`
	SchemaVersion                int    `json:"schema_version"`
	Identity                     string `json:"identity"`
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
	InputPrice                   uint64 `json:"input_price_micro_usd_per_million_tokens"`
	OutputPrice                  uint64 `json:"output_price_micro_usd_per_million_tokens"`
	EstimatedInputTokens         uint32 `json:"estimated_input_tokens"`
	MaxOutputTokens              uint32 `json:"max_output_tokens"`
	CostCap                      uint64 `json:"cost_cap_micro_usd"`
	MaximumCost                  uint64 `json:"maximum_cost_micro_usd"`
	RemainingBefore              uint64 `json:"remaining_before_micro_usd"`
	Reserved                     uint64 `json:"reserved_micro_usd"`
	RemainingAfter               uint64 `json:"remaining_after_micro_usd"`
}

// EncodeRouteAttemptAuthorization returns the canonical durable authority representation.
func EncodeRouteAttemptAuthorization(authorization RouteAttemptAuthorization) ([]byte, error) {
	if err := authorization.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(routeAuthorizationWireValue(authorization))
	if err != nil || len(encoded) > maximumRouteRecordEncodingBytes {
		return nil, ErrInvalidRouteAttemptAuthorizationEncoding
	}
	return encoded, nil
}

// ParseRouteAttemptAuthorization accepts only the canonical durable authority representation.
func ParseRouteAttemptAuthorization(encoded []byte) (RouteAttemptAuthorization, error) {
	if len(encoded) == 0 || len(encoded) > maximumRouteRecordEncodingBytes {
		return RouteAttemptAuthorization{}, ErrInvalidRouteAttemptAuthorizationEncoding
	}
	var wire routeAuthorizationWire
	if decodeCanonicalRouteRecord(encoded, &wire) != nil {
		return RouteAttemptAuthorization{}, ErrInvalidRouteAttemptAuthorizationEncoding
	}
	authorization, err := parseRouteAuthorizationWire(wire)
	if err != nil {
		return RouteAttemptAuthorization{}, ErrInvalidRouteAttemptAuthorizationEncoding
	}
	reencoded, err := EncodeRouteAttemptAuthorization(authorization)
	if err != nil || !bytes.Equal(reencoded, encoded) {
		return RouteAttemptAuthorization{}, ErrInvalidRouteAttemptAuthorizationEncoding
	}
	return authorization, nil
}

func routeAuthorizationWireValue(authorization RouteAttemptAuthorization) routeAuthorizationWire {
	route := authorization.RouteReference()
	pricing := authorization.Pricing()
	budget := authorization.CostBudget()
	return routeAuthorizationWire{
		Contract: "open-trestle/route-attempt-authorization", SchemaVersion: 1,
		Identity: authorization.Identity(), Kind: authorization.Kind().String(),
		ReviewScopeIdentity: authorization.ReviewScopeIdentity(), RequestIdentity: authorization.RequestIdentity(),
		SelectionReceiptIdentity: authorization.SelectionReceiptIdentity(), RegistryRevision: authorization.RegistryRevision(),
		RouteRecordIdentity: authorization.RouteRecordIdentity(), AttemptOrdinal: authorization.AttemptOrdinal(),
		RouteAttemptOrdinal: authorization.RouteAttemptOrdinal(), PreviousOutcomeIdentity: authorization.PreviousOutcomeIdentity(),
		ContinuationDecisionIdentity: authorization.ContinuationDecisionIdentity(), Zone: route.Zone().String(),
		ProviderID: route.ProviderID(), AdapterID: route.AdapterID(), ConnectionID: route.ConnectionID(),
		ModelID: route.ModelID(), ModelVersion: route.ModelVersion(), ContentLogging: authorization.ContentLoggingMode().String(),
		InputPrice: pricing.InputMicroUSDPerMillionTokens(), OutputPrice: pricing.OutputMicroUSDPerMillionTokens(),
		EstimatedInputTokens: budget.EstimatedInputTokens(), MaxOutputTokens: budget.MaxOutputTokens(),
		CostCap: budget.MaxCostMicroUSD(), MaximumCost: authorization.MaximumCost().MaximumCostMicroUSD(),
		RemainingBefore: authorization.RemainingCostBeforeMicroUSD(), Reserved: authorization.ReservedCostMicroUSD(),
		RemainingAfter: authorization.RemainingCostAfterMicroUSD(),
	}
}

func parseRouteAuthorizationWire(wire routeAuthorizationWire) (RouteAttemptAuthorization, error) {
	if wire.Contract != "open-trestle/route-attempt-authorization" || wire.SchemaVersion != 1 {
		return RouteAttemptAuthorization{}, ErrInvalidRouteAttemptAuthorizationEncoding
	}
	kind, err := ParseRouteAttemptKind(wire.Kind)
	if err != nil {
		return RouteAttemptAuthorization{}, err
	}
	zone, err := provider.ParseProviderZone(wire.Zone)
	if err != nil {
		return RouteAttemptAuthorization{}, err
	}
	route, err := provider.NewRouteReference(
		zone, wire.ProviderID, wire.AdapterID, wire.ConnectionID, wire.ModelID, wire.ModelVersion,
	)
	if err != nil {
		return RouteAttemptAuthorization{}, err
	}
	logging, err := provider.ParseContentLoggingMode(wire.ContentLogging)
	if err != nil {
		return RouteAttemptAuthorization{}, err
	}
	pricing, err := provider.NewRoutePricing(wire.InputPrice, wire.OutputPrice)
	if err != nil {
		return RouteAttemptAuthorization{}, err
	}
	budget, err := provider.NewModelCostBudget(uint64(wire.EstimatedInputTokens), uint64(wire.MaxOutputTokens), wire.CostCap)
	if err != nil {
		return RouteAttemptAuthorization{}, err
	}
	maximum, err := provider.EstimateMaximumRouteCost(pricing, budget)
	if err != nil || maximum.MaximumCostMicroUSD() != wire.MaximumCost {
		return RouteAttemptAuthorization{}, ErrInvalidRouteAttemptAuthorizationEncoding
	}
	authorization := RouteAttemptAuthorization{
		identity: wire.Identity, kind: kind, reviewScopeIdentity: wire.ReviewScopeIdentity,
		requestIdentity: wire.RequestIdentity, selectionReceiptIdentity: wire.SelectionReceiptIdentity,
		registryRevision: wire.RegistryRevision, routeRecordIdentity: wire.RouteRecordIdentity,
		attemptOrdinal: wire.AttemptOrdinal, routeAttemptOrdinal: wire.RouteAttemptOrdinal,
		previousOutcomeIdentity:      wire.PreviousOutcomeIdentity,
		continuationDecisionIdentity: wire.ContinuationDecisionIdentity,
		routeReference:               route, contentLoggingMode: logging, pricing: pricing, costBudget: budget,
		maximumCost: maximum, remainingCostBeforeMicroUSD: wire.RemainingBefore,
		reservedCostMicroUSD: wire.Reserved, remainingCostAfterMicroUSD: wire.RemainingAfter,
	}
	if err := authorization.Validate(); err != nil {
		return RouteAttemptAuthorization{}, err
	}
	return authorization, nil
}

// RouteExecutionRecord is one successful attempt, cost settlement, and normalized output receipt.
type RouteExecutionRecord struct {
	identity       string
	authorization  RouteAttemptAuthorization
	outcome        RouteAttemptOutcome
	reconciliation RouteCostReconciliation
	output         RouteOutputReceipt
}

// NewRouteExecutionRecord binds one complete successful route execution.
func NewRouteExecutionRecord(
	authorization RouteAttemptAuthorization,
	outcome RouteAttemptOutcome,
	reconciliation RouteCostReconciliation,
	output RouteOutputReceipt,
) (RouteExecutionRecord, error) {
	record := RouteExecutionRecord{
		authorization: authorization, outcome: outcome,
		reconciliation: reconciliation, output: output,
	}
	record.identity = deriveRouteExecutionRecordIdentity(record)
	if err := record.Validate(); err != nil {
		return RouteExecutionRecord{}, err
	}
	return record, nil
}

func (r RouteExecutionRecord) Identity() string                         { return r.identity }
func (r RouteExecutionRecord) Authorization() RouteAttemptAuthorization { return r.authorization }
func (r RouteExecutionRecord) Outcome() RouteAttemptOutcome             { return r.outcome }
func (r RouteExecutionRecord) Reconciliation() RouteCostReconciliation  { return r.reconciliation }
func (r RouteExecutionRecord) Output() RouteOutputReceipt               { return r.output }
func (r RouteExecutionRecord) String() string                           { return "route execution record" }
func (r RouteExecutionRecord) GoString() string                         { return "gateway.RouteExecutionRecord{<redacted>}" }
func (r RouteExecutionRecord) Format(state fmt.State, verb rune) {
	formatted := "route execution record"
	if verb == 'q' {
		formatted = `"route execution record"`
	} else if verb == 'v' && state.Flag('#') {
		formatted = "gateway.RouteExecutionRecord{<redacted>}"
	}
	_, _ = state.Write([]byte(formatted))
}

// Validate verifies all attempt, cost, scope, request, response, and output bindings.
func (r RouteExecutionRecord) Validate() error {
	if r.authorization.Validate() != nil || r.outcome.Validate() != nil ||
		r.reconciliation.Validate() != nil || r.output.Validate() != nil ||
		r.outcome.Status() != RouteAttemptSucceeded ||
		r.outcome.AuthorizationIdentity() != r.authorization.Identity() ||
		r.reconciliation.AttemptAuthorizationIdentity() != r.authorization.Identity() ||
		r.reconciliation.AttemptOutcomeIdentity() != r.outcome.Identity() ||
		r.output.ReviewScopeIdentity() != r.authorization.ReviewScopeIdentity() ||
		r.output.RequestIdentity() != r.authorization.RequestIdentity() ||
		r.output.ResponseIdentity() != r.outcome.ResponseIdentity() ||
		r.output.AuthorizationIdentity() != r.authorization.Identity() ||
		r.output.OutcomeIdentity() != r.outcome.Identity() {
		return ErrInvalidRouteExecutionRecord
	}
	if r.identity != deriveRouteExecutionRecordIdentity(r) {
		return ErrInvalidRouteExecutionRecord
	}
	return nil
}

func deriveRouteExecutionRecordIdentity(record RouteExecutionRecord) string {
	encoded, err := json.Marshal(struct {
		Contract       string `json:"contract"`
		SchemaVersion  int    `json:"schema_version"`
		Authorization  string `json:"authorization"`
		Outcome        string `json:"outcome"`
		Reconciliation string `json:"reconciliation"`
		Output         string `json:"output"`
	}{
		"open-trestle/route-execution-record", 1, record.authorization.Identity(),
		record.outcome.Identity(), record.reconciliation.Identity(), record.output.Identity(),
	})
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

type routeOutcomeWire struct {
	Identity               string `json:"identity"`
	Status                 string `json:"status"`
	ResponseIdentity       string `json:"response_identity"`
	UsageKnown             bool   `json:"usage_known"`
	InputTokens            uint32 `json:"input_tokens"`
	OutputTokens           uint32 `json:"output_tokens"`
	CachedInputTokens      uint32 `json:"cached_input_tokens"`
	Failure                string `json:"failure"`
	ReplaySafety           string `json:"replay_safety"`
	RetryAfterMilliseconds uint32 `json:"retry_after_milliseconds"`
	DurationMilliseconds   uint64 `json:"duration_milliseconds"`
}

type routeReconciliationWire struct {
	Identity                          string `json:"identity"`
	Status                            string `json:"status"`
	ReservedCostMicroUSD              uint64 `json:"reserved_cost_micro_usd"`
	ActualKnown                       bool   `json:"actual_known"`
	ActualInputCostMicroUSD           uint64 `json:"actual_input_cost_micro_usd"`
	ActualOutputCostMicroUSD          uint64 `json:"actual_output_cost_micro_usd"`
	ActualTotalCostMicroUSD           uint64 `json:"actual_total_cost_micro_usd"`
	RemainingAfterReservationMicroUSD uint64 `json:"remaining_after_reservation_micro_usd"`
	RemainingCostMicroUSD             uint64 `json:"remaining_cost_micro_usd"`
	BudgetOverrunMicroUSD             uint64 `json:"budget_overrun_micro_usd"`
}

type routeOutputWire struct {
	Identity         string `json:"identity"`
	Kind             string `json:"kind"`
	ContextIdentity  string `json:"context_identity"`
	ArtifactIdentity string `json:"artifact_identity"`
}

type routeExecutionWire struct {
	Contract       string                  `json:"contract"`
	SchemaVersion  int                     `json:"schema_version"`
	Identity       string                  `json:"identity"`
	Authorization  routeAuthorizationWire  `json:"authorization"`
	Outcome        routeOutcomeWire        `json:"outcome"`
	Reconciliation routeReconciliationWire `json:"reconciliation"`
	Output         routeOutputWire         `json:"output"`
}

// EncodeRouteExecutionRecord returns one canonical durable successful execution.
func EncodeRouteExecutionRecord(record RouteExecutionRecord) ([]byte, error) {
	if err := record.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(routeExecutionWireValue(record))
	if err != nil || len(encoded) > maximumRouteRecordEncodingBytes {
		return nil, ErrInvalidRouteExecutionRecordEncoding
	}
	return encoded, nil
}

// ParseRouteExecutionRecord accepts only one canonical durable successful execution.
func ParseRouteExecutionRecord(encoded []byte) (RouteExecutionRecord, error) {
	if len(encoded) == 0 || len(encoded) > maximumRouteRecordEncodingBytes {
		return RouteExecutionRecord{}, ErrInvalidRouteExecutionRecordEncoding
	}
	var wire routeExecutionWire
	if decodeCanonicalRouteRecord(encoded, &wire) != nil ||
		wire.Contract != "open-trestle/route-execution-record" || wire.SchemaVersion != 1 {
		return RouteExecutionRecord{}, ErrInvalidRouteExecutionRecordEncoding
	}
	authorization, err := parseRouteAuthorizationWire(wire.Authorization)
	if err != nil {
		return RouteExecutionRecord{}, ErrInvalidRouteExecutionRecordEncoding
	}
	outcome, err := parseRouteOutcomeWire(authorization, wire.Outcome)
	if err != nil {
		return RouteExecutionRecord{}, ErrInvalidRouteExecutionRecordEncoding
	}
	reconciliation, err := ReconcileAuthorizedRouteAttemptCost(authorization, outcome)
	if err != nil || !reconciliationWireMatches(wire.Reconciliation, reconciliation) {
		return RouteExecutionRecord{}, ErrInvalidRouteExecutionRecordEncoding
	}
	output, err := parseRouteOutputWire(authorization, outcome, wire.Output)
	if err != nil {
		return RouteExecutionRecord{}, ErrInvalidRouteExecutionRecordEncoding
	}
	record, err := NewRouteExecutionRecord(authorization, outcome, reconciliation, output)
	if err != nil || record.Identity() != wire.Identity {
		return RouteExecutionRecord{}, ErrInvalidRouteExecutionRecordEncoding
	}
	reencoded, err := EncodeRouteExecutionRecord(record)
	if err != nil || !bytes.Equal(reencoded, encoded) {
		return RouteExecutionRecord{}, ErrInvalidRouteExecutionRecordEncoding
	}
	return record, nil
}

func routeExecutionWireValue(record RouteExecutionRecord) routeExecutionWire {
	outcome := record.Outcome()
	actual := record.Reconciliation().ActualCost()
	output := record.Output()
	return routeExecutionWire{
		Contract: "open-trestle/route-execution-record", SchemaVersion: 1, Identity: record.Identity(),
		Authorization: routeAuthorizationWireValue(record.Authorization()),
		Outcome: routeOutcomeWire{
			Identity: outcome.Identity(), Status: outcome.Status().String(),
			ResponseIdentity: outcome.ResponseIdentity(), UsageKnown: outcome.Usage().IsKnown(),
			InputTokens: outcome.Usage().InputTokens(), OutputTokens: outcome.Usage().OutputTokens(),
			CachedInputTokens: outcome.Usage().CachedInputTokens(), Failure: outcome.Failure().String(),
			ReplaySafety: outcome.ReplaySafety().String(), RetryAfterMilliseconds: outcome.RetryAfterMilliseconds(),
			DurationMilliseconds: outcome.DurationMilliseconds(),
		},
		Reconciliation: routeReconciliationWire{
			Identity: record.Reconciliation().Identity(), Status: record.Reconciliation().Status().String(),
			ReservedCostMicroUSD: record.Reconciliation().ReservedCostMicroUSD(), ActualKnown: actual.IsKnown(),
			ActualInputCostMicroUSD: actual.InputCostMicroUSD(), ActualOutputCostMicroUSD: actual.OutputCostMicroUSD(),
			ActualTotalCostMicroUSD:           actual.TotalCostMicroUSD(),
			RemainingAfterReservationMicroUSD: record.Reconciliation().RemainingAfterReservationMicroUSD(),
			RemainingCostMicroUSD:             record.Reconciliation().RemainingCostMicroUSD(),
			BudgetOverrunMicroUSD:             record.Reconciliation().BudgetOverrunMicroUSD(),
		},
		Output: routeOutputWire{
			Identity: output.Identity(), Kind: output.Kind().String(),
			ContextIdentity: output.ContextIdentity(), ArtifactIdentity: output.ArtifactIdentity(),
		},
	}
}

func parseRouteOutcomeWire(
	authorization RouteAttemptAuthorization,
	wire routeOutcomeWire,
) (RouteAttemptOutcome, error) {
	var usage provider.RouteTokenUsage
	var err error
	if wire.UsageKnown {
		usage, err = provider.NewRouteTokenUsage(uint64(wire.InputTokens), uint64(wire.OutputTokens), uint64(wire.CachedInputTokens))
	} else {
		if wire.InputTokens != 0 || wire.OutputTokens != 0 || wire.CachedInputTokens != 0 {
			return RouteAttemptOutcome{}, ErrInvalidRouteExecutionRecordEncoding
		}
		usage = provider.NewUnknownRouteTokenUsage()
	}
	if err != nil {
		return RouteAttemptOutcome{}, err
	}
	status, err := ParseRouteAttemptOutcomeStatus(wire.Status)
	if err != nil {
		return RouteAttemptOutcome{}, err
	}
	var outcome RouteAttemptOutcome
	if status == RouteAttemptSucceeded {
		if wire.Failure != "" || wire.ReplaySafety != "" || wire.RetryAfterMilliseconds != 0 {
			return RouteAttemptOutcome{}, ErrInvalidRouteExecutionRecordEncoding
		}
		outcome, err = NewSuccessfulRouteAttemptOutcome(
			authorization, wire.ResponseIdentity, usage, wire.DurationMilliseconds,
		)
	} else {
		failure, parseErr := ParseRouteFailureClass(wire.Failure)
		if parseErr != nil {
			return RouteAttemptOutcome{}, parseErr
		}
		safety, parseErr := ParseRouteReplaySafety(wire.ReplaySafety)
		if parseErr != nil {
			return RouteAttemptOutcome{}, parseErr
		}
		outcome, err = NewFailedRouteAttemptOutcome(
			authorization, failure, safety, usage,
			wire.RetryAfterMilliseconds, wire.DurationMilliseconds,
		)
	}
	if err != nil || outcome.Identity() != wire.Identity {
		return RouteAttemptOutcome{}, ErrInvalidRouteExecutionRecordEncoding
	}
	return outcome, nil
}

func reconciliationWireMatches(wire routeReconciliationWire, value RouteCostReconciliation) bool {
	actual := value.ActualCost()
	return wire.Identity == value.Identity() && wire.Status == value.Status().String() &&
		wire.ReservedCostMicroUSD == value.ReservedCostMicroUSD() && wire.ActualKnown == actual.IsKnown() &&
		wire.ActualInputCostMicroUSD == actual.InputCostMicroUSD() &&
		wire.ActualOutputCostMicroUSD == actual.OutputCostMicroUSD() &&
		wire.ActualTotalCostMicroUSD == actual.TotalCostMicroUSD() &&
		wire.RemainingAfterReservationMicroUSD == value.RemainingAfterReservationMicroUSD() &&
		wire.RemainingCostMicroUSD == value.RemainingCostMicroUSD() &&
		wire.BudgetOverrunMicroUSD == value.BudgetOverrunMicroUSD()
}

func parseRouteOutputWire(
	authorization RouteAttemptAuthorization,
	outcome RouteAttemptOutcome,
	wire routeOutputWire,
) (RouteOutputReceipt, error) {
	kind, err := ParseRouteOutputKind(wire.Kind)
	if err != nil {
		return RouteOutputReceipt{}, err
	}
	output := RouteOutputReceipt{
		identity: wire.Identity, kind: kind,
		reviewScopeIdentity: authorization.ReviewScopeIdentity(), contextIdentity: wire.ContextIdentity,
		artifactIdentity: wire.ArtifactIdentity, requestIdentity: authorization.RequestIdentity(),
		responseIdentity: outcome.ResponseIdentity(), authorizationIdentity: authorization.Identity(),
		outcomeIdentity: outcome.Identity(),
	}
	if err := output.Validate(); err != nil {
		return RouteOutputReceipt{}, err
	}
	return output, nil
}

func decodeCanonicalRouteRecord(encoded []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrInvalidRouteExecutionRecordEncoding
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return ErrInvalidRouteExecutionRecordEncoding
	}
	return nil
}
