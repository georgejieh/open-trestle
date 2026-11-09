package gateway

import (
	"fmt"
	"time"

	"github.com/georgejieh/open-trestle/internal/provider"
)

// InvestigationTurnRecord is readback of one complete owner-dispatched turn.
// It cannot be supplied to an owner as settlement or execution authority.
type InvestigationTurnRecord struct {
	identity, ownerIdentity, sessionIdentity, policyIdentity, scopeIdentity string
	ordinal                                                                 uint8
	role                                                                    InvestigationTurnRole
	previous                                                                string
	deadlineMillis, startedMillis, finishedMillis                           int64
	estimateVersion                                                         uint8
	declaredInput, maxOutput                                                uint32
	originalCap                                                             uint64
	systemBytes                                                             uint32
	responseFormatBytes                                                     uint32
	structuredOutput                                                        bool
	request                                                                 provider.Request
	selection                                                               RouteSelectionReceipt
	ranking                                                                 RouteRankingResult
	authorization                                                           RouteAttemptAuthorization
	dispatch                                                                RouteDispatchResult
	outcome                                                                 RouteAttemptOutcome
	reconciliation                                                          RouteCostReconciliation
}

func newInvestigationTurnRecord(owner *InvestigationRouteOwner, ordinal uint8, role InvestigationTurnRole, previous string, request provider.Request, transport investigationTurnTransport, selection RouteSelectionReceipt, ranking RouteRankingResult, authorization RouteAttemptAuthorization, dispatch RouteDispatchResult, outcome RouteAttemptOutcome, reconciliation RouteCostReconciliation, started, finished time.Time) (InvestigationTurnRecord, error) {
	value := InvestigationTurnRecord{ownerIdentity: owner.identity, sessionIdentity: owner.options.SessionIdentity, policyIdentity: owner.options.PolicyIdentity, scopeIdentity: owner.options.Scope.Identity(), ordinal: ordinal, role: role, previous: previous, deadlineMillis: owner.options.Deadline.UnixMilli(), startedMillis: started.UnixMilli(), finishedMillis: finished.UnixMilli(), estimateVersion: InvestigationBudgetEstimateVersion, declaredInput: owner.options.Budget.EstimatedInputTokens(), maxOutput: owner.options.Budget.MaxOutputTokens(), originalCap: owner.options.Budget.MaxCostMicroUSD(), systemBytes: transport.systemBytes, responseFormatBytes: transport.responseFormatBytes, structuredOutput: transport.structured, request: request, selection: selection, ranking: ranking, authorization: authorization, dispatch: dispatch, outcome: outcome, reconciliation: reconciliation}
	value.identity = value.deriveIdentity()
	if value.Validate() != nil {
		return InvestigationTurnRecord{}, ErrInvestigationRouteOwner
	}
	return value, nil
}

func (r InvestigationTurnRecord) Identity() string                         { return r.identity }
func (r InvestigationTurnRecord) PreviousTurnIdentity() string             { return r.previous }
func (r InvestigationTurnRecord) RequestIdentity() string                  { return r.request.Identity() }
func (r InvestigationTurnRecord) Selection() RouteSelectionReceipt         { return r.selection }
func (r InvestigationTurnRecord) Authorization() RouteAttemptAuthorization { return r.authorization }
func (r InvestigationTurnRecord) Dispatch() RouteDispatchResult            { return r.dispatch }
func (r InvestigationTurnRecord) Outcome() RouteAttemptOutcome             { return r.outcome }
func (r InvestigationTurnRecord) Reconciliation() RouteCostReconciliation  { return r.reconciliation }

// EstimateVersion returns the recorded input estimate version of the turn.
func (r InvestigationTurnRecord) EstimateVersion() uint8 { return r.estimateVersion }

// SystemChannelBytes returns the trusted system channel bytes the turn reserved
// for, recorded from estimate version 2. Estimate version 1 turns did not count
// the system channel and return 0.
func (r InvestigationTurnRecord) SystemChannelBytes() uint32 { return r.systemBytes }

// ResponseFormatBytes returns the serialized response_format bytes the turn
// reserved for and true when its routes used the local structured-output
// transport, recorded from estimate version 2. Other turns return 0 and false.
func (r InvestigationTurnRecord) ResponseFormatBytes() (uint32, bool) {
	return r.responseFormatBytes, r.structuredOutput
}

// Request returns the exact request the turn dispatched.
func (r InvestigationTurnRecord) Request() provider.Request { return r.request }

func (r InvestigationTurnRecord) Validate() error {
	for _, id := range []string{r.identity, r.ownerIdentity, r.sessionIdentity, r.policyIdentity, r.scopeIdentity} {
		if !validInvestigationIdentity(id) {
			return ErrInvestigationRouteOwner
		}
	}
	if r.ordinal == 0 || r.ordinal > 8 || r.role.String() == "" || (r.ordinal == 1) != (r.previous == "") || r.previous != "" && !validInvestigationIdentity(r.previous) || r.startedMillis <= 0 || r.finishedMillis < r.startedMillis || r.deadlineMillis <= r.finishedMillis || r.deadlineMillis > 253402300799999 || r.finishedMillis-r.startedMillis > int64(maxRouteAttemptDurationMilliseconds) {
		return ErrInvestigationRouteOwner
	}
	if r.request.Validate() != nil || r.selection.Validate() != nil || r.ranking.Validate() != nil || r.authorization.Validate() != nil || r.dispatch.Validate() != nil || r.outcome.Validate() != nil || r.reconciliation.Validate() != nil {
		return ErrInvestigationRouteOwner
	}
	// The recorded estimate version selects the formula; it rejects any other version.
	// Only a structured-output turn counts response_format bytes, and only from
	// estimate version 2.
	if !r.structuredOutput && r.responseFormatBytes != 0 || r.structuredOutput && r.estimateVersion == investigationBudgetEstimateVersionV1 {
		return ErrInvestigationRouteOwner
	}
	budget, err := investigationTurnEstimate(r.estimateVersion, r.declaredInput, r.maxOutput, r.request, r.systemBytes, r.responseFormatBytes, r.authorization.RemainingCostBeforeMicroUSD())
	if err != nil || r.selection.CostBudget() != budget || r.authorization.RemainingCostBeforeMicroUSD() > r.originalCap || r.selection.ReviewScopeIdentity() != r.scopeIdentity || r.authorization.ReviewScopeIdentity() != r.scopeIdentity || r.selection.RequestIdentity() != r.request.Identity() {
		return ErrInvestigationRouteOwner
	}
	if _, err := provider.NewModelCostBudget(uint64(r.declaredInput), uint64(r.maxOutput), r.originalCap); err != nil {
		return ErrInvestigationRouteOwner
	}
	expectedAuthority, err := NewInitialRouteAttemptAuthorization(r.request, r.selection, r.ranking)
	if err != nil || expectedAuthority.Identity() != r.authorization.Identity() || r.authorization.Kind() != RouteAttemptInitial || r.authorization.PreviousOutcomeIdentity() != "" || r.authorization.ContinuationDecisionIdentity() != "" {
		return ErrInvestigationRouteOwner
	}
	if r.dispatch.Status() != RouteDispatchSucceeded || r.dispatch.AuthorizationIdentity() != r.authorization.Identity() || r.dispatch.Response().Capability() != r.request.Capability() {
		return ErrInvestigationRouteOwner
	}
	expectedOutcome, err := NewRouteAttemptOutcomeFromDispatch(r.authorization, r.dispatch, uint64(r.finishedMillis-r.startedMillis))
	if err != nil || expectedOutcome.Identity() != r.outcome.Identity() {
		return ErrInvestigationRouteOwner
	}
	expectedCost, err := ReconcileAuthorizedRouteAttemptCost(r.authorization, r.outcome)
	if err != nil || expectedCost.Identity() != r.reconciliation.Identity() || !r.reconciliation.ActualCost().IsKnown() || r.reconciliation.Status() == RouteCostBudgetExceeded {
		return ErrInvestigationRouteOwner
	}
	if r.identity != r.deriveIdentity() {
		return ErrInvestigationRouteOwner
	}
	return nil
}

// deriveIdentity hashes the 26-element version 1 preimage. From estimate
// version 2 the recorded system channel bytes are appended as a 27th element,
// so version 1 identities are unchanged, and a structured-output turn appends
// its response_format bytes as a 28th, so standard version 2 identities are
// unchanged.
func (r InvestigationTurnRecord) deriveIdentity() string {
	preimage := []any{
		"open-trestle/investigation-turn", 1,
		r.ownerIdentity, r.sessionIdentity, r.policyIdentity, r.scopeIdentity,
		r.ordinal, r.role.String(), r.previous,
		r.deadlineMillis, r.startedMillis, r.finishedMillis,
		r.estimateVersion, r.declaredInput, r.maxOutput, r.originalCap,
		r.request.Identity(), r.selection.Identity(), r.authorization.Identity(),
		r.dispatch.Identity(), r.outcome.Identity(), r.reconciliation.Identity(),
		r.authorization.RemainingCostBeforeMicroUSD(), r.authorization.ReservedCostMicroUSD(),
		r.reconciliation.ActualCost().TotalCostMicroUSD(), r.reconciliation.RemainingCostMicroUSD(),
	}
	if r.estimateVersion != investigationBudgetEstimateVersionV1 {
		preimage = append(preimage, r.systemBytes)
	}
	if r.structuredOutput {
		preimage = append(preimage, r.responseFormatBytes)
	}
	return investigationIdentity(preimage)
}
func (r InvestigationTurnRecord) String() string { return "investigation turn record" }
func (r InvestigationTurnRecord) GoString() string {
	return "gateway.InvestigationTurnRecord{<redacted>}"
}
func (r InvestigationTurnRecord) Format(s fmt.State, verb rune) {
	_, _ = s.Write([]byte("investigation turn record"))
}
