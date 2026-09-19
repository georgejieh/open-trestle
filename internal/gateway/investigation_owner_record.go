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
	request                                                                 provider.Request
	selection                                                               RouteSelectionReceipt
	ranking                                                                 RouteRankingResult
	authorization                                                           RouteAttemptAuthorization
	dispatch                                                                RouteDispatchResult
	outcome                                                                 RouteAttemptOutcome
	reconciliation                                                          RouteCostReconciliation
}

func newInvestigationTurnRecord(owner *InvestigationRouteOwner, ordinal uint8, role InvestigationTurnRole, previous string, request provider.Request, selection RouteSelectionReceipt, ranking RouteRankingResult, authorization RouteAttemptAuthorization, dispatch RouteDispatchResult, outcome RouteAttemptOutcome, reconciliation RouteCostReconciliation, started, finished time.Time) (InvestigationTurnRecord, error) {
	value := InvestigationTurnRecord{ownerIdentity: owner.identity, sessionIdentity: owner.options.SessionIdentity, policyIdentity: owner.options.PolicyIdentity, scopeIdentity: owner.options.Scope.Identity(), ordinal: ordinal, role: role, previous: previous, deadlineMillis: owner.options.Deadline.UnixMilli(), startedMillis: started.UnixMilli(), finishedMillis: finished.UnixMilli(), estimateVersion: InvestigationBudgetEstimateVersion, declaredInput: owner.options.Budget.EstimatedInputTokens(), maxOutput: owner.options.Budget.MaxOutputTokens(), originalCap: owner.options.Budget.MaxCostMicroUSD(), request: request, selection: selection, ranking: ranking, authorization: authorization, dispatch: dispatch, outcome: outcome, reconciliation: reconciliation}
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

func (r InvestigationTurnRecord) Validate() error {
	for _, id := range []string{r.identity, r.ownerIdentity, r.sessionIdentity, r.policyIdentity, r.scopeIdentity} {
		if !validInvestigationIdentity(id) {
			return ErrInvestigationRouteOwner
		}
	}
	if r.ordinal == 0 || r.ordinal > 8 || r.role.String() == "" || (r.ordinal == 1) != (r.previous == "") || r.previous != "" && !validInvestigationIdentity(r.previous) || r.startedMillis <= 0 || r.finishedMillis < r.startedMillis || r.deadlineMillis <= r.finishedMillis || r.deadlineMillis > 253402300799999 || r.finishedMillis-r.startedMillis > int64(maxRouteAttemptDurationMilliseconds) || r.estimateVersion != InvestigationBudgetEstimateVersion {
		return ErrInvestigationRouteOwner
	}
	if r.request.Validate() != nil || r.selection.Validate() != nil || r.ranking.Validate() != nil || r.authorization.Validate() != nil || r.dispatch.Validate() != nil || r.outcome.Validate() != nil || r.reconciliation.Validate() != nil {
		return ErrInvestigationRouteOwner
	}
	budget, err := provider.NewModelCostBudget(max(uint64(r.declaredInput), uint64(len(r.request.Payload()))+256), uint64(r.maxOutput), r.authorization.RemainingCostBeforeMicroUSD())
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

func (r InvestigationTurnRecord) deriveIdentity() string {
	return investigationIdentity([]any{
		"open-trestle/investigation-turn", 1,
		r.ownerIdentity, r.sessionIdentity, r.policyIdentity, r.scopeIdentity,
		r.ordinal, r.role.String(), r.previous,
		r.deadlineMillis, r.startedMillis, r.finishedMillis,
		r.estimateVersion, r.declaredInput, r.maxOutput, r.originalCap,
		r.request.Identity(), r.selection.Identity(), r.authorization.Identity(),
		r.dispatch.Identity(), r.outcome.Identity(), r.reconciliation.Identity(),
		r.authorization.RemainingCostBeforeMicroUSD(), r.authorization.ReservedCostMicroUSD(),
		r.reconciliation.ActualCost().TotalCostMicroUSD(), r.reconciliation.RemainingCostMicroUSD(),
	})
}
func (r InvestigationTurnRecord) String() string { return "investigation turn record" }
func (r InvestigationTurnRecord) GoString() string {
	return "gateway.InvestigationTurnRecord{<redacted>}"
}
func (r InvestigationTurnRecord) Format(s fmt.State, verb rune) {
	_, _ = s.Write([]byte("investigation turn record"))
}
