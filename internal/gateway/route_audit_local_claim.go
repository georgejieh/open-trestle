package gateway

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/provider"
)

// ClaimStrictInitialLocalRouteAttempt appends one uniquely acquired initial LOCAL
// claim with an exact typed selection and four-parent causal contract. This is
// only an audit checkpoint: callers can reconstruct typed selection values. It
// does not prove stored request bytes, scanner results, a pinned runtime pair,
// a current task lease, dispatch authorization, or settlement. No adapter is
// called here. Legacy ClaimRouteAttempt and its parent contract are unchanged.
func ClaimStrictInitialLocalRouteAttempt(ctx context.Context, ledger audit.Ledger, scope audit.ReviewScope, request provider.Request, input ReviewRoutingInput, ranking RouteRankingPolicy, selection RouteSelectionReceipt, authorization RouteAttemptAuthorization, occurredAt time.Time) (audit.Event, bool, error) {
	if err := validateRouteAuditInputs(ledger, scope); err != nil {
		return audit.Event{}, false, err
	}
	for _, validate := range []func() error{request.Validate, input.Validate, ranking.Validate, selection.Validate, authorization.Validate} {
		if err := validate(); err != nil {
			return audit.Event{}, false, err
		}
	}
	pin, hasPin := ranking.PinnedRoute()
	allowedZones := input.ProviderDataConstraints().AllowedProviderZones()
	if input.ReviewScopeIdentity() != scope.Identity() || selection.ReviewScopeIdentity() != scope.Identity() || authorization.ReviewScopeIdentity() != scope.Identity() {
		return audit.Event{}, false, ErrRouteAuditScopeMismatch
	}
	if input.RequestIdentity() != request.Identity() || selection.RequestIdentity() != request.Identity() || authorization.RequestIdentity() != request.Identity() ||
		selection.RoutingInputIdentity() != input.Identity() || selection.RankingPolicyIdentity() != ranking.Identity() ||
		selection.SelectedRecordIdentity() != authorization.RouteRecordIdentity() || selection.RegistryRevision() != authorization.RegistryRevision() ||
		selection.CostBudget() != authorization.CostBudget() || authorization.SelectionReceiptIdentity() != selection.Identity() ||
		authorization.Kind() != RouteAttemptInitial || authorization.AttemptOrdinal() != 1 || authorization.RouteAttemptOrdinal() != 1 ||
		authorization.PreviousOutcomeIdentity() != "" || authorization.ContinuationDecisionIdentity() != "" ||
		!hasPin || pin != authorization.RouteReference() || pin.Zone() != provider.ProviderZoneLocal ||
		!allowedZones.Allows(provider.ProviderZoneLocal) ||
		authorization.ContentLoggingMode() != provider.ContentLoggingDisabled {
		return audit.Event{}, false, ErrRouteAuditRecordMismatch
	}
	// LOCAL must be the only permitted zone, not merely one allowed route.
	for zone := provider.ProviderZonePrivateRemote; zone <= provider.ProviderZoneSubscriptionOAuth; zone++ {
		if allowedZones.Allows(zone) {
			return audit.Event{}, false, ErrRouteAuditRecordMismatch
		}
	}
	selectionParents := []string{input.Identity(), selection.SelectedRecordIdentity(), ranking.Identity()}
	claimParents := append([]string{selection.Identity()}, selectionParents...)
	// Each pass scans a snapshot bounded by Head. A changed head forces rescan,
	// including before an idempotent return. Append's expected predecessor is CAS.
	for range maxRouteAuditAppendConflicts {
		head, hasHead, err := ledger.Head(ctx, scope)
		if err != nil {
			return audit.Event{}, false, err
		}
		var after uint64
		selectionCount := 0
		var existing audit.Event
		claimCount := 0
		for hasHead && after < head.Sequence() {
			events, err := ledger.Read(ctx, scope, after, 1000)
			if err != nil {
				return audit.Event{}, false, err
			}
			if len(events) == 0 {
				return audit.Event{}, false, ErrRouteAuditRecordMismatch
			}
			for _, event := range events {
				if event.Sequence() > head.Sequence() {
					break
				}
				if event.Kind() == audit.EventRouteSelected && event.SubjectIdentity() == selection.Identity() {
					selectionCount++
					if selectionCount != 1 || !routeAuditParentsMatch(event, selectionParents) {
						return audit.Event{}, false, ErrRouteAuditRecordMismatch
					}
				}
				if event.Kind() == audit.EventRouteAttemptClaimed && event.SubjectIdentity() == authorization.Identity() {
					claimCount++
					if claimCount != 1 || selectionCount != 1 || !routeAuditParentsMatch(event, claimParents) {
						return audit.Event{}, false, ErrRouteAuditRecordMismatch
					}
					existing = event
				}
			}
			after = events[len(events)-1].Sequence()
		}
		latest, hasLatest, err := ledger.Head(ctx, scope)
		if err != nil {
			return audit.Event{}, false, err
		}
		if hasHead != hasLatest || hasHead && head.Identity() != latest.Identity() {
			continue
		}
		if selectionCount == 0 {
			return audit.Event{}, false, ErrRouteAuditPrerequisiteMissing
		}
		if claimCount != 0 {
			return existing, false, nil
		}
		sequence, previous := uint64(1), ""
		if hasHead {
			sequence, previous = head.Sequence()+1, head.Identity()
		}
		// Event canonicalizes parent ordering. Check no accidental parent collapse.
		sorted := slices.Clone(claimParents)
		slices.Sort(sorted)
		for i := 1; i < len(sorted); i++ {
			if sorted[i] == sorted[i-1] {
				return audit.Event{}, false, ErrRouteAuditRecordMismatch
			}
		}
		event, err := audit.NewEvent(scope, sequence, previous, audit.EventRouteAttemptClaimed, authorization.Identity(), claimParents, occurredAt)
		if err != nil {
			return audit.Event{}, false, err
		}
		err = ledger.Append(ctx, previous, event)
		if err == nil {
			return event, true, nil
		}
		if !errors.Is(err, audit.ErrAuditHeadConflict) {
			return audit.Event{}, false, err
		}
	}
	return audit.Event{}, false, ErrRouteAuditAppendConflict
}
