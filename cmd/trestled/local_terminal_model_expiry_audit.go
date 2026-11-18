package main

import (
	"context"
	"reflect"
	"slices"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	modelhandler "github.com/georgejieh/open-trestle/handlers/model"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/runtimecatalog"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

type terminalExpiryClock struct{ at time.Time }

func (c terminalExpiryClock) Now() time.Time { return c.at }

func terminalExpiryAuditEvent(event audit.Event, scope audit.ReviewScope, sequence uint64, previous string, kind audit.EventKind, subject string, parents []string, earliest, latest time.Time) bool {
	slices.Sort(parents)
	return event.Validate() == nil && event.Scope() == scope && event.Sequence() == sequence && event.PreviousIdentity() == previous && event.Kind() == kind && event.SubjectIdentity() == subject && slices.Equal(event.CausalParentIdentities(), parents) && event.OccurredAtUnixMilliseconds() >= earliest.UnixMilli() && event.OccurredAtUnixMilliseconds() <= latest.UnixMilli()
}

// validateTerminalExpiryGeneration checks the generation request's audit
// against its retained artifacts: the selection, any refused attempts the
// handler retried on the same route, and the final attempt the candidate
// records. It returns the index of the first event after that request.
func validateTerminalExpiryGeneration(ctx context.Context, events []audit.Event, fact controlplane.HistoricalContextPacketFact, proof terminalModelExpiry, values []artifact.Artifact, configuration runtimeconfig.RuntimePolicy, inventory runtimeconfig.RouteInventory, scanner review.ScannerBinaryDigests, now time.Time) (modelhandler.GenerationResult, int, error) {
	fail := func() (modelhandler.GenerationResult, int, error) {
		return modelhandler.GenerationResult{}, 0, errTerminalModelExpiry
	}
	if len(values) < 12 || len(events) < 4 {
		return fail()
	}
	linked, ok := fact.LinkedInputEvent()
	if !ok {
		return fail()
	}
	descriptor := linked.InputDescriptor()
	packet, requestArtifact, receiptArtifact, inputArtifact, candidate := values[7], values[8], values[9], values[10], values[11]
	input, err := modelhandler.ParseGenerationInput(inputArtifact.Payload())
	if err != nil || !input.IsSanitized() || descriptor.ScannerHelperDigest != scanner.HelperSHA256 || review.ValidateSanitizedEgressArtifacts(packet, requestArtifact, receiptArtifact, scanner) != nil {
		return fail()
	}
	result, err := modelhandler.ParseGenerationResultArtifact(candidate, inputArtifact, packet)
	if err != nil {
		return fail()
	}
	initial, authorization := input.Authorization(), result.RouteExecution().Authorization()
	if initial.Kind() != gateway.RouteAttemptInitial || initial.AttemptOrdinal() != 1 || initial.RouteAttemptOrdinal() != 1 || initial.PreviousOutcomeIdentity() != "" || initial.ContinuationDecisionIdentity() != "" || initial.ReviewScopeIdentity() != fact.Plan().Scope().Identity() || !gateway.IsSameReservationRetryOf(initial, authorization) {
		return fail()
	}
	attempts, ok := recordedRouteAttempts(events, 1, initial.SelectionReceiptIdentity())
	if !ok || !routeAttemptsGrantedFrom(events, attempts, initial) || !finalRouteAttemptIs(events, attempts, authorization) || !respondedRouteAttempt(events, attempts[len(attempts)-1].claim) {
		return fail()
	}
	if descriptor.Input.ArtifactIdentity != inputArtifact.Identity() || descriptor.PacketArtifactIdentity != packet.Identity() || descriptor.GenerationInputIdentity != input.Identity() || descriptor.AuthorizationIdentity != initial.Identity() || descriptor.SelectionReceiptIdentity != initial.SelectionReceiptIdentity() || descriptor.SelectedRecordIdentity != initial.RouteRecordIdentity() || descriptor.Request.ArtifactIdentity != input.SanitizedRequestArtifactIdentity() || descriptor.Receipt.ArtifactIdentity != input.SanitizedEgressReceiptArtifactIdentity() || descriptor.ReceiptIdentity != input.SanitizedEgressReceiptIdentity() {
		return fail()
	}
	if !reflect.DeepEqual(descriptor.Input, localInputArtifactDescriptor(inputArtifact)) || !reflect.DeepEqual(descriptor.Request, localInputArtifactDescriptor(requestArtifact)) || !reflect.DeepEqual(descriptor.Receipt, localInputArtifactDescriptor(receiptArtifact)) {
		return fail()
	}
	sanitized, err := review.ParseSanitizedModelRequest(requestArtifact.Payload())
	if err != nil {
		return fail()
	}
	request, err := sanitized.ProviderRequest()
	if err != nil {
		return fail()
	}
	pair, err := runtimecatalog.ResolveLocalGenerationRoutePair(configuration, inventory)
	if err != nil {
		return fail()
	}
	route, err := runtimecatalog.PlanLocalGenerationRoute(ctx, fact.Plan().Scope(), request, configuration, inventory, pair)
	if err != nil || !runtimecatalog.MatchesLocalGenerationAuthorization(route, initial) || route.SelectionIdentity() != descriptor.SelectionReceiptIdentity || route.RoutingInputIdentity() != descriptor.RoutingInputIdentity || route.SelectedRecordIdentity() != descriptor.SelectedRecordIdentity || route.RequestIdentity() != authorization.RequestIdentity() || route.PolicyIdentity() != descriptor.PolicyIdentity || route.PairIdentity() != descriptor.RoutePairIdentity || route.RegistryRevision() != descriptor.RegistryRevision || route.PerformanceRevision() != descriptor.PerformanceRevision {
		return fail()
	}
	execution := result.RouteExecution()
	attempt, err := gateway.NewCompletedRouteAttemptRecord(authorization, execution.Outcome(), execution.Reconciliation())
	if err != nil || execution.Outcome().Status() != gateway.RouteAttemptSucceeded || execution.Reconciliation().Status() == gateway.RouteCostBudgetExceeded {
		return fail()
	}
	dispatch, err := attempt.DispatchResultIdentity()
	if err != nil {
		return fail()
	}
	final := attempts[len(attempts)-1].claim
	specs := []auditEventSpec{{audit.EventRouteSelected, initial.SelectionReceiptIdentity(), []string{route.RoutingInputIdentity(), route.SelectedRecordIdentity(), route.RankingPolicyIdentity()}}}
	// The refused attempts left no artifact; their shape and lineage are checked above.
	for _, event := range events[1 : final+1] {
		specs = append(specs, recordedAuditEventSpec(event))
	}
	specs = append(specs,
		auditEventSpec{audit.EventRouteDispatchCompleted, execution.Outcome().Identity(), []string{authorization.Identity(), dispatch, execution.Outcome().ResponseIdentity()}},
		auditEventSpec{audit.EventRouteCostReconciled, execution.Reconciliation().Identity(), []string{authorization.Identity(), execution.Outcome().Identity()}})
	previous, at := "", packet.CreatedAt()
	for i, spec := range specs {
		limit := candidate.CreatedAt()
		if i == 0 {
			limit = linked.OccurredAt()
		} else if i == 1 && proof.candidateClaim.OccurredAt().After(at) {
			at = proof.candidateClaim.OccurredAt()
		}
		if !terminalExpiryAuditEvent(events[i], fact.Plan().Scope(), uint64(i+1), previous, spec.kind, spec.subject, spec.parents, at, limit) {
			return fail()
		}
		previous, at = events[i].Identity(), time.UnixMilli(events[i].OccurredAtUnixMilliseconds())
	}
	end := proof.failed.OccurredAt()
	if proof.task == "verification" {
		if proof.candidateSuccess.OutputIdentity() != candidate.Identity() {
			return fail()
		}
		end = proof.candidateSuccess.OccurredAt()
	}
	if candidate.CreatedAt().Before(proof.candidateClaim.OccurredAt()) || candidate.CreatedAt().After(end) || candidate.CreatedAt().After(now) || !candidate.ExpiresAt().Equal(packet.ExpiresAt()) || proof.task == "candidates" && candidate.CreatedAt().After(proof.latestLease.LeaseExpiresAt()) {
		return fail()
	}
	if events[final+1].OccurredAtUnixMilliseconds() != candidate.CreatedAt().UnixMilli() || events[final+2].OccurredAtUnixMilliseconds() != candidate.CreatedAt().UnixMilli() {
		return fail()
	}
	return result, final + 3, nil
}

// validateTerminalExpiryVerifier checks the verification request's audit from
// events[next]: its selection, any refused attempts the handler retried on the
// same route, and the claim the lease ended at, which must be the last event.
// The existing policy authorizer is run only against a new in-memory ledger.
func validateTerminalExpiryVerifier(ctx context.Context, events []audit.Event, next int, fact controlplane.HistoricalContextPacketFact, proof terminalModelExpiry, values []artifact.Artifact, generation modelhandler.GenerationResult, configuration runtimeconfig.RuntimePolicy, inventory runtimeconfig.RouteInventory, scanner review.ScannerBinaryDigests) error {
	if proof.task != "verification" || next < 4 || next+2 > len(events) || len(values) != 14 {
		return errTerminalModelExpiry
	}
	generationInput, err := modelhandler.ParseGenerationInput(values[10].Payload())
	if err != nil {
		return err
	}
	verification, err := review.NewVerificationRequestContext(values[7].Payload(), generation.ContextIdentity(), fact.Plan().Scope().Identity(), generationInput.MemoryScopeIdentity(), generationInput.MemoryIdentity(), generationInput.Snapshot(), generationInput.EvidenceItems(), generation.Candidates())
	if err != nil {
		return err
	}
	raw, err := verification.ProviderRequest()
	if err != nil {
		return err
	}
	if review.ValidateSanitizedVerificationEgressArtifacts(raw, generation.ContextIdentity(), generation.Candidates().Identity(), values[11], values[10], values[7], values[12], values[13], scanner) != nil {
		return errTerminalModelExpiry
	}
	for _, value := range values[12:] {
		if value.CreatedAt().Before(proof.claim.OccurredAt()) || value.CreatedAt().After(proof.failed.OccurredAt()) {
			return errTerminalModelExpiry
		}
	}
	sanitized, err := review.ParseSanitizedModelRequest(values[12].Payload())
	if err != nil {
		return err
	}
	request, err := sanitized.ProviderRequest()
	if err != nil {
		return err
	}
	inventoryView, err := runtimecatalog.NewStaticVerificationRouteInventory(inventory)
	if err != nil {
		return err
	}
	memoryLedger := audit.NewMemoryLedger()
	authorizer, err := runtimecatalog.NewVerificationPolicyAuthorizerFromRuntimePolicy(configuration, inventoryView, memoryLedger, terminalExpiryClock{time.UnixMilli(events[next].OccurredAtUnixMilliseconds())})
	if err != nil {
		return err
	}
	authority, err := authorizer.Authorize(ctx, fact.Plan().Scope(), request, generation.RouteExecution())
	if err != nil || !authority.MatchesGeneration(request, generation.RouteExecution()) {
		return errTerminalModelExpiry
	}
	selected, found, err := memoryLedger.Head(ctx, fact.Plan().Scope())
	if err != nil || !found || selected.Sequence() != 1 || selected.Kind() != audit.EventRouteSelected {
		return errTerminalModelExpiry
	}
	if !terminalExpiryAuditEvent(events[next], fact.Plan().Scope(), uint64(next+1), events[next-1].Identity(), audit.EventRouteSelected, selected.SubjectIdentity(), selected.CausalParentIdentities(), values[12].CreatedAt(), proof.failed.OccurredAt()) {
		return errTerminalModelExpiry
	}
	authorization := authority.Authorization()
	attempts, ok := recordedRouteAttempts(events, next+1, authorization.SelectionReceiptIdentity())
	if !ok || !routeAttemptsGrantedFrom(events, attempts, authorization) || attempts[len(attempts)-1].claim != len(events)-1 {
		return errTerminalModelExpiry
	}
	// The first claim follows the request at once; a retry follows its wait.
	for i := next + 1; i < len(events); i++ {
		earliest, latest := time.UnixMilli(events[i-1].OccurredAtUnixMilliseconds()), proof.failed.OccurredAt()
		if i == next+1 {
			earliest, latest = values[12].CreatedAt(), values[12].CreatedAt()
		}
		spec := recordedAuditEventSpec(events[i])
		if !terminalExpiryAuditEvent(events[i], fact.Plan().Scope(), uint64(i+1), events[i-1].Identity(), spec.kind, spec.subject, spec.parents, earliest, latest) {
			return errTerminalModelExpiry
		}
	}
	return nil
}
