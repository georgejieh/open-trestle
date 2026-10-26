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

func validateTerminalExpiryGeneration(ctx context.Context, events []audit.Event, fact controlplane.HistoricalContextPacketFact, proof terminalModelExpiry, values []artifact.Artifact, configuration runtimeconfig.RuntimePolicy, inventory runtimeconfig.RouteInventory, scanner review.ScannerBinaryDigests, now time.Time) (modelhandler.GenerationResult, error) {
	fail := func() (modelhandler.GenerationResult, error) {
		return modelhandler.GenerationResult{}, errTerminalModelExpiry
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
	if err != nil || !input.IsSanitized() || descriptor.ScannerLauncherDigest != scanner.LauncherSHA256 || descriptor.ScannerWorkerDigest != scanner.WorkerSHA256 || review.ValidateSanitizedEgressArtifacts(packet, requestArtifact, receiptArtifact, scanner) != nil {
		return fail()
	}
	result, err := modelhandler.ParseGenerationResultArtifact(candidate, inputArtifact, packet)
	if err != nil {
		return fail()
	}
	authorization := result.RouteExecution().Authorization()
	if authorization.Kind() != gateway.RouteAttemptInitial || authorization.AttemptOrdinal() != 1 || authorization.RouteAttemptOrdinal() != 1 || authorization.PreviousOutcomeIdentity() != "" || authorization.ContinuationDecisionIdentity() != "" || authorization.ReviewScopeIdentity() != fact.Plan().Scope().Identity() {
		return fail()
	}
	if descriptor.Input.ArtifactIdentity != inputArtifact.Identity() || descriptor.PacketArtifactIdentity != packet.Identity() || descriptor.GenerationInputIdentity != input.Identity() || descriptor.AuthorizationIdentity != authorization.Identity() || descriptor.SelectionReceiptIdentity != authorization.SelectionReceiptIdentity() || descriptor.SelectedRecordIdentity != authorization.RouteRecordIdentity() || descriptor.Request.ArtifactIdentity != input.SanitizedRequestArtifactIdentity() || descriptor.Receipt.ArtifactIdentity != input.SanitizedEgressReceiptArtifactIdentity() || descriptor.ReceiptIdentity != input.SanitizedEgressReceiptIdentity() {
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
	if err != nil || !runtimecatalog.MatchesLocalGenerationAuthorization(route, authorization) || route.SelectionIdentity() != descriptor.SelectionReceiptIdentity || route.RoutingInputIdentity() != descriptor.RoutingInputIdentity || route.SelectedRecordIdentity() != descriptor.SelectedRecordIdentity || route.RequestIdentity() != authorization.RequestIdentity() || route.PolicyIdentity() != descriptor.PolicyIdentity || route.PairIdentity() != descriptor.RoutePairIdentity || route.RegistryRevision() != descriptor.RegistryRevision || route.PerformanceRevision() != descriptor.PerformanceRevision {
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
	specs := []struct {
		kind    audit.EventKind
		subject string
		parents []string
	}{
		{audit.EventRouteSelected, authorization.SelectionReceiptIdentity(), []string{route.RoutingInputIdentity(), route.SelectedRecordIdentity(), route.RankingPolicyIdentity()}},
		{audit.EventRouteAttemptClaimed, authorization.Identity(), []string{authorization.SelectionReceiptIdentity()}},
		{audit.EventRouteDispatchCompleted, execution.Outcome().Identity(), []string{authorization.Identity(), dispatch, execution.Outcome().ResponseIdentity()}},
		{audit.EventRouteCostReconciled, execution.Reconciliation().Identity(), []string{authorization.Identity(), execution.Outcome().Identity()}},
	}
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
	if events[2].OccurredAtUnixMilliseconds() != candidate.CreatedAt().UnixMilli() || events[3].OccurredAtUnixMilliseconds() != candidate.CreatedAt().UnixMilli() {
		return fail()
	}
	return result, nil
}

// The existing policy authorizer is run only against a new in-memory ledger.
func validateTerminalExpiryVerifier(ctx context.Context, events []audit.Event, fact controlplane.HistoricalContextPacketFact, proof terminalModelExpiry, values []artifact.Artifact, generation modelhandler.GenerationResult, configuration runtimeconfig.RuntimePolicy, inventory runtimeconfig.RouteInventory, scanner review.ScannerBinaryDigests) error {
	if proof.task != "verification" || len(events) != 6 || len(values) != 14 {
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
	authorizer, err := runtimecatalog.NewVerificationPolicyAuthorizerFromRuntimePolicy(configuration, inventoryView, memoryLedger, terminalExpiryClock{time.UnixMilli(events[4].OccurredAtUnixMilliseconds())})
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
	if !terminalExpiryAuditEvent(events[4], fact.Plan().Scope(), 5, events[3].Identity(), audit.EventRouteSelected, selected.SubjectIdentity(), selected.CausalParentIdentities(), values[12].CreatedAt(), proof.failed.OccurredAt()) {
		return errTerminalModelExpiry
	}
	authorization := authority.Authorization()
	if !terminalExpiryAuditEvent(events[5], fact.Plan().Scope(), 6, events[4].Identity(), audit.EventRouteAttemptClaimed, authorization.Identity(), []string{authorization.SelectionReceiptIdentity()}, values[12].CreatedAt(), values[12].CreatedAt()) {
		return errTerminalModelExpiry
	}
	return nil
}
