package main

import (
	"errors"
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
)

var errGenerationRejectionAudit = errors.New("generation rejection audit proof refused")

// validateGenerationRejectionAudit checks supplied records, not their physical
// storage, journal replay, enrollment or ownership. It grants no startup authority.
func validateGenerationRejectionAudit(events []audit.Event, value, inputArtifact, packet, requestArtifact, receiptArtifact artifact.Artifact, descriptor controlplane.ContextInputDescriptor, route runtimecatalog.LocalGenerationRoutePlan, handler string, now time.Time) error {
	fail := func() error { return errGenerationRejectionAudit }
	rejection, err := modelhandler.ParseGenerationRejectionArtifact(value, inputArtifact, packet)
	if err != nil || !physicalPacketDigest(handler) || rejection.HandlerIdentity() != handler || now.UnixMilli() <= 0 || now.Before(value.CreatedAt()) || !now.Before(value.ExpiresAt()) || !generationRejectionAuditShape(events) {
		return fail()
	}
	for _, item := range []artifact.Artifact{value, inputArtifact, packet, requestArtifact, receiptArtifact} {
		if item.Validate() != nil || item.Scope() != value.Scope() || item.Classification() != packet.Classification() || item.Protection() != packet.Protection() || now.Before(item.CreatedAt()) || !now.Before(item.ExpiresAt()) {
			return fail()
		}
	}
	if !reflect.DeepEqual(descriptor.Input, localInputArtifactDescriptor(inputArtifact)) || !reflect.DeepEqual(descriptor.Request, localInputArtifactDescriptor(requestArtifact)) || !reflect.DeepEqual(descriptor.Receipt, localInputArtifactDescriptor(receiptArtifact)) {
		return fail()
	}
	if review.ValidateSanitizedEgressArtifacts(packet, requestArtifact, receiptArtifact, review.ScannerBinaryDigests{LauncherSHA256: descriptor.ScannerLauncherDigest, WorkerSHA256: descriptor.ScannerWorkerDigest}) != nil {
		return fail()
	}
	input, err := modelhandler.ParseGenerationInput(inputArtifact.Payload())
	if err != nil {
		return fail()
	}
	attempt := rejection.Attempt()
	initial, authorization := input.Authorization(), attempt.Authorization()
	if initial.Kind() != gateway.RouteAttemptInitial || initial.AttemptOrdinal() != 1 || initial.RouteAttemptOrdinal() != 1 || initial.PreviousOutcomeIdentity() != "" || initial.ContinuationDecisionIdentity() != "" || initial.ReviewScopeIdentity() != value.Scope().Identity() || !gateway.IsSameReservationRetryOf(initial, authorization) {
		return fail()
	}
	// The refused attempts the handler retried left no artifact: their claims
	// must carry the lineage the gateway grants from the input's authorization.
	attempts, ok := recordedRouteAttempts(events, 1, initial.SelectionReceiptIdentity())
	if !ok || !routeAttemptsGrantedFrom(events, attempts, initial) || !finalRouteAttemptIs(events, attempts, authorization) {
		return fail()
	}
	sanitized, err := review.ParseSanitizedModelRequest(requestArtifact.Payload())
	if err != nil {
		return fail()
	}
	providerRequest, err := sanitized.ProviderRequest()
	if err != nil || providerRequest.Identity() != authorization.RequestIdentity() {
		return fail()
	}
	if descriptor.Input.ArtifactIdentity != inputArtifact.Identity() || descriptor.PacketArtifactIdentity != packet.Identity() || descriptor.GenerationInputIdentity != input.Identity() || descriptor.AuthorizationIdentity != initial.Identity() || descriptor.SelectionReceiptIdentity != initial.SelectionReceiptIdentity() || descriptor.SelectedRecordIdentity != initial.RouteRecordIdentity() || descriptor.Request.ArtifactIdentity != input.SanitizedRequestArtifactIdentity() || descriptor.Receipt.ArtifactIdentity != input.SanitizedEgressReceiptArtifactIdentity() || descriptor.ReceiptIdentity != input.SanitizedEgressReceiptIdentity() {
		return fail()
	}
	if !physicalPacketDigest(route.RankingPolicyIdentity()) || route.SelectionIdentity() != descriptor.SelectionReceiptIdentity || route.RoutingInputIdentity() != descriptor.RoutingInputIdentity || route.SelectedRecordIdentity() != descriptor.SelectedRecordIdentity || route.RequestIdentity() != authorization.RequestIdentity() || route.PolicyIdentity() != descriptor.PolicyIdentity || route.PairIdentity() != descriptor.RoutePairIdentity || route.RegistryRevision() != descriptor.RegistryRevision || route.PerformanceRevision() != descriptor.PerformanceRevision {
		return fail()
	}
	dispatch, err := attempt.DispatchResultIdentity()
	if err != nil {
		return fail()
	}
	final := attempts[len(attempts)-1].claim
	expected := []auditEventSpec{{audit.EventRouteSelected, initial.SelectionReceiptIdentity(), []string{route.RoutingInputIdentity(), route.SelectedRecordIdentity(), route.RankingPolicyIdentity()}}}
	for _, event := range events[1 : final+1] {
		expected = append(expected, recordedAuditEventSpec(event))
	}
	expected = append(expected,
		auditEventSpec{audit.EventRouteDispatchCompleted, attempt.Outcome().Identity(), []string{authorization.Identity(), dispatch, attempt.Outcome().ResponseIdentity()}},
		auditEventSpec{audit.EventRouteCostReconciled, attempt.Reconciliation().Identity(), []string{authorization.Identity(), attempt.Outcome().Identity()}},
		auditEventSpec{audit.EventGenerationRejected, value.Identity(), []string{inputArtifact.Identity(), packet.Identity(), attempt.Identity()}})
	previous := ""
	at := packet.CreatedAt().UnixMilli()
	for i, event := range events {
		spec := expected[i]
		slices.Sort(spec.parents)
		if event.Validate() != nil || event.Scope() != value.Scope() || event.Sequence() != uint64(i+1) || event.PreviousIdentity() != previous || event.Kind() != spec.kind || event.SubjectIdentity() != spec.subject || !slices.Equal(event.CausalParentIdentities(), spec.parents) || event.OccurredAtUnixMilliseconds() < at || event.OccurredAtUnixMilliseconds() > now.UnixMilli() {
			return fail()
		}
		previous, at = event.Identity(), event.OccurredAtUnixMilliseconds()
	}
	if events[len(events)-1].OccurredAtUnixMilliseconds() < value.CreatedAt().UnixMilli() {
		return fail()
	}
	return nil
}
