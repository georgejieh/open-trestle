package main

import (
	"errors"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/controlplane"
	contexthandler "github.com/georgejieh/open-trestle/handlers/context"
	modelhandler "github.com/georgejieh/open-trestle/handlers/model"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/runtimecatalog"
)

var errInvalidLocalContextInput = errors.New("invalid local context input")

func localInputArtifactDescriptor(value artifact.Artifact) controlplane.ContextInputArtifactDescriptor {
	return controlplane.ContextInputArtifactDescriptor{
		ArtifactIdentity: value.Identity(), PayloadDigest: value.PayloadDigest(),
		Classification: value.Classification().String(), Protection: value.Protection().String(),
		Provenance: value.Provenance(), CreatedAtMilliseconds: value.CreatedAt().UnixMilli(),
		ExpiresAtMilliseconds: value.ExpiresAt().UnixMilli(),
	}
}

// buildLocalContextInputDescriptor describes an unpersisted candidate. It grants
// no append, artifact write, model dispatch or settlement authority.
func buildLocalContextInputDescriptor(packet controlplane.PreparedContextPacket, lease controlplane.TaskLease, candidate contexthandler.SanitizedPacketCandidate, input artifact.Artifact, grant gateway.RouteAttemptAuthorization, route runtimecatalog.LocalGenerationRoutePlan, authorizerIdentity string) (controlplane.ContextInputDescriptor, error) {
	request, receipt := candidate.RequestArtifact(), candidate.ReceiptArtifact()
	if lease.Validate() != nil || packet.Identity() == "" || grant.Validate() != nil ||
		request.Validate() != nil || receipt.Validate() != nil || input.Validate() != nil ||
		request.Kind() != artifact.KindSanitizedModelRequest || receipt.Kind() != artifact.KindSanitizedEgressReceipt ||
		input.Kind() != artifact.KindTaskInput || packet.Descriptor().ArtifactIdentity != candidate.Packet().Artifact().Identity() ||
		grant.SelectionReceiptIdentity() != route.SelectionIdentity() || grant.RouteRecordIdentity() != route.SelectedRecordIdentity() ||
		route.RequestIdentity() != grant.RequestIdentity() || authorizerIdentity == "" {
		return controlplane.ContextInputDescriptor{}, errInvalidLocalContextInput
	}
	generationInput, err := modelhandler.ParseGenerationInput(input.Payload())
	if err != nil || !generationInput.IsSanitized() || generationInput.ContextArtifactIdentity() != packet.Descriptor().ArtifactIdentity ||
		generationInput.SanitizedRequestArtifactIdentity() != request.Identity() || generationInput.SanitizedEgressReceiptArtifactIdentity() != receipt.Identity() ||
		generationInput.Authorization().Identity() != grant.Identity() {
		return controlplane.ContextInputDescriptor{}, errInvalidLocalContextInput
	}
	scanner := candidate.Scanner()
	descriptor := controlplane.ContextInputDescriptor{
		PacketPreparedEventIdentity: packet.Identity(), PacketArtifactIdentity: packet.Descriptor().ArtifactIdentity,
		LeaseIdentity: lease.Identity(), LeaseEventIdentity: lease.EventIdentity(),
		Request: localInputArtifactDescriptor(request), Receipt: localInputArtifactDescriptor(receipt), Input: localInputArtifactDescriptor(input),
		ReceiptIdentity: candidate.Receipt().Identity(), ScannerLauncherDigest: scanner.LauncherSHA256, ScannerWorkerDigest: scanner.WorkerSHA256,
		GenerationInputIdentity: generationInput.Identity(), AuthorizationIdentity: grant.Identity(),
		SelectionReceiptIdentity: grant.SelectionReceiptIdentity(), RoutingInputIdentity: route.RoutingInputIdentity(),
		SelectedRecordIdentity: route.SelectedRecordIdentity(), PolicyIdentity: route.PolicyIdentity(), RoutePairIdentity: route.PairIdentity(),
		AuthorizerIdentity: authorizerIdentity, SanitizerIdentity: candidate.SanitizerIdentity(), RegistryRevision: route.RegistryRevision(),
		PerformanceRevision: route.PerformanceRevision(),
	}
	return descriptor, nil
}
