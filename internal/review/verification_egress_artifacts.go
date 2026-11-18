package review

import (
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/internal/provider"
)

func NewSanitizedVerificationEgressArtifacts(raw provider.Request, generationContextIdentity, candidateBatchIdentity string, generation, generationInput, generationContext artifact.Artifact, request SanitizedModelRequest, receipt SanitizedEgressReceipt, expected ScannerBinaryDigests, createdAt time.Time) (artifact.Artifact, artifact.Artifact, error) {
	if !validVerificationEgressEvidence(raw, generationContextIdentity, candidateBatchIdentity, generation, generationInput, generationContext) || request.Validate() != nil || receipt.Validate() != nil || !expected.validate() || createdAt.Before(generation.CreatedAt()) || !createdAt.Before(generationContext.ExpiresAt()) {
		return artifact.Artifact{}, artifact.Artifact{}, ErrInvalidSanitizedEgressArtifacts
	}
	if request.ReviewScopeIdentity() != generation.Scope().Identity() || request.RawRequestIdentity() != raw.Identity() || receipt.ReviewScopeIdentity() != generation.Scope().Identity() || receipt.RawRequestIdentity() != raw.Identity() || receipt.SanitizedRequestIdentity() != request.SanitizedRequestIdentity() || receipt.Scanner().HelperSHA256 != expected.HelperSHA256 || validateSanitizedRequestProjection(raw, request, receipt) != nil {
		return artifact.Artifact{}, artifact.Artifact{}, ErrInvalidSanitizedEgressArtifacts
	}
	requestPayload, err := EncodeSanitizedModelRequest(request)
	if err != nil {
		return artifact.Artifact{}, artifact.Artifact{}, ErrInvalidSanitizedEgressArtifacts
	}
	evidence := verificationEgressEvidence(generation, generationInput, generationContext)
	requestArtifact, err := artifact.New(generation.Scope(), artifact.KindSanitizedModelRequest, "application/json", generation.Classification(), artifact.OriginHost, generation.Protection(), evidence, requestPayload, createdAt, generationContext.ExpiresAt())
	if err != nil {
		return artifact.Artifact{}, artifact.Artifact{}, ErrInvalidSanitizedEgressArtifacts
	}
	receiptPayload, err := EncodeSanitizedEgressReceipt(receipt)
	if err != nil {
		return artifact.Artifact{}, artifact.Artifact{}, ErrInvalidSanitizedEgressArtifacts
	}
	receiptProvenance := append(verificationEgressEvidence(generation, generationInput, generationContext), requestArtifact.Identity())
	receiptArtifact, err := artifact.New(generation.Scope(), artifact.KindSanitizedEgressReceipt, "application/json", generation.Classification(), artifact.OriginHost, generation.Protection(), receiptProvenance, receiptPayload, createdAt, generationContext.ExpiresAt())
	if err != nil || ValidateSanitizedVerificationEgressArtifacts(raw, generationContextIdentity, candidateBatchIdentity, generation, generationInput, generationContext, requestArtifact, receiptArtifact, expected) != nil {
		return artifact.Artifact{}, artifact.Artifact{}, ErrInvalidSanitizedEgressArtifacts
	}
	return requestArtifact, receiptArtifact, nil
}

func ValidateSanitizedVerificationEgressArtifacts(raw provider.Request, generationContextIdentity, candidateBatchIdentity string, generation, generationInput, generationContext, requestArtifact, receiptArtifact artifact.Artifact, expected ScannerBinaryDigests) error {
	if !expected.validate() || !validVerificationEgressEvidence(raw, generationContextIdentity, candidateBatchIdentity, generation, generationInput, generationContext) || requestArtifact.Validate() != nil || receiptArtifact.Validate() != nil || requestArtifact.Kind() != artifact.KindSanitizedModelRequest || receiptArtifact.Kind() != artifact.KindSanitizedEgressReceipt || requestArtifact.MediaType() != "application/json" || receiptArtifact.MediaType() != "application/json" || requestArtifact.Origin() != artifact.OriginHost || receiptArtifact.Origin() != artifact.OriginHost {
		return ErrInvalidSanitizedEgressArtifacts
	}
	if requestArtifact.Scope().Identity() != generation.Scope().Identity() || receiptArtifact.Scope().Identity() != generation.Scope().Identity() || requestArtifact.Classification() != generation.Classification() || receiptArtifact.Classification() != generation.Classification() || requestArtifact.Protection() != generation.Protection() || receiptArtifact.Protection() != generation.Protection() || !requestArtifact.CreatedAt().Equal(receiptArtifact.CreatedAt()) || requestArtifact.CreatedAt().Before(generation.CreatedAt()) || !requestArtifact.ExpiresAt().Equal(generationContext.ExpiresAt()) || !receiptArtifact.ExpiresAt().Equal(generationContext.ExpiresAt()) || !exactProvenance(requestArtifact.Provenance(), verificationEgressEvidence(generation, generationInput, generationContext)) || !exactProvenance(receiptArtifact.Provenance(), append(verificationEgressEvidence(generation, generationInput, generationContext), requestArtifact.Identity())) {
		return ErrInvalidSanitizedEgressArtifacts
	}
	request, err := ParseSanitizedModelRequest(requestArtifact.Payload())
	if err != nil {
		return ErrInvalidSanitizedEgressArtifacts
	}
	receipt, err := ParseSanitizedEgressReceipt(receiptArtifact.Payload())
	if err != nil || receipt.Scanner().HelperSHA256 != expected.HelperSHA256 || request.ReviewScopeIdentity() != generation.Scope().Identity() || receipt.ReviewScopeIdentity() != generation.Scope().Identity() || request.RawRequestIdentity() != raw.Identity() || receipt.RawRequestIdentity() != raw.Identity() || request.SanitizedRequestIdentity() != receipt.SanitizedRequestIdentity() {
		return ErrInvalidSanitizedEgressArtifacts
	}
	rebuilt, err := request.ProviderRequest()
	if err != nil || rebuilt.Identity() != receipt.SanitizedRequestIdentity() || validateSanitizedRequestProjection(raw, request, receipt) != nil {
		return ErrInvalidSanitizedEgressArtifacts
	}
	return nil
}

func validVerificationEgressEvidence(raw provider.Request, generationContextIdentity, candidateBatchIdentity string, generation, generationInput, generationContext artifact.Artifact) bool {
	wire, wireErr := decodeVerificationContextWire(raw.Payload())
	if wireErr != nil || wire.GenerationContextIdentity != generationContextIdentity || wire.CandidateBatchIdentity != candidateBatchIdentity || !validCandidateDigest(generationContextIdentity) || !validCandidateDigest(candidateBatchIdentity) {
		return false
	}
	if raw.Validate() != nil || raw.Capability() != provider.CapabilityReviewV1 || raw.MediaType() != "application/json" || generation.Validate() != nil || generationInput.Validate() != nil || generationContext.Validate() != nil || generation.Kind() != artifact.KindCandidateBatch || generationInput.Kind() != artifact.KindTaskInput || generationContext.Kind() != artifact.KindContextPacket || generation.Origin() != artifact.OriginModel || generationInput.Origin() != artifact.OriginHost || generationContext.Origin() != artifact.OriginHost || generation.Scope().Identity() != generationInput.Scope().Identity() || generation.Scope().Identity() != generationContext.Scope().Identity() || generation.Classification() != generationInput.Classification() || generation.Classification() != generationContext.Classification() || generation.Protection() != generationInput.Protection() || generation.Protection() != generationContext.Protection() || !generation.ExpiresAt().Equal(generationInput.ExpiresAt()) || !generation.ExpiresAt().Equal(generationContext.ExpiresAt()) || !hasArtifactProvenance(generation.Provenance(), generationInput.Identity()) || !hasArtifactProvenance(generation.Provenance(), generationContext.Identity()) || ValidateVerificationModelRequest(raw, generation.Scope().Identity()) != nil {
		return false
	}
	return true
}

func verificationEgressEvidence(generation, generationInput, generationContext artifact.Artifact) []string {
	return []string{generation.Identity(), generationInput.Identity(), generationContext.Identity()}
}

func hasArtifactProvenance(values []string, identity string) bool {
	for _, value := range values {
		if value == identity {
			return true
		}
	}
	return false
}
