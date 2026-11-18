package review

import (
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/internal/provider"
)

func NewSanitizedEgressArtifacts(raw artifact.Artifact, request SanitizedModelRequest, receipt SanitizedEgressReceipt, expected ScannerBinaryDigests, createdAt time.Time) (artifact.Artifact, artifact.Artifact, error) {
	if !validRawSanitizedEgressArtifact(raw) || request.Validate() != nil || receipt.Validate() != nil || !expected.validate() || receipt.Scanner().HelperSHA256 != expected.HelperSHA256 || createdAt.Before(raw.CreatedAt()) || !createdAt.Before(raw.ExpiresAt()) {
		return artifact.Artifact{}, artifact.Artifact{}, ErrInvalidSanitizedEgressArtifacts
	}
	rawRequest, err := provider.NewRequest(provider.CapabilityReviewV1, raw.MediaType(), raw.Payload())
	if err != nil || request.ReviewScopeIdentity() != raw.Scope().Identity() || request.RawRequestIdentity() != rawRequest.Identity() || receipt.ReviewScopeIdentity() != raw.Scope().Identity() || receipt.RawRequestIdentity() != rawRequest.Identity() || receipt.SanitizedRequestIdentity() != request.SanitizedRequestIdentity() {
		return artifact.Artifact{}, artifact.Artifact{}, ErrInvalidSanitizedEgressArtifacts
	}
	requestPayload, err := EncodeSanitizedModelRequest(request)
	if err != nil {
		return artifact.Artifact{}, artifact.Artifact{}, ErrInvalidSanitizedEgressArtifacts
	}
	requestArtifact, err := artifact.New(raw.Scope(), artifact.KindSanitizedModelRequest, "application/json", raw.Classification(), artifact.OriginHost, raw.Protection(), []string{raw.Identity()}, requestPayload, createdAt, raw.ExpiresAt())
	if err != nil {
		return artifact.Artifact{}, artifact.Artifact{}, ErrInvalidSanitizedEgressArtifacts
	}
	receiptPayload, err := EncodeSanitizedEgressReceipt(receipt)
	if err != nil {
		return artifact.Artifact{}, artifact.Artifact{}, ErrInvalidSanitizedEgressArtifacts
	}
	receiptArtifact, err := artifact.New(raw.Scope(), artifact.KindSanitizedEgressReceipt, "application/json", raw.Classification(), artifact.OriginHost, raw.Protection(), []string{raw.Identity(), requestArtifact.Identity()}, receiptPayload, createdAt, raw.ExpiresAt())
	if err != nil {
		return artifact.Artifact{}, artifact.Artifact{}, ErrInvalidSanitizedEgressArtifacts
	}
	if ValidateSanitizedEgressArtifacts(raw, requestArtifact, receiptArtifact, expected) != nil {
		return artifact.Artifact{}, artifact.Artifact{}, ErrInvalidSanitizedEgressArtifacts
	}
	return requestArtifact, receiptArtifact, nil
}

func ValidateSanitizedEgressArtifacts(raw, requestArtifact, receiptArtifact artifact.Artifact, expected ScannerBinaryDigests) error {
	if !expected.validate() || !validRawSanitizedEgressArtifact(raw) || requestArtifact.Validate() != nil || receiptArtifact.Validate() != nil || requestArtifact.Kind() != artifact.KindSanitizedModelRequest || receiptArtifact.Kind() != artifact.KindSanitizedEgressReceipt || requestArtifact.MediaType() != "application/json" || receiptArtifact.MediaType() != "application/json" || requestArtifact.Origin() != artifact.OriginHost || receiptArtifact.Origin() != artifact.OriginHost {
		return ErrInvalidSanitizedEgressArtifacts
	}
	if requestArtifact.Scope().Identity() != raw.Scope().Identity() || receiptArtifact.Scope().Identity() != raw.Scope().Identity() || requestArtifact.Classification() != raw.Classification() || receiptArtifact.Classification() != raw.Classification() || requestArtifact.Protection() != raw.Protection() || receiptArtifact.Protection() != raw.Protection() || !requestArtifact.CreatedAt().Equal(receiptArtifact.CreatedAt()) || requestArtifact.CreatedAt().Before(raw.CreatedAt()) || !requestArtifact.ExpiresAt().Equal(raw.ExpiresAt()) || !receiptArtifact.ExpiresAt().Equal(raw.ExpiresAt()) || !exactProvenance(requestArtifact.Provenance(), []string{raw.Identity()}) || !exactProvenance(receiptArtifact.Provenance(), []string{raw.Identity(), requestArtifact.Identity()}) {
		return ErrInvalidSanitizedEgressArtifacts
	}
	request, err := ParseSanitizedModelRequest(requestArtifact.Payload())
	if err != nil {
		return ErrInvalidSanitizedEgressArtifacts
	}
	receipt, err := ParseSanitizedEgressReceipt(receiptArtifact.Payload())
	if err != nil || receipt.Scanner().HelperSHA256 != expected.HelperSHA256 {
		return ErrInvalidSanitizedEgressArtifacts
	}
	rawRequest, err := provider.NewRequest(provider.CapabilityReviewV1, raw.MediaType(), raw.Payload())
	if err != nil || request.ReviewScopeIdentity() != raw.Scope().Identity() || receipt.ReviewScopeIdentity() != raw.Scope().Identity() || request.RawRequestIdentity() != rawRequest.Identity() || receipt.RawRequestIdentity() != rawRequest.Identity() || request.SanitizedRequestIdentity() != receipt.SanitizedRequestIdentity() {
		return ErrInvalidSanitizedEgressArtifacts
	}
	rebuiltRequest, err := request.ProviderRequest()
	if err != nil || rebuiltRequest.Identity() != receipt.SanitizedRequestIdentity() || validateSanitizedRequestProjection(rawRequest, request, receipt) != nil {
		return ErrInvalidSanitizedEgressArtifacts
	}
	return nil
}

func validRawSanitizedEgressArtifact(value artifact.Artifact) bool {
	return value.Validate() == nil && value.Kind() == artifact.KindContextPacket && value.MediaType() == "application/json" && value.Origin() == artifact.OriginHost
}
func exactProvenance(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	matched := make(map[string]bool, len(got))
	for _, value := range got {
		matched[value] = true
	}
	for _, value := range want {
		if !matched[value] {
			return false
		}
	}
	return true
}
