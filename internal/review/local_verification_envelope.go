package review

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/georgejieh/open-trestle/internal/provider"
)

type localVerificationEnvelopeWire struct {
	Contract            string `json:"contract"`
	SchemaVersion       int    `json:"schema_version"`
	ReviewScopeIdentity string `json:"review_scope_identity"`
	RawRequestIdentity  string `json:"raw_request_identity"`
	Capability          string `json:"capability"`
	MediaType           string `json:"media_type"`
	Payload             []byte `json:"payload"`
}

func NewLocalVerificationRequest(raw provider.Request, reviewScopeIdentity string) (provider.Request, error) {
	if ValidateVerificationModelRequest(raw, reviewScopeIdentity) != nil {
		return provider.Request{}, ErrInvalidModelRequestContract
	}
	wire := localVerificationEnvelopeWire{
		Contract: "open-trestle/local-verification-envelope", SchemaVersion: 1,
		ReviewScopeIdentity: reviewScopeIdentity, RawRequestIdentity: raw.Identity(),
		Capability: raw.Capability().String(), MediaType: raw.MediaType(), Payload: raw.Payload(),
	}
	encoded, err := json.Marshal(wire)
	if err != nil {
		return provider.Request{}, ErrInvalidModelRequestContract
	}
	request, err := provider.NewRequest(raw.Capability(), "application/json", encoded)
	if err != nil || ValidateLocalVerificationRequest(request, reviewScopeIdentity) != nil {
		return provider.Request{}, ErrInvalidModelRequestContract
	}
	return request, nil
}

func ValidateLocalVerificationRequest(request provider.Request, reviewScopeIdentity string) error {
	_, err := parseLocalVerificationRequest(request, reviewScopeIdentity)
	return err
}

func LocalVerificationPayload(request provider.Request, reviewScopeIdentity string, zone provider.ProviderZone) ([]byte, error) {
	if zone != provider.ProviderZoneLocal {
		return nil, ErrInvalidModelRequestContract
	}
	raw, err := parseLocalVerificationRequest(request, reviewScopeIdentity)
	if err != nil {
		return nil, ErrInvalidModelRequestContract
	}
	return raw.Payload(), nil
}

func parseLocalVerificationRequest(request provider.Request, reviewScopeIdentity string) (provider.Request, error) {
	if request.Validate() != nil || request.Capability() != provider.CapabilityReviewV1 || request.MediaType() != "application/json" || !validCandidateDigest(reviewScopeIdentity) || rejectAmbiguousModelRequestJSON(request.Payload()) != nil {
		return provider.Request{}, ErrInvalidModelRequestContract
	}
	decoder := json.NewDecoder(bytes.NewReader(request.Payload()))
	decoder.DisallowUnknownFields()
	var wire localVerificationEnvelopeWire
	if decoder.Decode(&wire) != nil {
		return provider.Request{}, ErrInvalidModelRequestContract
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return provider.Request{}, ErrInvalidModelRequestContract
	}
	canonical, err := json.Marshal(wire)
	if err != nil || !bytes.Equal(canonical, request.Payload()) || wire.Contract != "open-trestle/local-verification-envelope" || wire.SchemaVersion != 1 || wire.ReviewScopeIdentity != reviewScopeIdentity || wire.Capability != provider.CapabilityReviewV1.String() || wire.MediaType != "application/json" || !validCandidateDigest(wire.RawRequestIdentity) {
		return provider.Request{}, ErrInvalidModelRequestContract
	}
	raw, err := provider.NewRequest(provider.CapabilityReviewV1, wire.MediaType, wire.Payload)
	if err != nil || raw.Identity() != wire.RawRequestIdentity || ValidateVerificationModelRequest(raw, reviewScopeIdentity) != nil {
		return provider.Request{}, ErrInvalidModelRequestContract
	}
	return raw, nil
}
