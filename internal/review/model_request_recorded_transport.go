package review

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"

	"github.com/georgejieh/open-trestle/internal/provider"
)

// RecordedInvestigationTurnTransportBytes re-measures, from the exact request
// of a retained investigation turn, the trusted system channel bytes and the
// local structured-output response_format bytes an adapter sends with it. These
// are the counts an investigation turn estimate version 2 records, so readback
// can refuse a record whose counts were not measured from its own request.
//
// The contract is read from the version the request records, so a turn stays
// measurable after a later version becomes the only executable one. An
// executable request is measured exactly as ModelRequestSystemChannelBytes and
// ModelRequestResponseFormatBytes measure it. A recorded investigation context
// of version 5 or 6, or a local verification envelope around a recorded
// verification context whose contract travels only in the system channel, is
// measured by its pinned contract. Any other request, including an
// investigation context of version 4, which predates the recorded counts, is
// refused.
func RecordedInvestigationTurnTransportBytes(request provider.Request) (uint32, uint32, error) {
	if request.Validate() != nil || request.Capability() != provider.CapabilityReviewV1 || request.MediaType() != "application/json" {
		return 0, 0, ErrInvalidModelRequestContract
	}
	_, contract := modelRequestMeasuredPayloads(request)
	instructions, instructionsErr := TrustedModelRequestInstructions(contract)
	schema, schemaErr := TrustedModelRequestOutputSchema(contract)
	if instructionsErr != nil || schemaErr != nil {
		var err error
		instructions, schema, err = recordedInvestigationTurnContract(request.Payload())
		if err != nil {
			return 0, 0, err
		}
	}
	return uint32(min(uint64(len(instructions)), math.MaxUint32)), localStructuredOutputFramingBytes(schema), nil
}

func recordedInvestigationTurnContract(payload []byte) (string, json.RawMessage, error) {
	var header struct {
		Contract            string `json:"contract"`
		SchemaVersion       int    `json:"schema_version"`
		ReviewScopeIdentity string `json:"review_scope_identity"`
	}
	if len(payload) == 0 || len(payload) > maxProviderContextPacketBytes || rejectAmbiguousModelRequestJSON(payload) != nil || json.Unmarshal(payload, &header) != nil {
		return "", nil, ErrInvalidModelRequestContract
	}
	switch header.Contract {
	case "open-trestle/review-context-packet":
		if ValidateRecordedInvestigationContext(payload) != nil {
			return "", nil, ErrInvalidModelRequestContract
		}
		switch header.SchemaVersion {
		case investigationContextVersionV5:
			return investigationInstructionsV5, InvestigationOutputSchema(), nil
		case investigationContextVersion:
			return investigationInstructionsV6, InvestigationOutputSchema(), nil
		}
	case "open-trestle/local-verification-envelope":
		inner, err := recordedLocalVerificationPayload(payload, header.ReviewScopeIdentity)
		if err != nil {
			return "", nil, err
		}
		wire, err := decodeVerificationContextWire(inner)
		if err != nil || wire.ReviewScopeIdentity != header.ReviewScopeIdentity || wire.Task != "candidate_verification" || wire.OutputSchemaIdentity != ModelVerificationBatchSchemaIdentity ||
			!contractInSystemChannelOnly(wire.SchemaVersion, true) || !validRecordedModelOutputContract(wire.SchemaVersion, wire.Instructions, wire.InstructionsIdentity, wire.OutputSchema, true) {
			return "", nil, ErrInvalidModelRequestContract
		}
		return modelOutputContractForVersion(wire.SchemaVersion, true)
	}
	return "", nil, ErrInvalidModelRequestContract
}

// recordedLocalVerificationPayload returns the inner request payload of exact
// version 1 local verification envelope bytes without requiring the inner
// verification context to be the executable version.
func recordedLocalVerificationPayload(payload []byte, reviewScopeIdentity string) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var wire localVerificationEnvelopeWire
	if decoder.Decode(&wire) != nil {
		return nil, ErrInvalidModelRequestContract
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, ErrInvalidModelRequestContract
	}
	canonical, err := json.Marshal(wire)
	if err != nil || !bytes.Equal(canonical, payload) || wire.Contract != "open-trestle/local-verification-envelope" || wire.SchemaVersion != 1 || wire.ReviewScopeIdentity != reviewScopeIdentity || !validCandidateDigest(reviewScopeIdentity) || wire.Capability != provider.CapabilityReviewV1.String() || wire.MediaType != "application/json" || !validCandidateDigest(wire.RawRequestIdentity) {
		return nil, ErrInvalidModelRequestContract
	}
	raw, err := provider.NewRequest(provider.CapabilityReviewV1, wire.MediaType, wire.Payload)
	if err != nil || raw.Identity() != wire.RawRequestIdentity {
		return nil, ErrInvalidModelRequestContract
	}
	return raw.Payload(), nil
}
