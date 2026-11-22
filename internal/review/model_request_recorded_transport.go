package review

import (
	"math"

	"github.com/georgejieh/open-trestle/internal/provider"
)

// RecordedInvestigationTurnTransportBytes re-measures, from the exact request
// of a retained investigation turn, the trusted system channel bytes and the
// local structured-output response_format bytes an adapter sends with it, as
// ModelRequestSystemChannelBytes and ModelRequestResponseFormatBytes measure
// them. These are the counts an investigation turn estimate records, so
// readback can refuse a record whose counts were not measured from its own
// request. A request without a trusted contract is refused.
func RecordedInvestigationTurnTransportBytes(request provider.Request) (uint32, uint32, error) {
	if request.Validate() != nil || request.Capability() != provider.CapabilityReviewV1 || request.MediaType() != "application/json" {
		return 0, 0, ErrInvalidModelRequestContract
	}
	_, contract := modelRequestMeasuredPayloads(request)
	instructions, instructionsErr := TrustedModelRequestInstructions(contract)
	schema, schemaErr := TrustedModelRequestOutputSchema(contract)
	if instructionsErr != nil || schemaErr != nil {
		return 0, 0, ErrInvalidModelRequestContract
	}
	return uint32(min(uint64(len(instructions)), math.MaxUint32)), localStructuredOutputFramingBytes(schema), nil
}
