package review

import (
	"math"

	"github.com/georgejieh/open-trestle/internal/provider"
)

// ModelRequestSystemChannelBytes returns the byte length of the trusted system
// channel an adapter sends alongside request: the pinned host contract and any
// specialist guidance from TrustedModelRequestInstructions. A sanitized egress
// request and a local verification envelope are measured by the inner request
// they carry, which is the request the adapter unwraps and sends. A request
// without a trusted contract has no system channel and returns 0.
//
// ModelRequestBudget adds exactly these bytes to its estimate. Callers that
// plan or record an estimate outside this package count the same value.
func ModelRequestSystemChannelBytes(request provider.Request) uint32 {
	_, systemBytes := modelRequestEstimateParts(request)
	return systemBytes
}

// modelRequestEstimateParts returns the payload ModelRequestBudget measures and
// the system channel bytes sent with it. Only a sanitized verification request
// is measured by its smaller inner payload; every other request is measured by
// its complete payload.
func modelRequestEstimateParts(request provider.Request) ([]byte, uint32) {
	payload := request.Payload()
	instructionsPayload := payload
	if sanitized, err := ParseSanitizedModelRequest(payload); err == nil {
		instructionsPayload = sanitized.request.Payload()
		if ValidateVerificationModelRequest(sanitized.request, sanitized.ReviewScopeIdentity()) == nil {
			payload = instructionsPayload
		}
	} else if scope, err := ModelRequestReviewScopeIdentity(request); err == nil {
		if inner, err := LocalVerificationPayload(request, scope, provider.ProviderZoneLocal); err == nil {
			instructionsPayload = inner
		}
	}
	instructions, err := TrustedModelRequestInstructions(instructionsPayload)
	if err != nil {
		return payload, 0
	}
	// The system channel is bounded by the pinned contracts and the embedded
	// catalog; saturating keeps an impossible overflow from shrinking it.
	return payload, uint32(min(uint64(len(instructions)), math.MaxUint32))
}
