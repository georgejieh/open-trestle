package review

import (
	"encoding/json"
	"math"

	"github.com/georgejieh/open-trestle/internal/provider"
)

// ModelRequestTransport names the request wire whose bytes an input estimate
// counts.
type ModelRequestTransport uint8

const (
	// ModelRequestTransportStandard sends the request payload and the trusted
	// system channel. ModelRequestBudget estimates it.
	ModelRequestTransportStandard ModelRequestTransport = iota
	// ModelRequestTransportLocalStructuredOutput is the Chat schema transport
	// of the opt-in local option and of OpenRouter structured verification. It
	// also sends a serialized response_format that carries the request's
	// host-pinned output schema.
	ModelRequestTransportLocalStructuredOutput
)

// localStructuredOutputSchemaName is the fixed json_schema name that the local
// structured-output transport sends.
const localStructuredOutputSchemaName = "open_trestle_review"

func (t ModelRequestTransport) String() string {
	switch t {
	case ModelRequestTransportStandard:
		return "standard"
	case ModelRequestTransportLocalStructuredOutput:
		return "local_structured_output"
	}
	return ""
}

func (t ModelRequestTransport) Validate() error {
	if t.String() == "" {
		return ErrInvalidModelRequestContract
	}
	return nil
}

// localStructuredOutputFramingWire mirrors the response_format member, with its
// field wrapper, that the OpenAI-compatible adapter serializes and counts.
type localStructuredOutputFramingWire struct {
	ResponseFormat struct {
		Type       string `json:"type"`
		JSONSchema struct {
			Name   string          `json:"name"`
			Strict bool            `json:"strict"`
			Schema json.RawMessage `json:"schema"`
		} `json:"json_schema"`
	} `json:"response_format"`
}

// ModelRequestResponseFormatBytes returns the byte length of the serialized
// response_format object, including its field wrapper, that the local
// structured-output transport sends with request:
// {"response_format":{"type":"json_schema","json_schema":{"name":"open_trestle_review","strict":true,"schema":S}}}.
// S is the host-pinned output schema of the request the adapter unwraps, as
// for ModelRequestSystemChannelBytes, so the count is deterministic from that
// schema. A request without a trusted contract returns 0; the adapter refuses
// to send it.
func ModelRequestResponseFormatBytes(request provider.Request) uint32 {
	_, contract := modelRequestMeasuredPayloads(request)
	schema, err := TrustedModelRequestOutputSchema(contract)
	if err != nil {
		return 0
	}
	return localStructuredOutputFramingBytes(schema)
}

func localStructuredOutputFramingBytes(schema json.RawMessage) uint32 {
	var wire localStructuredOutputFramingWire
	wire.ResponseFormat.Type = "json_schema"
	wire.ResponseFormat.JSONSchema.Name = localStructuredOutputSchemaName
	wire.ResponseFormat.JSONSchema.Strict = true
	wire.ResponseFormat.JSONSchema.Schema = schema
	encoded, err := json.Marshal(wire)
	if err != nil {
		return 0
	}
	return uint32(min(uint64(len(encoded)), math.MaxUint32))
}

// ModelRequestBudgetForTransport is ModelRequestBudget for the request wire
// that transport sends. The standard transport is ModelRequestBudget itself.
// The local structured-output transport also counts
// ModelRequestResponseFormatBytes, so a reservation planned with it covers
// everything the adapter checks and sends.
func ModelRequestBudgetForTransport(request provider.Request, declared provider.ModelCostBudget, transport ModelRequestTransport) (provider.ModelCostBudget, error) {
	if err := transport.Validate(); err != nil {
		return provider.ModelCostBudget{}, err
	}
	if transport == ModelRequestTransportStandard {
		return ModelRequestBudget(request, declared)
	}
	if err := request.Validate(); err != nil {
		return provider.ModelCostBudget{}, err
	}
	if err := declared.Validate(); err != nil {
		return provider.ModelCostBudget{}, err
	}
	payload, systemBytes := modelRequestEstimateParts(request)
	estimated := max(uint64(declared.EstimatedInputTokens()), uint64(len(payload))+uint64(systemBytes)+uint64(ModelRequestResponseFormatBytes(request))+modelRequestFramingReserve)
	return provider.NewModelCostBudget(estimated, uint64(declared.MaxOutputTokens()), declared.MaxCostMicroUSD())
}
