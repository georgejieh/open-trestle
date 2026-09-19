package provider

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"strings"
	"unicode/utf8"
)

const (
	maxProviderResponseParts            = 64
	maxProviderResponsePartPayloadBytes = 2 << 20
	maxProviderResponsePayloadBytes     = 8 << 20
)

var (
	// ErrInvalidResponsePartKind identifies an unknown normalized response part.
	ErrInvalidResponsePartKind = errors.New("invalid provider response part kind")
	// ErrInvalidResponsePartMediaType identifies a malformed or kind-incompatible media type.
	ErrInvalidResponsePartMediaType = errors.New("invalid provider response part media type")
	// ErrInvalidResponsePartPayload identifies empty, malformed, or non-UTF-8 response content.
	ErrInvalidResponsePartPayload = errors.New("invalid provider response part payload")
	// ErrResponsePartPayloadTooLarge identifies one response part beyond its copied-content bound.
	ErrResponsePartPayloadTooLarge = errors.New("provider response part payload too large")
	// ErrInvalidResponseFinishReason identifies an unknown provider finish reason.
	ErrInvalidResponseFinishReason = errors.New("invalid provider response finish reason")
	// ErrInvalidProviderResponseParts identifies an empty or malformed part collection.
	ErrInvalidProviderResponseParts = errors.New("invalid provider response parts")
	// ErrTooManyProviderResponseParts identifies a response beyond the part-count bound.
	ErrTooManyProviderResponseParts = errors.New("too many provider response parts")
	// ErrProviderResponseTooLarge identifies aggregate response content beyond its bound.
	ErrProviderResponseTooLarge = errors.New("provider response too large")
	// ErrProviderResponseFinishMismatch identifies tool-call content inconsistent with the finish reason.
	ErrProviderResponseFinishMismatch = errors.New("provider response finish mismatch")
	// ErrInvalidProviderResponseIdentity identifies a response identity inconsistent with its contents.
	ErrInvalidProviderResponseIdentity = errors.New("invalid provider response identity")
)

// ResponsePartKind identifies one provider-neutral response content role.
type ResponsePartKind uint8

const (
	ResponsePartAssistantText ResponsePartKind = iota + 1
	ResponsePartToolCall
	ResponsePartToolResult
	ResponsePartRefusal
	ResponsePartCitation
	ResponsePartStructuredData
)

// String returns the stable response part kind token or an empty string.
func (k ResponsePartKind) String() string {
	switch k {
	case ResponsePartAssistantText:
		return "assistant_text"
	case ResponsePartToolCall:
		return "tool_call"
	case ResponsePartToolResult:
		return "tool_result"
	case ResponsePartRefusal:
		return "refusal"
	case ResponsePartCitation:
		return "citation"
	case ResponsePartStructuredData:
		return "structured_data"
	default:
		return ""
	}
}

// ParseResponsePartKind parses one exact stable response part kind token.
func ParseResponsePartKind(value string) (ResponsePartKind, error) {
	for kind := ResponsePartAssistantText; kind <= ResponsePartStructuredData; kind++ {
		if kind.String() == value {
			return kind, nil
		}
	}
	return 0, fmt.Errorf("parse response part kind: %w", ErrInvalidResponsePartKind)
}

// Validate verifies that the response part kind is recognized.
func (k ResponsePartKind) Validate() error {
	if k.String() == "" {
		return ErrInvalidResponsePartKind
	}
	return nil
}

// ResponsePart contains one immutable normalized response content segment.
// A tool-call part is an inert proposal. It does not authorize or execute a tool.
type ResponsePart struct {
	kind      ResponsePartKind
	mediaType string
	payload   string
}

// NewResponsePart copies and validates one bounded response segment.
func NewResponsePart(kind ResponsePartKind, mediaType string, payload []byte) (ResponsePart, error) {
	if len(mediaType) > maxProviderMediaTypeBytes {
		return ResponsePart{}, ErrInvalidResponsePartMediaType
	}
	canonicalMediaType := strings.TrimSpace(mediaType)
	if err := validateResponsePartFields(kind, canonicalMediaType, payload); err != nil {
		return ResponsePart{}, err
	}
	return ResponsePart{kind: kind, mediaType: strings.Clone(canonicalMediaType), payload: string(payload)}, nil
}

func (p ResponsePart) Kind() ResponsePartKind { return p.kind }
func (p ResponsePart) MediaType() string      { return p.mediaType }
func (p ResponsePart) SizeBytes() int         { return len(p.payload) }

// Payload returns a defensive copy of the part content.
func (p ResponsePart) Payload() []byte {
	if p.payload == "" {
		return nil
	}
	return []byte(p.payload)
}

func (p ResponsePart) String() string   { return "provider response part" }
func (p ResponsePart) GoString() string { return "provider.ResponsePart{<redacted>}" }
func (p ResponsePart) Format(state fmt.State, verb rune) {
	formatted := "provider response part"
	if verb == 'q' {
		formatted = `"provider response part"`
	} else if verb == 'v' && state.Flag('#') {
		formatted = "provider.ResponsePart{<redacted>}"
	}
	_, _ = state.Write([]byte(formatted))
}

// Validate verifies that the response part remains canonical and bounded.
func (p ResponsePart) Validate() error {
	if p.mediaType != strings.TrimSpace(p.mediaType) {
		return ErrInvalidResponsePartMediaType
	}
	return validateResponsePartFields(p.kind, p.mediaType, []byte(p.payload))
}

func validateResponsePartFields(kind ResponsePartKind, mediaType string, payload []byte) error {
	if err := kind.Validate(); err != nil {
		return err
	}
	if mediaType == "" || len(mediaType) > maxProviderMediaTypeBytes {
		return ErrInvalidResponsePartMediaType
	}
	baseMediaType, _, err := mime.ParseMediaType(mediaType)
	if err != nil {
		return ErrInvalidResponsePartMediaType
	}
	if len(payload) == 0 {
		return ErrInvalidResponsePartPayload
	}
	if len(payload) > maxProviderResponsePartPayloadBytes {
		return ErrResponsePartPayloadTooLarge
	}
	if !utf8.Valid(payload) {
		return ErrInvalidResponsePartPayload
	}
	switch kind {
	case ResponsePartAssistantText, ResponsePartRefusal:
		if !strings.HasPrefix(baseMediaType, "text/") {
			return ErrInvalidResponsePartMediaType
		}
	case ResponsePartToolCall, ResponsePartToolResult, ResponsePartCitation, ResponsePartStructuredData:
		if baseMediaType != "application/json" {
			return ErrInvalidResponsePartMediaType
		}
		if !json.Valid(payload) {
			return ErrInvalidResponsePartPayload
		}
	}
	return nil
}

// ResponseFinishReason identifies why a provider stopped producing the response.
type ResponseFinishReason uint8

const (
	ResponseFinishStop ResponseFinishReason = iota + 1
	ResponseFinishLength
	ResponseFinishToolCalls
	ResponseFinishContentFilter
)

func (r ResponseFinishReason) String() string {
	switch r {
	case ResponseFinishStop:
		return "stop"
	case ResponseFinishLength:
		return "length"
	case ResponseFinishToolCalls:
		return "tool_calls"
	case ResponseFinishContentFilter:
		return "content_filter"
	default:
		return ""
	}
}

// ParseResponseFinishReason parses one exact stable finish token.
func ParseResponseFinishReason(value string) (ResponseFinishReason, error) {
	for reason := ResponseFinishStop; reason <= ResponseFinishContentFilter; reason++ {
		if reason.String() == value {
			return reason, nil
		}
	}
	return 0, fmt.Errorf("parse response finish reason: %w", ErrInvalidResponseFinishReason)
}

func (r ResponseFinishReason) Validate() error {
	if r.String() == "" {
		return ErrInvalidResponseFinishReason
	}
	return nil
}

// Response is one immutable content-addressed provider-neutral result.
type Response struct {
	identity     string
	capability   Capability
	finishReason ResponseFinishReason
	parts        []ResponsePart
	usage        RouteTokenUsage
}

// NewResponse copies and validates a complete normalized provider response.
func NewResponse(capability Capability, finishReason ResponseFinishReason, parts []ResponsePart, usage RouteTokenUsage) (Response, error) {
	if len(parts) > maxProviderResponseParts {
		return Response{}, ErrTooManyProviderResponseParts
	}
	response := Response{
		capability: capability, finishReason: finishReason,
		parts: append([]ResponsePart(nil), parts...), usage: usage,
	}
	if err := response.validateFields(); err != nil {
		return Response{}, err
	}
	response.identity = deriveProviderResponseIdentity(response)
	return response, nil
}

func (r Response) Identity() string                   { return r.identity }
func (r Response) Capability() Capability             { return r.capability }
func (r Response) FinishReason() ResponseFinishReason { return r.finishReason }
func (r Response) PartCount() int                     { return len(r.parts) }
func (r Response) Usage() RouteTokenUsage             { return r.usage }

// Parts returns a defensive copy of the immutable response parts.
func (r Response) Parts() []ResponsePart { return append([]ResponsePart(nil), r.parts...) }

func (r Response) String() string   { return "provider response" }
func (r Response) GoString() string { return "provider.Response{<redacted>}" }
func (r Response) Format(state fmt.State, verb rune) {
	formatted := "provider response"
	if verb == 'q' {
		formatted = `"provider response"`
	} else if verb == 'v' && state.Flag('#') {
		formatted = "provider.Response{<redacted>}"
	}
	_, _ = state.Write([]byte(formatted))
}

// Validate verifies all part bounds, finish semantics, usage, and content identity.
func (r Response) Validate() error {
	if err := r.validateFields(); err != nil {
		return err
	}
	if r.identity != deriveProviderResponseIdentity(r) {
		return ErrInvalidProviderResponseIdentity
	}
	return nil
}

func (r Response) validateFields() error {
	if r.capability != CapabilityReviewV1 {
		return ErrInvalidCapability
	}
	if err := r.finishReason.Validate(); err != nil {
		return err
	}
	if len(r.parts) == 0 {
		return ErrInvalidProviderResponseParts
	}
	if len(r.parts) > maxProviderResponseParts {
		return ErrTooManyProviderResponseParts
	}
	if err := r.usage.Validate(); err != nil {
		return err
	}
	totalBytes := 0
	hasToolCall := false
	for _, part := range r.parts {
		if err := part.Validate(); err != nil {
			return err
		}
		totalBytes += part.SizeBytes()
		if totalBytes > maxProviderResponsePayloadBytes {
			return ErrProviderResponseTooLarge
		}
		hasToolCall = hasToolCall || part.Kind() == ResponsePartToolCall
	}
	if hasToolCall != (r.finishReason == ResponseFinishToolCalls) {
		return ErrProviderResponseFinishMismatch
	}
	return nil
}

func deriveProviderResponseIdentity(response Response) string {
	type partIdentity struct {
		Kind          string `json:"kind"`
		MediaTypeB64  string `json:"media_type_b64"`
		PayloadDigest string `json:"payload_digest"`
		PayloadBytes  int    `json:"payload_bytes"`
	}
	parts := make([]partIdentity, len(response.parts))
	for index, part := range response.parts {
		digest := sha256String(part.payload)
		parts[index] = partIdentity{
			Kind: part.kind.String(), MediaTypeB64: base64.StdEncoding.EncodeToString([]byte(part.mediaType)),
			PayloadDigest: hex.EncodeToString(digest[:]), PayloadBytes: len(part.payload),
		}
	}
	preimage := struct {
		Contract      string         `json:"contract"`
		SchemaVersion int            `json:"schema_version"`
		Capability    string         `json:"capability"`
		FinishReason  string         `json:"finish_reason"`
		Parts         []partIdentity `json:"parts"`
		UsageKnown    bool           `json:"usage_known"`
		InputTokens   uint32         `json:"input_tokens"`
		OutputTokens  uint32         `json:"output_tokens"`
		CachedTokens  uint32         `json:"cached_tokens"`
	}{
		Contract: "open-trestle/provider-response", SchemaVersion: 1,
		Capability: response.capability.String(), FinishReason: response.finishReason.String(), Parts: parts,
		UsageKnown: response.usage.IsKnown(), InputTokens: response.usage.InputTokens(),
		OutputTokens: response.usage.OutputTokens(), CachedTokens: response.usage.CachedInputTokens(),
	}
	encoded, err := json.Marshal(preimage)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
