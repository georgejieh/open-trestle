package provider

import (
	"errors"
	"fmt"
	"mime"
	"strings"
)

// Bounds copied request metadata and content before any provider or route exists.
const (
	maxProviderMediaTypeBytes      = 255
	maxProviderRequestPayloadBytes = 8 << 20
)

var (
	// ErrInvalidCapability identifies an unsupported provider capability.
	ErrInvalidCapability = errors.New("invalid provider capability")
	// ErrInvalidMediaType identifies a missing or noncanonical media type.
	ErrInvalidMediaType = errors.New("invalid provider media type")
	// ErrInvalidPayload identifies an empty provider request payload.
	ErrInvalidPayload = errors.New("invalid provider payload")
	// ErrPayloadTooLarge identifies a payload beyond the copied-content bound.
	ErrPayloadTooLarge = errors.New("provider payload too large")
)

// Capability identifies a stable provider-neutral operation contract.
type Capability uint8

const (
	// CapabilityReviewV1 identifies the first bounded review request contract.
	CapabilityReviewV1 Capability = iota + 1
)

// String returns the stable capability token or an empty string for unknown values.
func (c Capability) String() string {
	if c == CapabilityReviewV1 {
		return "review.v1"
	}
	return ""
}

// ParseCapability parses one exact stable capability token.
func ParseCapability(value string) (Capability, error) {
	if value != "review.v1" {
		return 0, fmt.Errorf("parse capability: %w", ErrInvalidCapability)
	}
	return CapabilityReviewV1, nil
}

// Request contains one immutable provider-neutral payload.
type Request struct {
	capability Capability
	mediaType  string
	payload    string
}

// NewRequest creates an immutable bounded provider request value.
func NewRequest(capability Capability, mediaType string, payload []byte) (Request, error) {
	if len(mediaType) > maxProviderMediaTypeBytes {
		return Request{}, fmt.Errorf("validate media type: %w", ErrInvalidMediaType)
	}
	canonicalMediaType := strings.TrimSpace(mediaType)
	if err := validateRequestFields(capability, canonicalMediaType, len(payload)); err != nil {
		return Request{}, err
	}
	return Request{
		capability: capability,
		mediaType:  strings.Clone(canonicalMediaType),
		payload:    string(payload),
	}, nil
}

// Capability returns the requested provider-neutral operation.
func (r Request) Capability() Capability { return r.capability }

// MediaType returns the canonical trimmed payload media type.
func (r Request) MediaType() string { return r.mediaType }

// Payload returns a defensive copy of the opaque request bytes.
func (r Request) Payload() []byte {
	if r.payload == "" {
		return nil
	}
	return []byte(r.payload)
}

// String returns a redacted request description.
func (r Request) String() string { return "provider request" }

// GoString returns a redacted Go-syntax request description.
func (r Request) GoString() string { return "provider.Request{<redacted>}" }

// Format writes a redacted representation for verbs dispatched through fmt.Formatter.
func (r Request) Format(state fmt.State, verb rune) {
	formatted := "provider request"
	if verb == 'q' {
		formatted = `"provider request"`
	} else if verb == 'v' && state.Flag('#') {
		formatted = "provider.Request{<redacted>}"
	}
	_, _ = state.Write([]byte(formatted))
}

// Validate verifies that the request remains canonical and bounded.
func (r Request) Validate() error {
	if r.mediaType != strings.TrimSpace(r.mediaType) {
		return fmt.Errorf("validate media type: %w", ErrInvalidMediaType)
	}
	return validateRequestFields(r.capability, r.mediaType, len(r.payload))
}

func validateRequestFields(capability Capability, mediaType string, payloadBytes int) error {
	if capability != CapabilityReviewV1 {
		return fmt.Errorf("validate capability: %w", ErrInvalidCapability)
	}
	if mediaType == "" || len(mediaType) > maxProviderMediaTypeBytes {
		return fmt.Errorf("validate media type: %w", ErrInvalidMediaType)
	}
	if _, _, err := mime.ParseMediaType(mediaType); err != nil {
		return fmt.Errorf("validate media type: %w", ErrInvalidMediaType)
	}
	if payloadBytes == 0 {
		return fmt.Errorf("validate payload: %w", ErrInvalidPayload)
	}
	if payloadBytes > maxProviderRequestPayloadBytes {
		return fmt.Errorf("validate payload: %w", ErrPayloadTooLarge)
	}
	return nil
}
