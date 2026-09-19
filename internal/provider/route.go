package provider

import (
	"errors"
	"fmt"
	"strings"
)

// Bounds unresolved route labels before registry or policy resolution.
const (
	maxProviderIDBytes           = 64
	maxProviderAdapterIDBytes    = 64
	maxProviderConnectionIDBytes = 128
	maxProviderModelIDBytes      = 255
	maxProviderModelVersionBytes = 128
)

var (
	// ErrInvalidProviderZone identifies an unknown provider route class.
	ErrInvalidProviderZone = errors.New("invalid provider zone")
	// ErrInvalidProviderID identifies a malformed provider namespace label.
	ErrInvalidProviderID = errors.New("invalid provider ID")
	// ErrInvalidAdapterID identifies a malformed provider adapter label.
	ErrInvalidAdapterID = errors.New("invalid provider adapter ID")
	// ErrInvalidConnectionID identifies a malformed provider connection label.
	ErrInvalidConnectionID = errors.New("invalid provider connection ID")
	// ErrInvalidModelID identifies a malformed provider model label.
	ErrInvalidModelID = errors.New("invalid provider model ID")
	// ErrInvalidModelVersion identifies a malformed provider model version label.
	ErrInvalidModelVersion = errors.New("invalid provider model version")
)

// ProviderZone identifies a declared provider route class.
type ProviderZone uint8

const (
	ProviderZoneLocal ProviderZone = iota + 1
	ProviderZonePrivateRemote
	ProviderZoneBrokeredRemote
	ProviderZoneSubscriptionOAuth
)

// String returns the stable zone token or an empty string for unknown values.
func (z ProviderZone) String() string {
	switch z {
	case ProviderZoneLocal:
		return "local"
	case ProviderZonePrivateRemote:
		return "private_remote"
	case ProviderZoneBrokeredRemote:
		return "brokered_remote"
	case ProviderZoneSubscriptionOAuth:
		return "subscription_oauth"
	default:
		return ""
	}
}

// ParseProviderZone parses one exact stable provider zone token.
func ParseProviderZone(value string) (ProviderZone, error) {
	switch value {
	case "local":
		return ProviderZoneLocal, nil
	case "private_remote":
		return ProviderZonePrivateRemote, nil
	case "brokered_remote":
		return ProviderZoneBrokeredRemote, nil
	case "subscription_oauth":
		return ProviderZoneSubscriptionOAuth, nil
	default:
		return 0, fmt.Errorf("parse provider zone: %w", ErrInvalidProviderZone)
	}
}

// ValidateAdapterID verifies one stable adapter implementation identifier.
func ValidateAdapterID(adapterID string) error {
	if !validRouteRegistryID(adapterID, maxProviderAdapterIDBytes) {
		return fmt.Errorf("validate adapter ID: %w", ErrInvalidAdapterID)
	}
	return nil
}

// RouteReference binds non-secret labels for an unresolved model selection target.
type RouteReference struct {
	zone         ProviderZone
	providerID   string
	adapterID    string
	connectionID string
	modelID      string
	modelVersion string
}

// NewRouteReference creates an immutable unresolved route reference.
func NewRouteReference(zone ProviderZone, providerID, adapterID, connectionID, modelID, modelVersion string) (RouteReference, error) {
	if err := validateRouteReference(zone, providerID, adapterID, connectionID, modelID, modelVersion); err != nil {
		return RouteReference{}, err
	}
	return RouteReference{
		zone:         zone,
		providerID:   strings.Clone(providerID),
		adapterID:    strings.Clone(adapterID),
		connectionID: strings.Clone(connectionID),
		modelID:      strings.Clone(modelID),
		modelVersion: strings.Clone(modelVersion),
	}, nil
}

// Zone returns the declared provider zone.
func (r RouteReference) Zone() ProviderZone { return r.zone }

// ProviderID returns the provider namespace label.
func (r RouteReference) ProviderID() string { return r.providerID }

// AdapterID returns the opaque adapter label.
func (r RouteReference) AdapterID() string { return r.adapterID }

// ConnectionID returns the opaque connection label.
func (r RouteReference) ConnectionID() string { return r.connectionID }

// ModelID returns the exact model namespace label.
func (r RouteReference) ModelID() string { return r.modelID }

// ModelVersion returns the exact version or tag selector, or an empty string when unbound.
func (r RouteReference) ModelVersion() string { return r.modelVersion }

// String returns a redacted route description.
func (r RouteReference) String() string { return "provider route reference" }

// GoString returns a redacted Go-syntax route description.
func (r RouteReference) GoString() string { return "provider.RouteReference{<redacted>}" }

// Validate verifies that the unresolved reference remains canonical and bounded.
func (r RouteReference) Validate() error {
	return validateRouteReference(r.zone, r.providerID, r.adapterID, r.connectionID, r.modelID, r.modelVersion)
}

func validateRouteReference(zone ProviderZone, providerID, adapterID, connectionID, modelID, modelVersion string) error {
	if zone.String() == "" {
		return fmt.Errorf("validate provider zone: %w", ErrInvalidProviderZone)
	}
	if !validRouteRegistryID(providerID, maxProviderIDBytes) {
		return fmt.Errorf("validate provider ID: %w", ErrInvalidProviderID)
	}
	if !validRouteRegistryID(adapterID, maxProviderAdapterIDBytes) {
		return fmt.Errorf("validate adapter ID: %w", ErrInvalidAdapterID)
	}
	if !validRouteConnectionID(connectionID) {
		return fmt.Errorf("validate connection ID: %w", ErrInvalidConnectionID)
	}
	if !validRouteModelID(modelID) {
		return fmt.Errorf("validate model ID: %w", ErrInvalidModelID)
	}
	if !validRouteModelVersion(modelVersion) {
		return fmt.Errorf("validate model version: %w", ErrInvalidModelVersion)
	}
	return nil
}

func validRouteRegistryID(value string, maxBytes int) bool {
	if len(value) == 0 || len(value) > maxBytes || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' {
			continue
		}
		switch character {
		case '.', '_', '-':
		default:
			return false
		}
	}
	return true
}

func validRouteConnectionID(value string) bool {
	if len(value) == 0 || len(value) > maxProviderConnectionIDBytes {
		return false
	}
	segmentStart := true
	for index := 0; index < len(value); index++ {
		character := value[index]
		if segmentStart {
			if character < 'a' || character > 'z' {
				return false
			}
			segmentStart = false
			continue
		}
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' {
			continue
		}
		switch character {
		case '.', '_', '-':
		case '/':
			segmentStart = true
		default:
			return false
		}
	}
	return !segmentStart
}

func validRouteModelID(value string) bool {
	if len(value) == 0 || len(value) > maxProviderModelIDBytes {
		return false
	}
	segmentStart := true
	for index := 0; index < len(value); index++ {
		character := value[index]
		if segmentStart {
			if !isRouteModelAlphaNumeric(character) {
				return false
			}
			segmentStart = false
			continue
		}
		if isRouteModelAlphaNumeric(character) {
			continue
		}
		switch character {
		case '.', '_', '+', '-':
		case '/':
			segmentStart = true
		default:
			return false
		}
	}
	return !segmentStart
}

func validRouteModelVersion(value string) bool {
	if value == "" {
		return true
	}
	if len(value) > maxProviderModelVersionBytes || !isRouteModelAlphaNumeric(value[0]) {
		return false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if isRouteModelAlphaNumeric(character) {
			continue
		}
		switch character {
		case '.', '_', '+', '-':
		default:
			return false
		}
	}
	return true
}

func isRouteModelAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9'
}
