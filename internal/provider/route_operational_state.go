package provider

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

var (
	// ErrInvalidRouteHealth identifies an unknown health observation.
	ErrInvalidRouteHealth = errors.New("invalid route health")
	// ErrInvalidRouteQuota identifies an unknown quota observation.
	ErrInvalidRouteQuota = errors.New("invalid route quota")
	// ErrInvalidRouteOperationalRecordIdentity identifies a malformed registry record identity.
	ErrInvalidRouteOperationalRecordIdentity = errors.New("invalid route operational record identity")
	// ErrInvalidRouteOperationalRevision identifies a missing observation revision.
	ErrInvalidRouteOperationalRevision = errors.New("invalid route operational revision")
)

// RouteHealth identifies the observed health of one route.
type RouteHealth uint8

const (
	RouteHealthHealthy RouteHealth = iota + 1
	RouteHealthUnhealthy
	RouteHealthUnknown
)

// String returns the stable health token or an empty string for unknown values.
func (h RouteHealth) String() string {
	switch h {
	case RouteHealthHealthy:
		return "healthy"
	case RouteHealthUnhealthy:
		return "unhealthy"
	case RouteHealthUnknown:
		return "unknown"
	default:
		return ""
	}
}

// ParseRouteHealth parses one exact stable health token.
func ParseRouteHealth(value string) (RouteHealth, error) {
	switch value {
	case "healthy":
		return RouteHealthHealthy, nil
	case "unhealthy":
		return RouteHealthUnhealthy, nil
	case "unknown":
		return RouteHealthUnknown, nil
	default:
		return 0, fmt.Errorf("parse route health: %w", ErrInvalidRouteHealth)
	}
}

// Validate verifies that the health observation is known.
func (h RouteHealth) Validate() error {
	if h.String() == "" {
		return fmt.Errorf("validate route health: %w", ErrInvalidRouteHealth)
	}
	return nil
}

// RouteQuota identifies the observed request quota state of one route.
type RouteQuota uint8

const (
	RouteQuotaAvailable RouteQuota = iota + 1
	RouteQuotaExhausted
	RouteQuotaUnknown
)

// String returns the stable quota token or an empty string for unknown values.
func (q RouteQuota) String() string {
	switch q {
	case RouteQuotaAvailable:
		return "available"
	case RouteQuotaExhausted:
		return "exhausted"
	case RouteQuotaUnknown:
		return "unknown"
	default:
		return ""
	}
}

// ParseRouteQuota parses one exact stable quota token.
func ParseRouteQuota(value string) (RouteQuota, error) {
	switch value {
	case "available":
		return RouteQuotaAvailable, nil
	case "exhausted":
		return RouteQuotaExhausted, nil
	case "unknown":
		return RouteQuotaUnknown, nil
	default:
		return 0, fmt.Errorf("parse route quota: %w", ErrInvalidRouteQuota)
	}
}

// Validate verifies that the quota observation is known.
func (q RouteQuota) Validate() error {
	if q.String() == "" {
		return fmt.Errorf("validate route quota: %w", ErrInvalidRouteQuota)
	}
	return nil
}

// RouteOperationalState binds dynamic readiness observations to one registry record.
type RouteOperationalState struct {
	recordIdentity      string
	observationRevision uint64
	health              RouteHealth
	quota               RouteQuota
}

// NewRouteOperationalState creates an immutable readiness observation.
func NewRouteOperationalState(recordIdentity string, observationRevision uint64, health RouteHealth, quota RouteQuota) (RouteOperationalState, error) {
	state := RouteOperationalState{
		recordIdentity:      strings.Clone(recordIdentity),
		observationRevision: observationRevision,
		health:              health,
		quota:               quota,
	}
	if err := state.Validate(); err != nil {
		return RouteOperationalState{}, err
	}
	return state, nil
}

// RecordIdentity returns the bound registry record identity.
func (s RouteOperationalState) RecordIdentity() string { return s.recordIdentity }

// ObservationRevision returns the positive operational-state sequence.
func (s RouteOperationalState) ObservationRevision() uint64 { return s.observationRevision }

// Health returns the observed health state.
func (s RouteOperationalState) Health() RouteHealth { return s.health }

// Quota returns the observed quota state.
func (s RouteOperationalState) Quota() RouteQuota { return s.quota }

// String returns a redacted operational-state description.
func (s RouteOperationalState) String() string { return "route operational state" }

// GoString returns a redacted Go-syntax operational-state description.
func (s RouteOperationalState) GoString() string {
	return "provider.RouteOperationalState{<redacted>}"
}

// Format writes a redacted representation for verbs dispatched through fmt.Formatter.
func (s RouteOperationalState) Format(state fmt.State, verb rune) {
	formatted := "route operational state"
	if verb == 'q' {
		formatted = `"route operational state"`
	} else if verb == 'v' && state.Flag('#') {
		formatted = "provider.RouteOperationalState{<redacted>}"
	}
	_, _ = state.Write([]byte(formatted))
}

// Validate verifies record identity, revision, health, and quota in order.
func (s RouteOperationalState) Validate() error {
	if len(s.recordIdentity) != sha256.Size*2 || s.recordIdentity != strings.ToLower(s.recordIdentity) {
		return fmt.Errorf("validate route operational record identity: %w", ErrInvalidRouteOperationalRecordIdentity)
	}
	if _, err := hex.DecodeString(s.recordIdentity); err != nil {
		return fmt.Errorf("validate route operational record identity: %w", ErrInvalidRouteOperationalRecordIdentity)
	}
	if s.observationRevision == 0 {
		return fmt.Errorf("validate route operational revision: %w", ErrInvalidRouteOperationalRevision)
	}
	if err := s.health.Validate(); err != nil {
		return err
	}
	return s.quota.Validate()
}
