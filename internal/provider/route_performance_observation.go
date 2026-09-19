package provider

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const (
	minRouteLatencySampleCount  uint32 = 20
	maxRouteLatencyMilliseconds uint32 = 86_400_000
)

var (
	// ErrInvalidRoutePerformanceIdentity identifies a malformed registry-record identity.
	ErrInvalidRoutePerformanceIdentity = errors.New("invalid route performance identity")
	// ErrInvalidRoutePerformanceRevision identifies a missing performance observation revision.
	ErrInvalidRoutePerformanceRevision = errors.New("invalid route performance revision")
	// ErrInvalidRouteLatency identifies a malformed P95 latency value.
	ErrInvalidRouteLatency = errors.New("invalid route latency")
	// ErrInsufficientRouteLatencySamples identifies a P95 based on too few observations.
	ErrInsufficientRouteLatencySamples = errors.New("insufficient route latency samples")
)

// RoutePerformanceObservation binds a known or unknown latency measurement to one registry record.
type RoutePerformanceObservation struct {
	recordIdentity         string
	observationRevision    uint64
	latencyKnown           bool
	p95LatencyMilliseconds uint32
	sampleCount            uint32
}

// NewKnownRoutePerformanceObservation creates a record-bound sampled P95 latency observation.
func NewKnownRoutePerformanceObservation(recordIdentity string, observationRevision uint64, p95LatencyMilliseconds, sampleCount uint32) (RoutePerformanceObservation, error) {
	observation := RoutePerformanceObservation{
		recordIdentity:         strings.Clone(recordIdentity),
		observationRevision:    observationRevision,
		latencyKnown:           true,
		p95LatencyMilliseconds: p95LatencyMilliseconds,
		sampleCount:            sampleCount,
	}
	if err := observation.Validate(); err != nil {
		return RoutePerformanceObservation{}, err
	}
	return observation, nil
}

// NewUnknownRoutePerformanceObservation creates an explicit record-bound unknown latency observation.
func NewUnknownRoutePerformanceObservation(recordIdentity string, observationRevision uint64) (RoutePerformanceObservation, error) {
	observation := RoutePerformanceObservation{
		recordIdentity:      strings.Clone(recordIdentity),
		observationRevision: observationRevision,
	}
	if err := observation.Validate(); err != nil {
		return RoutePerformanceObservation{}, err
	}
	return observation, nil
}

// RecordIdentity returns the exact registry-record identity observed.
func (o RoutePerformanceObservation) RecordIdentity() string { return o.recordIdentity }

// ObservationRevision returns the caller-managed performance snapshot revision.
func (o RoutePerformanceObservation) ObservationRevision() uint64 { return o.observationRevision }

// LatencyKnown reports whether a sampled P95 is available.
func (o RoutePerformanceObservation) LatencyKnown() bool { return o.latencyKnown }

// P95LatencyMilliseconds returns the P95 latency or zero when unknown.
func (o RoutePerformanceObservation) P95LatencyMilliseconds() uint32 {
	return o.p95LatencyMilliseconds
}

// SampleCount returns the contributing request count or zero when latency is unknown.
func (o RoutePerformanceObservation) SampleCount() uint32 { return o.sampleCount }

// String returns a redacted performance-observation description.
func (o RoutePerformanceObservation) String() string { return "route performance observation" }

// GoString returns a redacted Go-syntax performance-observation description.
func (o RoutePerformanceObservation) GoString() string {
	return "provider.RoutePerformanceObservation{<redacted>}"
}

// Format writes a redacted representation for verbs dispatched through fmt.Formatter.
func (o RoutePerformanceObservation) Format(state fmt.State, verb rune) {
	formatted := "route performance observation"
	if verb == 'q' {
		formatted = `"route performance observation"`
	} else if verb == 'v' && state.Flag('#') {
		formatted = "provider.RoutePerformanceObservation{<redacted>}"
	}
	_, _ = state.Write([]byte(formatted))
}

// Validate verifies identity, revision, and known-or-unknown latency state in order.
func (o RoutePerformanceObservation) Validate() error {
	if !validRoutePerformanceIdentity(o.recordIdentity) {
		return ErrInvalidRoutePerformanceIdentity
	}
	if o.observationRevision == 0 {
		return ErrInvalidRoutePerformanceRevision
	}
	if o.latencyKnown {
		if o.p95LatencyMilliseconds == 0 || o.p95LatencyMilliseconds > maxRouteLatencyMilliseconds {
			return ErrInvalidRouteLatency
		}
		if o.sampleCount < minRouteLatencySampleCount {
			return ErrInsufficientRouteLatencySamples
		}
		return nil
	}
	if o.p95LatencyMilliseconds != 0 {
		return ErrInvalidRouteLatency
	}
	if o.sampleCount != 0 {
		return ErrInsufficientRouteLatencySamples
	}
	return nil
}

func validRoutePerformanceIdentity(identity string) bool {
	if len(identity) != sha256.Size*2 || identity != strings.ToLower(identity) {
		return false
	}
	_, err := hex.DecodeString(identity)
	return err == nil
}
