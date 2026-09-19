package provider

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestNewKnownRoutePerformanceObservationBindsValues(t *testing.T) {
	observation, err := NewKnownRoutePerformanceObservation(routeRegistryEvidenceDigest, 9, 250, minRouteLatencySampleCount)
	if err != nil {
		t.Fatal(err)
	}
	if observation.RecordIdentity() != routeRegistryEvidenceDigest || observation.ObservationRevision() != 9 || !observation.LatencyKnown() || observation.P95LatencyMilliseconds() != 250 || observation.SampleCount() != minRouteLatencySampleCount || observation.Validate() != nil {
		t.Fatalf("observation did not round trip: %#v", observation)
	}
}

func TestNewUnknownRoutePerformanceObservationIsExplicit(t *testing.T) {
	observation, err := NewUnknownRoutePerformanceObservation(routeRegistryEvidenceDigest, 10)
	if err != nil {
		t.Fatal(err)
	}
	if observation.RecordIdentity() != routeRegistryEvidenceDigest || observation.ObservationRevision() != 10 || observation.LatencyKnown() || observation.P95LatencyMilliseconds() != 0 || observation.SampleCount() != 0 || observation.Validate() != nil {
		t.Fatalf("unknown observation did not round trip: %#v", observation)
	}
}

func TestRoutePerformanceObservationRejectsInvalidValuesInOrder(t *testing.T) {
	valid := RoutePerformanceObservation{
		recordIdentity:         routeRegistryEvidenceDigest,
		observationRevision:    1,
		latencyKnown:           true,
		p95LatencyMilliseconds: 1,
		sampleCount:            minRouteLatencySampleCount,
	}
	for _, test := range []struct {
		name        string
		observation RoutePerformanceObservation
		want        error
	}{
		{name: "identity", observation: RoutePerformanceObservation{}, want: ErrInvalidRoutePerformanceIdentity},
		{name: "revision", observation: RoutePerformanceObservation{recordIdentity: routeRegistryEvidenceDigest}, want: ErrInvalidRoutePerformanceRevision},
		{name: "latency zero", observation: RoutePerformanceObservation{recordIdentity: routeRegistryEvidenceDigest, observationRevision: 1, latencyKnown: true, sampleCount: minRouteLatencySampleCount}, want: ErrInvalidRouteLatency},
		{name: "latency high", observation: RoutePerformanceObservation{recordIdentity: routeRegistryEvidenceDigest, observationRevision: 1, latencyKnown: true, p95LatencyMilliseconds: maxRouteLatencyMilliseconds + 1, sampleCount: minRouteLatencySampleCount}, want: ErrInvalidRouteLatency},
		{name: "samples", observation: RoutePerformanceObservation{recordIdentity: routeRegistryEvidenceDigest, observationRevision: 1, latencyKnown: true, p95LatencyMilliseconds: 1, sampleCount: minRouteLatencySampleCount - 1}, want: ErrInsufficientRouteLatencySamples},
		{name: "unknown latency payload", observation: RoutePerformanceObservation{recordIdentity: routeRegistryEvidenceDigest, observationRevision: 1, p95LatencyMilliseconds: 1}, want: ErrInvalidRouteLatency},
		{name: "unknown sample payload", observation: RoutePerformanceObservation{recordIdentity: routeRegistryEvidenceDigest, observationRevision: 1, sampleCount: 1}, want: ErrInsufficientRouteLatencySamples},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := test.observation.Validate(); !errors.Is(err, test.want) {
				t.Fatalf("Validate() = %v, want %v", err, test.want)
			}
		})
	}
	if valid.Validate() != nil {
		t.Fatal("valid observation rejected")
	}
}

func TestRoutePerformanceObservationConstructorsRejectBoundaries(t *testing.T) {
	for _, test := range []struct {
		name     string
		known    bool
		identity string
		revision uint64
		latency  uint32
		samples  uint32
		want     error
	}{
		{name: "identity", known: true, identity: "bad", revision: 1, latency: 1, samples: minRouteLatencySampleCount, want: ErrInvalidRoutePerformanceIdentity},
		{name: "revision", known: true, identity: routeRegistryEvidenceDigest, latency: 1, samples: minRouteLatencySampleCount, want: ErrInvalidRoutePerformanceRevision},
		{name: "latency", known: true, identity: routeRegistryEvidenceDigest, revision: 1, samples: minRouteLatencySampleCount, want: ErrInvalidRouteLatency},
		{name: "samples", known: true, identity: routeRegistryEvidenceDigest, revision: 1, latency: 1, samples: minRouteLatencySampleCount - 1, want: ErrInsufficientRouteLatencySamples},
		{name: "unknown identity", identity: "bad", revision: 1, want: ErrInvalidRoutePerformanceIdentity},
		{name: "unknown revision", identity: routeRegistryEvidenceDigest, want: ErrInvalidRoutePerformanceRevision},
	} {
		t.Run(test.name, func(t *testing.T) {
			var observation RoutePerformanceObservation
			var err error
			if test.known {
				observation, err = NewKnownRoutePerformanceObservation(test.identity, test.revision, test.latency, test.samples)
			} else {
				observation, err = NewUnknownRoutePerformanceObservation(test.identity, test.revision)
			}
			if !errors.Is(err, test.want) || observation != (RoutePerformanceObservation{}) {
				t.Fatalf("constructor = (%#v, %v), want %v", observation, err, test.want)
			}
		})
	}
}

func TestRoutePerformanceObservationSurfaceAndFormatting(t *testing.T) {
	typeOfObservation := reflect.TypeOf(RoutePerformanceObservation{})
	want := []string{"recordIdentity", "observationRevision", "latencyKnown", "p95LatencyMilliseconds", "sampleCount"}
	if typeOfObservation.NumField() != len(want) {
		t.Fatalf("RoutePerformanceObservation has %d fields", typeOfObservation.NumField())
	}
	for index, name := range want {
		if field := typeOfObservation.Field(index); field.Name != name {
			t.Fatalf("field %d = %q, want %q", index, field.Name, name)
		}
	}
	observation, _ := NewKnownRoutePerformanceObservation(routeRegistryEvidenceDigest, 1, 1, minRouteLatencySampleCount)
	for _, format := range []string{"%s", "%v", "%+v", "%q", "%#v", "%d", "%x"} {
		formatted := fmt.Sprintf(format, observation)
		if strings.Contains(formatted, routeRegistryEvidenceDigest) {
			t.Fatalf("format %q exposed route identity: %q", format, formatted)
		}
	}
}
