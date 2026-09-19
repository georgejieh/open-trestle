// Package runtimeconfig validates operator-owned runtime inventory and policy inputs.
package runtimeconfig

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"

	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
)

const maxInventoryRoutes = 64

var ErrInvalidRouteInventory = errors.New("invalid runtime route inventory")

type RouteDefinition struct {
	Route                  provider.RouteReference
	Capabilities           provider.ModelCapabilities
	ContentLogging         provider.ContentLoggingMode
	Pricing                provider.RoutePricing
	Quality                provider.RouteQualityTier
	RegistryRevision       uint64
	RegistryStatus         provider.RouteRegistryStatus
	EvidenceManifest       []byte
	OperationalRevision    uint64
	Health                 provider.RouteHealth
	Quota                  provider.RouteQuota
	PerformanceRevision    uint64
	P95LatencyMilliseconds uint32
	LatencySampleCount     uint32
}
type RouteInventory struct {
	identity            string
	registryRevision    uint64
	performanceRevision uint64
	candidates          []gateway.ObservedRouteCandidate
	performance         []provider.RoutePerformanceObservation
}

func NewRouteInventory(ctx context.Context, definitions []RouteDefinition) (RouteInventory, error) {
	if ctx == nil || ctx.Err() != nil || len(definitions) == 0 || len(definitions) > maxInventoryRoutes {
		return RouteInventory{}, ErrInvalidRouteInventory
	}
	candidates := make([]gateway.ObservedRouteCandidate, 0, len(definitions))
	performance := make([]provider.RoutePerformanceObservation, 0, len(definitions))
	seen := make(map[string]struct{}, len(definitions))
	registryRevision := definitions[0].RegistryRevision
	performanceRevision := definitions[0].PerformanceRevision
	if registryRevision == 0 || performanceRevision == 0 {
		return RouteInventory{}, ErrInvalidRouteInventory
	}
	for _, definition := range definitions {
		if definition.RegistryRevision != registryRevision || definition.PerformanceRevision != performanceRevision {
			return RouteInventory{}, ErrInvalidRouteInventory
		}
		capability, err := provider.NewRouteCapabilityDeclaration(definition.Route, definition.Capabilities)
		if err != nil {
			return RouteInventory{}, ErrInvalidRouteInventory
		}
		candidate, err := provider.NewRouteCandidateDeclaration(capability, definition.ContentLogging, definition.Pricing, definition.Quality)
		if err != nil {
			return RouteInventory{}, ErrInvalidRouteInventory
		}
		if len(definition.EvidenceManifest) == 0 {
			return RouteInventory{}, ErrInvalidRouteInventory
		}
		digest := sha256.Sum256(definition.EvidenceManifest)
		record, err := provider.NewRouteRegistryRecord(definition.RegistryRevision, candidate, definition.RegistryStatus, hex.EncodeToString(digest[:]))
		if err != nil {
			return RouteInventory{}, ErrInvalidRouteInventory
		}
		if _, exists := seen[record.Identity()]; exists {
			return RouteInventory{}, ErrInvalidRouteInventory
		}
		seen[record.Identity()] = struct{}{}
		source := inventorySource{record: record, manifest: append([]byte(nil), definition.EvidenceManifest...)}
		resolved, err := gateway.ResolveRouteRegistryRecord(ctx, record.Identity(), source, source)
		if err != nil {
			return RouteInventory{}, ErrInvalidRouteInventory
		}
		state, err := provider.NewRouteOperationalState(record.Identity(), definition.OperationalRevision, definition.Health, definition.Quota)
		if err != nil {
			return RouteInventory{}, ErrInvalidRouteInventory
		}
		observed, err := gateway.NewObservedRouteCandidate(resolved, state)
		if err != nil {
			return RouteInventory{}, ErrInvalidRouteInventory
		}
		var observation provider.RoutePerformanceObservation
		if definition.P95LatencyMilliseconds == 0 && definition.LatencySampleCount == 0 {
			observation, err = provider.NewUnknownRoutePerformanceObservation(record.Identity(), definition.PerformanceRevision)
		} else {
			observation, err = provider.NewKnownRoutePerformanceObservation(record.Identity(), definition.PerformanceRevision, definition.P95LatencyMilliseconds, definition.LatencySampleCount)
		}
		if err != nil {
			return RouteInventory{}, ErrInvalidRouteInventory
		}
		candidates = append(candidates, observed)
		performance = append(performance, observation)
	}
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].ResolvedRecord().RouteRegistryRecord().Identity() < candidates[j].ResolvedRecord().RouteRegistryRecord().Identity()
	})
	sort.Slice(performance, func(i, j int) bool { return performance[i].RecordIdentity() < performance[j].RecordIdentity() })
	value := RouteInventory{registryRevision: registryRevision, performanceRevision: performanceRevision, candidates: candidates, performance: performance}
	value.identity = inventoryIdentity(value)
	return value, nil
}
func (i RouteInventory) Identity() string            { return i.identity }
func (i RouteInventory) RegistryRevision() uint64    { return i.registryRevision }
func (i RouteInventory) PerformanceRevision() uint64 { return i.performanceRevision }
func (i RouteInventory) Candidates() []gateway.ObservedRouteCandidate {
	return append([]gateway.ObservedRouteCandidate(nil), i.candidates...)
}
func (i RouteInventory) PerformanceObservations() []provider.RoutePerformanceObservation {
	return append([]provider.RoutePerformanceObservation(nil), i.performance...)
}
func (i RouteInventory) Validate() error {
	if i.registryRevision == 0 || i.performanceRevision == 0 || len(i.candidates) == 0 || len(i.candidates) > maxInventoryRoutes || len(i.candidates) != len(i.performance) || i.identity != inventoryIdentity(i) {
		return ErrInvalidRouteInventory
	}
	previous := ""
	for index, candidate := range i.candidates {
		if candidate.Validate() != nil || candidate.ResolvedRecord().RouteRegistryRecord().RegistryRevision() != i.registryRevision {
			return ErrInvalidRouteInventory
		}
		identity := candidate.ResolvedRecord().RouteRegistryRecord().Identity()
		if identity <= previous || i.performance[index].Validate() != nil || i.performance[index].ObservationRevision() != i.performanceRevision || i.performance[index].RecordIdentity() != identity {
			return ErrInvalidRouteInventory
		}
		previous = identity
	}
	return nil
}

type inventorySource struct {
	record   provider.RouteRegistryRecord
	manifest []byte
}

func (s inventorySource) LookupRouteRegistryRecord(ctx context.Context, identity string) (provider.RouteRegistryRecord, error) {
	if ctx == nil || ctx.Err() != nil || identity != s.record.Identity() {
		return provider.RouteRegistryRecord{}, ErrInvalidRouteInventory
	}
	return s.record, nil
}
func (s inventorySource) OpenRouteEvidenceManifest(ctx context.Context, digest string) (io.ReadCloser, error) {
	if ctx == nil || ctx.Err() != nil || digest != s.record.EvidenceManifestDigest() {
		return nil, ErrInvalidRouteInventory
	}
	return io.NopCloser(bytes.NewReader(s.manifest)), nil
}
func inventoryIdentity(i RouteInventory) string {
	type item struct {
		Record              string `json:"record"`
		OperationalRevision uint64 `json:"operational_revision"`
		Health              string `json:"health"`
		Quota               string `json:"quota"`
		PerformanceRevision uint64 `json:"performance_revision"`
		LatencyKnown        bool   `json:"latency_known"`
		P95                 uint32 `json:"p95_latency_milliseconds"`
		Samples             uint32 `json:"sample_count"`
	}
	values := make([]item, len(i.candidates))
	for index, candidate := range i.candidates {
		state := candidate.OperationalState()
		observation := i.performance[index]
		values[index] = item{state.RecordIdentity(), state.ObservationRevision(), state.Health().String(), state.Quota().String(), observation.ObservationRevision(), observation.LatencyKnown(), observation.P95LatencyMilliseconds(), observation.SampleCount()}
	}
	sort.Slice(values, func(a, b int) bool { return values[a].Record < values[b].Record })
	encoded, _ := json.Marshal(struct {
		Contract            string `json:"contract"`
		Version             int    `json:"version"`
		RegistryRevision    uint64 `json:"registry_revision"`
		PerformanceRevision uint64 `json:"performance_revision"`
		Items               []item `json:"items"`
	}{"open-trestle/runtime-route-inventory", 1, i.registryRevision, i.performanceRevision, values})
	sum := sha256.Sum256(encoded)
	return strings.ToLower(hex.EncodeToString(sum[:]))
}
