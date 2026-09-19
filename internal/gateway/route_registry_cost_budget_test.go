package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/georgejieh/open-trestle/internal/provider"
)

func newFilterResolvedRecordWithPricing(t *testing.T, revision uint64, pricing provider.RoutePricing) ResolvedRouteRegistryRecord {
	t.Helper()
	manifest := []byte("route pricing evidence")
	digest := sha256.Sum256(manifest)
	capability := newRouteCompatibilityDeclaration(t, provider.ProviderZoneLocal, 128_000, 16_000, provider.ModelFeatureStructuredOutput)
	candidate, err := provider.NewRouteCandidateDeclaration(capability, provider.ContentLoggingDisabled, pricing, provider.RouteQualityTier1)
	if err != nil {
		t.Fatal(err)
	}
	record, err := provider.NewRouteRegistryRecord(revision, candidate, provider.RouteRegistryApproved, hex.EncodeToString(digest[:]))
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := ResolveRouteRegistryRecord(context.Background(), record.Identity(), &routeRegistryReaderStub{record: record}, &routeEvidenceManifestReaderStub{content: manifest})
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

func TestCheckResolvedRouteCostBudgetUsesBoundKnownPricing(t *testing.T) {
	pricing, _ := provider.NewRoutePricing(1_000_000, 1_000_000)
	resolved := newFilterResolvedRecordWithPricing(t, 1, pricing)
	budget, _ := provider.NewModelCostBudget(2, 3, 5)
	if err := CheckResolvedRouteCostBudget(resolved, budget); err != nil {
		t.Fatalf("CheckResolvedRouteCostBudget() = %v", err)
	}
}

func TestCheckResolvedRouteCostBudgetRejectsUnknownAndOverBudget(t *testing.T) {
	unknown := newFilterResolvedRecordWithPricing(t, 1, provider.NewUnknownRoutePricing())
	known, _ := provider.NewRoutePricing(1_000_000, 1_000_000)
	overBudget := newFilterResolvedRecordWithPricing(t, 1, known)
	budget, _ := provider.NewModelCostBudget(2, 3, 4)
	for _, test := range []struct {
		name     string
		resolved ResolvedRouteRegistryRecord
		want     error
	}{
		{name: "unknown", resolved: unknown, want: provider.ErrUnknownRoutePricing},
		{name: "over budget", resolved: overBudget, want: ErrRouteCostExceedsBudget},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := CheckResolvedRouteCostBudget(test.resolved, budget); !errors.Is(err, test.want) {
				t.Fatalf("CheckResolvedRouteCostBudget() = %v, want %v", err, test.want)
			}
		})
	}
}

func TestCheckResolvedRouteCostBudgetRejectsInvalidValues(t *testing.T) {
	pricing, _ := provider.NewRoutePricing(0, 0)
	resolved := newFilterResolvedRecordWithPricing(t, 1, pricing)
	validBudget, _ := provider.NewModelCostBudget(1, 1, 0)
	for _, test := range []struct {
		name     string
		resolved ResolvedRouteRegistryRecord
		budget   provider.ModelCostBudget
		want     error
	}{
		{name: "record", budget: validBudget, want: provider.ErrInvalidRouteRegistryRevision},
		{name: "budget", resolved: resolved, want: provider.ErrInvalidModelCostBudget},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := CheckResolvedRouteCostBudget(test.resolved, test.budget); !errors.Is(err, test.want) {
				t.Fatalf("CheckResolvedRouteCostBudget() = %v, want %v", err, test.want)
			}
		})
	}
}
