package gateway

import (
	"testing"

	"github.com/georgejieh/open-trestle/internal/provider"
)

func newRouteCandidate(t *testing.T, zone provider.ProviderZone, logging provider.ContentLoggingMode, contextTokens, outputTokens uint64, features ...provider.ModelFeature) provider.RouteCandidateDeclaration {
	t.Helper()
	capability := newRouteCompatibilityDeclaration(t, zone, contextTokens, outputTokens, features...)
	candidate, err := provider.NewRouteCandidateDeclaration(capability, logging, provider.NewUnknownRoutePricing(), provider.RouteQualityTier1)
	if err != nil {
		t.Fatal(err)
	}
	return candidate
}
