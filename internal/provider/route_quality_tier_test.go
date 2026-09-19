package provider

import (
	"errors"
	"testing"
)

func TestRouteQualityTierRoundTrips(t *testing.T) {
	for _, test := range []struct {
		tier  RouteQualityTier
		token string
	}{
		{RouteQualityTier1, "tier_1"},
		{RouteQualityTier2, "tier_2"},
		{RouteQualityTier3, "tier_3"},
		{RouteQualityTier4, "tier_4"},
	} {
		parsed, err := ParseRouteQualityTier(test.token)
		if err != nil || parsed != test.tier || test.tier.String() != test.token || test.tier.Validate() != nil {
			t.Fatalf("quality tier round trip = (%v, %v, %q)", parsed, err, test.tier.String())
		}
	}
}

func TestRouteQualityTierRejectsUnknownValues(t *testing.T) {
	for _, token := range []string{"", "unknown", "tier_0", "tier_5", " tier_1", "TIER_1"} {
		if tier, err := ParseRouteQualityTier(token); !errors.Is(err, ErrInvalidRouteQualityTier) || tier != 0 {
			t.Fatalf("ParseRouteQualityTier(%q) = (%v, %v)", token, tier, err)
		}
	}
	if (RouteQualityTier(0)).String() != "" || !errors.Is(RouteQualityTier(0).Validate(), ErrInvalidRouteQualityTier) {
		t.Fatal("zero quality tier did not fail closed")
	}
}
