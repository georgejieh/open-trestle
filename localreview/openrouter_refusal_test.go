package localreview

import (
	"bytes"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
)

// An OpenRouter 404 means no endpoint the request may use, which is how a
// zero-data-retention requirement refuses a model without ZDR endpoints.
// Another provider's 404 keeps the generic detail.
func TestRouteObserverNamesAnOpenRouterEndpointRefusal(t *testing.T) {
	pricing := observerPricing(t)
	for _, test := range []struct {
		name, providerID string
		zone             provider.ProviderZone
		results          []gateway.RouteDispatchResult
		want             string
	}{
		{"brokered OpenRouter", "openrouter", provider.ProviderZoneBrokeredRemote, []gateway.RouteDispatchResult{observedRefusal(t, gateway.RouteFailureModelUnavailable, gateway.RouteReplayNoSideEffect)}, FailureDetailProviderNoAllowedEndpoint},
		{"generic OpenRouter", "openrouter", provider.ProviderZonePrivateRemote, []gateway.RouteDispatchResult{observedRefusal(t, gateway.RouteFailureModelUnavailable, gateway.RouteReplayNoSideEffect)}, FailureDetailProviderNoAllowedEndpoint},
		{"another provider", "ollama-cloud", provider.ProviderZonePrivateRemote, []gateway.RouteDispatchResult{observedRefusal(t, gateway.RouteFailureModelUnavailable, gateway.RouteReplayNoSideEffect)}, FailureDetailProviderModelUnavailable},
		{"other OpenRouter refusal", "openrouter", provider.ProviderZoneBrokeredRemote, []gateway.RouteDispatchResult{observedRefusal(t, gateway.RouteFailurePaymentRequired, gateway.RouteReplayNoSideEffect)}, FailureDetailProviderPaymentRequired},
		{"outlived", "openrouter", provider.ProviderZoneBrokeredRemote, []gateway.RouteDispatchResult{observedRefusal(t, gateway.RouteFailureModelUnavailable, gateway.RouteReplayNoSideEffect), observerSuccess(t, observerUsage(t, 1, 1, 0))}, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			route, err := provider.NewRouteReference(test.zone, test.providerID, "adapter", "connection", "vendor/model", "")
			if err != nil {
				t.Fatal(err)
			}
			observer := &routeFailureObserver{}
			for index, result := range test.results {
				observer.record(string(rune('a'+index)), provider.CapabilityReviewV1, pricing, result)
				observer.recordRoute(route)
			}
			if detail, ok := observer.providerRefusal(controlplane.RunFailurePolicy); detail != test.want || ok != (test.want != "") {
				t.Fatalf("detail = (%q, %t), want %q", detail, ok, test.want)
			}
		})
	}
}

func TestRenderResultNamesTheZDRSettingForAnOpenRouterRefusal(t *testing.T) {
	result := Result{valid: true, wire: resultWire{Status: "refused", CI: "blocked", RunStatus: "failed", Failure: "policy", FailureDetail: FailureDetailProviderNoAllowedEndpoint, Tasks: []taskResult{{Key: "context", Status: "succeeded"}, {Key: "candidates", Status: "failed"}}}}
	var buffer bytes.Buffer
	if err := RenderResult(&buffer, result); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"failure: policy (task candidates): provider_no_allowed_endpoint", "hint: OpenRouter has no endpoint for this model that the request may use", "zero data retention is required", "OpenRouter account or key settings", "https://openrouter.ai/docs/guides/features/zdr"} {
		if !strings.Contains(buffer.String(), want) {
			t.Fatalf("text lacks %q:\n%s", want, buffer.String())
		}
	}
}
