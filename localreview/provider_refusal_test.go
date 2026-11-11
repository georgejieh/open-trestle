package localreview

import (
	"bytes"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/routehint"
)

func observedRefusal(t *testing.T, failure gateway.RouteFailureClass, safety gateway.RouteReplaySafety) gateway.RouteDispatchResult {
	t.Helper()
	result, err := gateway.NewFailedRouteDispatchResult(failure, safety, provider.NewUnknownRouteTokenUsage(), 0)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

// The exported detail tokens are the shared route hint vocabulary.
func TestProviderRefusalDetailsMatchTheSharedHints(t *testing.T) {
	for class, want := range map[gateway.RouteFailureClass]string{
		gateway.RouteFailurePaymentRequired:  FailureDetailProviderPaymentRequired,
		gateway.RouteFailureModelUnavailable: FailureDetailProviderModelUnavailable,
		gateway.RouteFailureModelRetired:     FailureDetailProviderModelRetired,
		gateway.RouteFailureAuthentication:   FailureDetailProviderAuthenticationFailed,
		gateway.RouteFailureAuthorization:    FailureDetailProviderAuthorizationDenied,
		gateway.RouteFailureRateLimited:      FailureDetailProviderRateLimited,
	} {
		if detail, hint, ok := routehint.ProviderRefusal(class); !ok || detail != want || hint == "" {
			t.Fatalf("%s = (%q, %q, %t), want %q", class, detail, hint, ok, want)
		}
	}
}

// TestRouteObserverNamesOnlyTheRefusalThatEndedTheRun requires the detail to
// come from the most recent dispatch, only when the provider answered it and
// only when it explains the run failure the handlers record.
func TestRouteObserverNamesOnlyTheRefusalThatEndedTheRun(t *testing.T) {
	pricing := observerPricing(t)
	for _, test := range []struct {
		name    string
		results []gateway.RouteDispatchResult
		failure controlplane.RunFailure
		want    string
	}{
		{"payment", []gateway.RouteDispatchResult{observedRefusal(t, gateway.RouteFailurePaymentRequired, gateway.RouteReplayNoSideEffect)}, controlplane.RunFailurePolicy, FailureDetailProviderPaymentRequired},
		{"model unavailable", []gateway.RouteDispatchResult{observedRefusal(t, gateway.RouteFailureModelUnavailable, gateway.RouteReplayNoSideEffect)}, controlplane.RunFailurePolicy, FailureDetailProviderModelUnavailable},
		{"model retired", []gateway.RouteDispatchResult{observedRefusal(t, gateway.RouteFailureModelRetired, gateway.RouteReplayNoSideEffect)}, controlplane.RunFailurePolicy, FailureDetailProviderModelRetired},
		{"authentication", []gateway.RouteDispatchResult{observedRefusal(t, gateway.RouteFailureAuthentication, gateway.RouteReplayNoSideEffect)}, controlplane.RunFailurePolicy, FailureDetailProviderAuthenticationFailed},
		{"authorization", []gateway.RouteDispatchResult{observedRefusal(t, gateway.RouteFailureAuthorization, gateway.RouteReplayNoSideEffect)}, controlplane.RunFailurePolicy, FailureDetailProviderAuthorizationDenied},
		{"rate limit on the last attempt", []gateway.RouteDispatchResult{observedRefusal(t, gateway.RouteFailureRateLimited, gateway.RouteReplayNoSideEffect), observedRefusal(t, gateway.RouteFailureRateLimited, gateway.RouteReplayNoSideEffect)}, controlplane.RunFailureTransient, FailureDetailProviderRateLimited},
		// A credential that could not be read never reached the provider.
		{"credential unavailable", []gateway.RouteDispatchResult{observedRefusal(t, gateway.RouteFailureAuthentication, gateway.RouteReplayNotDispatched)}, controlplane.RunFailurePolicy, ""},
		// A later attempt that succeeded outlived the earlier refusal.
		{"outlived", []gateway.RouteDispatchResult{observedRefusal(t, gateway.RouteFailureRateLimited, gateway.RouteReplayNoSideEffect), observerSuccess(t, observerUsage(t, 1, 1, 0))}, controlplane.RunFailureTransient, ""},
		// A later failure of another class is the run's cause.
		{"superseded", []gateway.RouteDispatchResult{observedRefusal(t, gateway.RouteFailurePaymentRequired, gateway.RouteReplayNoSideEffect), observedRefusal(t, gateway.RouteFailureInvalidResponse, gateway.RouteReplayOutcomeUnknown)}, controlplane.RunFailurePolicy, ""},
		// A refusal that does not explain the recorded run failure names none.
		{"other run failure", []gateway.RouteDispatchResult{observedRefusal(t, gateway.RouteFailurePaymentRequired, gateway.RouteReplayNoSideEffect)}, controlplane.RunFailureInternal, ""},
		{"server error", []gateway.RouteDispatchResult{observedRefusal(t, gateway.RouteFailureProviderServer, gateway.RouteReplayOutcomeUnknown)}, controlplane.RunFailureTransient, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			observer := &routeFailureObserver{}
			for index, result := range test.results {
				observer.record(string(rune('a'+index)), provider.CapabilityReviewV1, pricing, result)
			}
			detail, ok := observer.providerRefusal(test.failure)
			if detail != test.want || ok != (test.want != "") {
				t.Fatalf("detail = (%q, %t), want %q", detail, ok, test.want)
			}
			observer.reset()
			if detail, ok := observer.providerRefusal(test.failure); ok || detail != "" {
				t.Fatal("reset kept the last refusal")
			}
		})
	}
}

// A refused run names the failing task, the provider refusal detail and its
// fixed hint, and never the provider's own words.
func TestRenderResultNamesTheProviderRefusalAndItsHint(t *testing.T) {
	for _, test := range []struct {
		failure, detail, want string
	}{
		{"policy", FailureDetailProviderPaymentRequired, "failure: policy (task candidates): provider_payment_required\nhint: the provider refused the request for billing: add credit or a subscription to the provider account, or choose another route\n"},
		{"policy", FailureDetailProviderModelRetired, "failure: policy (task candidates): provider_model_retired\nhint: the provider no longer serves this model: choose a model the provider lists as available and re-run setup\n"},
		{"transient", FailureDetailProviderRateLimited, "failure: transient (task candidates): provider_rate_limited\nhint: the provider rate-limited the request on its last attempt: wait and run the review again, or choose another route\n"},
	} {
		result := Result{valid: true, wire: resultWire{Status: "refused", CI: "blocked", RunStatus: "failed", Failure: test.failure, FailureDetail: test.detail, Tasks: []taskResult{{Key: "context", Status: "succeeded"}, {Key: "candidates", Status: "failed"}, {Key: "verification", Status: "skipped"}}}}
		var buffer bytes.Buffer
		if err := RenderResult(&buffer, result); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(buffer.String(), test.want) {
			t.Fatalf("text = %q, want %q", buffer.String(), test.want)
		}
		report, err := result.Report()
		if err != nil || report.FailureTask != "candidates" || report.FailureDetail != test.detail || report.FailureHint == "" || !strings.Contains(test.want, report.FailureHint) {
			t.Fatalf("report task=%q detail=%q hint=%q err=%v", report.FailureTask, report.FailureDetail, report.FailureHint, err)
		}
	}
}
