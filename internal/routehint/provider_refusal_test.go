package routehint

import (
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/gateway"
)

// TestProviderRefusalNamesEachRefusalClass pins the content-free detail of
// each provider refusal class and requires a fixed one-line hint for it, and
// no detail for any other class.
func TestProviderRefusalNamesEachRefusalClass(t *testing.T) {
	want := map[gateway.RouteFailureClass]string{
		gateway.RouteFailurePaymentRequired:  "provider_payment_required",
		gateway.RouteFailureModelUnavailable: "provider_model_unavailable",
		gateway.RouteFailureModelRetired:     "provider_model_retired",
		gateway.RouteFailureAuthentication:   "provider_authentication_failed",
		gateway.RouteFailureAuthorization:    "provider_authorization_denied",
		gateway.RouteFailureRateLimited:      "provider_rate_limited",
	}
	hints := map[string]bool{}
	for class := gateway.RouteFailureTransport; class.Validate() == nil; class++ {
		detail, hint, ok := ProviderRefusal(class)
		expected, refusal := want[class]
		if ok != refusal || detail != expected {
			t.Fatalf("%s = (%q, %q, %t), want %q", class, detail, hint, ok, expected)
		}
		if !refusal {
			if hint != "" {
				t.Fatalf("%s carries a hint", class)
			}
			continue
		}
		if hint == "" || strings.ContainsAny(hint, "\r\n") || hints[hint] || ProviderRefusalHint(detail) != hint {
			t.Fatalf("%s hint %q is empty, multi-line, shared or not found by detail", class, hint)
		}
		hints[hint] = true
	}
	if ProviderRefusalHint("model_output_exhausted") != "" || ProviderRefusalHint("") != "" {
		t.Fatal("a detail that is not a provider refusal has a provider hint")
	}
}

// The payment and retired-model hints are the operator-facing words the
// review, set members and setup print; they name an action, not the provider.
func TestProviderRefusalHintsNameAnAction(t *testing.T) {
	if _, hint, _ := ProviderRefusal(gateway.RouteFailurePaymentRequired); hint != "the provider refused the request for billing: add credit or a subscription to the provider account, or choose another route" {
		t.Fatalf("payment hint = %q", hint)
	}
	if _, hint, _ := ProviderRefusal(gateway.RouteFailureModelRetired); hint != "the provider no longer serves this model: choose a model the provider lists as available and re-run setup" {
		t.Fatalf("retired hint = %q", hint)
	}
}
