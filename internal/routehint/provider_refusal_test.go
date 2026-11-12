package routehint

import (
	"os"
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
		gateway.RouteFailureInvalidResponse:  "provider_response_invalid",
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

// Each provider refusal's hint is its explanation and its action, and the
// console labels the same reason with the same words, so every surface names
// a refusal identically.
func TestProviderRefusalWordsMatchTheHintAndTheConsole(t *testing.T) {
	app, err := os.ReadFile("../../web/src/App.tsx")
	if err != nil {
		t.Fatal(err)
	}
	for class := gateway.RouteFailureTransport; class.Validate() == nil; class++ {
		detail, hint, ok := ProviderRefusal(class)
		if !ok {
			continue
		}
		label, text, action, found := ProviderRefusalWords(detail)
		if !found || label == "" || text+": "+action != hint {
			t.Fatalf("%s words (%q, %q, %q) do not compose its hint %q", detail, label, text, action, hint)
		}
		for _, pinned := range []string{`"` + label + ": " + text + `"`, `"` + action + `"`} {
			if !strings.Contains(strings.Join(strings.Fields(string(app)), " "), pinned) {
				t.Fatalf("web/src/App.tsx lacks %s", pinned)
			}
		}
	}
	if _, _, _, found := ProviderRefusalWords("no_merge_base"); found {
		t.Fatal("a reason that is not a provider refusal has provider words")
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

// A reply the adapter refused is named as a provider reply, not as an
// internal check, with an action; the words name no reply field.
func TestProviderResponseInvalidNamesTheRefusedReply(t *testing.T) {
	detail, hint, ok := ProviderRefusal(gateway.RouteFailureInvalidResponse)
	if !ok || detail != "provider_response_invalid" || hint != "the provider answered, but its reply did not match what Open Trestle accepts, for example malformed or truncated output, an unrecognized field or an unexpected HTTP status: run the review again; if it repeats, choose another model or route and report it" {
		t.Fatalf("invalid response = (%q, %q, %t)", detail, hint, ok)
	}
	if label, _, _, found := ProviderRefusalWords(detail); !found || label != "Provider reply refused" {
		t.Fatalf("label = %q", label)
	}
	for _, class := range []gateway.RouteFailureClass{gateway.RouteFailureOutputExhausted, gateway.RouteFailureProviderServer, gateway.RouteFailurePolicyDenied, gateway.RouteFailureBudgetExhausted, gateway.RouteFailureCancelled} {
		if detail, _, ok := ProviderRefusal(class); ok {
			t.Fatalf("%s names %q", class, detail)
		}
	}
}

// An answer that was not a valid review document is named as the model's
// answer, with an action, and is not a route failure class.
func TestModelOutputInvalidNamesTheAnswer(t *testing.T) {
	label, text, action, ok := ProviderRefusalWords(ModelOutputInvalid)
	if !ok || label != "Model answer not a review document" || text != "the model's answer was not a valid review document (for example malformed JSON, the wrong shape or a refusal)" || action != "run the review again; if it repeats, choose another model" {
		t.Fatalf("words = (%q, %q, %q, %t)", label, text, action, ok)
	}
	if hint := ProviderRefusalHint(ModelOutputInvalid); hint != text+": "+action {
		t.Fatalf("hint = %q", hint)
	}
	for class := gateway.RouteFailureTransport; class.Validate() == nil; class++ {
		if detail, _, _ := ProviderRefusal(class); detail == ModelOutputInvalid {
			t.Fatalf("%s names the model answer", class)
		}
	}
}
