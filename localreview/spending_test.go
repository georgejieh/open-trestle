package localreview

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/internal/scm"
)

func TestSpendingLimitRefusalIsAClosedPolicyRefusalBeforeAnyRun(t *testing.T) {
	result, err := NewSpendingLimitRefusalResult(scm.LocalGitObjectStoreProfileLooseAndPackIndexV1, review.ContextSpecialist{})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeResult(result)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if json.Unmarshal(encoded, &wire) != nil {
		t.Fatal("the result is not JSON")
	}
	for key, want := range map[string]any{"schema_version": float64(6), "status": "refused", "ci_disposition": "blocked", "run_status": "not_opened", "failure": "policy", "failure_detail": "spending_limit_reached", "usage_known": false, "actual_cost_micro_usd": float64(0)} {
		if wire[key] != want {
			t.Errorf("%s=%v, want %v", key, wire[key], want)
		}
	}
	if _, present := wire["token_usage"]; present {
		t.Fatal("a refusal before any run reports token usage")
	}
	if result.ExitCode() != 4 || result.ExitCodeFor(ExitPolicyDefault) != 4 {
		t.Fatalf("exit=%d, want 4", result.ExitCode())
	}
	var text bytes.Buffer
	if err := RenderResult(&text, result); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"status: refused\nci: blocked\nrun: not_opened\n",
		"failure: policy: spending_limit_reached\n",
		"hint: the spend recorded for an API key this review uses has reached its spending limit for the current period, so the review was not started and nothing was sent: run trestle usage to see it",
		"not a bill, and the limit is best effort, so your provider's own limit is the guarantee\n",
	} {
		if !strings.Contains(text.String(), want) {
			t.Fatalf("text lacks %q:\n%s", want, text.String())
		}
	}
	report, err := result.Report()
	if err != nil || report.FailureDetail != FailureDetailSpendingLimitReached || report.FailureHint == "" || report.TokenUsage != nil {
		t.Fatalf("report: %+v %v", report, err)
	}
	specialist, err := review.NewContextSpecialist(review.ContextSpecialistProfileIDs()[0])
	if err != nil {
		t.Fatal(err)
	}
	withProfile, err := NewSpendingLimitRefusalResult(scm.LocalGitObjectStoreProfileLooseAndPackIndexV1, specialist)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ = EncodeResult(withProfile)
	if !bytes.Contains(encoded, []byte(`"schema_version":6`)) || !bytes.Contains(encoded, []byte(`"specialist":{"profile_id":"`+specialist.ProfileID())) {
		t.Fatalf("a specialist refusal lost its version or profile: %s", encoded)
	}
	if _, err := ParseCompletedResult(encoded); err == nil {
		t.Fatal("a refusal was imported as a completed result")
	}
}

func TestRouteObserverCountsSentRequestsAtTheirSettledCostOrReservation(t *testing.T) {
	observer := &routeFailureObserver{}
	pricing := observerPricing(t)
	if spent := observer.spent(); spent.RequestsSent != 0 || spent.UpperBoundMicroUSD != 0 {
		t.Fatalf("a run without dispatches spent %+v", spent)
	}
	dispatch := func(authorization string, reserved uint64, result gateway.RouteDispatchResult) {
		observer.record(authorization, provider.CapabilityReviewV1, pricing, result)
		observer.recordSent(authorization, reserved, result)
	}
	// Settled from reported usage: 120 input and 30 output tokens.
	dispatch("generation", 70_000, observerSuccess(t, observerUsage(t, 120, 30, 20)))
	spent := observer.spent()
	if spent.RequestsSent != 1 || spent.UpperBoundMicroUSD != 180 || !spent.AllKnown {
		t.Fatalf("after a settled request: %+v", spent)
	}
	// A request refused before it was sent (for example a missing key) is not
	// counted.
	notSent, err := gateway.NewFailedRouteDispatchResult(gateway.RouteFailurePolicyDenied, gateway.RouteReplayNotDispatched, provider.NewUnknownRouteTokenUsage(), 0)
	if err != nil {
		t.Fatal(err)
	}
	dispatch("credential-missing", 70_000, notSent)
	if spent := observer.spent(); spent.RequestsSent != 1 || spent.UpperBoundMicroUSD != 180 {
		t.Fatalf("an unsent request was counted: %+v", spent)
	}
	// A sent request whose usage is unknown counts at its reservation.
	dispatch("verification", 70_000, observerFailure(t, provider.NewUnknownRouteTokenUsage()))
	spent = observer.spent()
	if spent.RequestsSent != 2 || spent.UpperBoundMicroUSD != 70_180 || spent.AllKnown {
		t.Fatalf("an unknown-usage request is not counted at its reservation: %+v", spent)
	}
	observer.reset()
	if spent := observer.spent(); spent != (SpendObservation{}) {
		t.Fatalf("reset kept an earlier run's spend: %+v", spent)
	}
	// The sum saturates instead of wrapping.
	dispatch("a", ^uint64(0)-1, observerFailure(t, provider.NewUnknownRouteTokenUsage()))
	dispatch("b", 5, observerFailure(t, provider.NewUnknownRouteTokenUsage()))
	if spent := observer.spent(); spent.UpperBoundMicroUSD != ^uint64(0) {
		t.Fatalf("the spend wrapped: %+v", spent)
	}
	var none *routeFailureObserver
	if none.spent() != (SpendObservation{}) || (*Session)(nil).SpendObservation() != (SpendObservation{}) {
		t.Fatal("a missing observer reports spend")
	}
}
