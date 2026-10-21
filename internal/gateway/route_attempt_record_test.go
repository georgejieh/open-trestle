package gateway

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

func TestCompletedRouteAttemptRecordPreservesOutcomeWithoutOutput(t *testing.T) {
	request, fixture, _ := newInitialAttemptFixture(t)
	authorization, err := NewInitialRouteAttemptAuthorization(request, fixture.selection, fixture.ranking)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher := &recordingRouteDispatcher{adapterID: authorization.RouteReference().AdapterID(), result: successfulDispatchResult(t)}
	dispatch, err := DispatchAuthorizedRoute(context.Background(), dispatcher, authorization, request)
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := NewRouteAttemptOutcomeFromDispatch(authorization, dispatch, 25)
	if err != nil {
		t.Fatal(err)
	}
	cost, err := ReconcileAuthorizedRouteAttemptCost(authorization, outcome)
	if err != nil {
		t.Fatal(err)
	}
	record, err := NewCompletedRouteAttemptRecord(authorization, outcome, cost)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeCompletedRouteAttemptRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseCompletedRouteAttemptRecord(encoded)
	if err != nil || parsed.Identity() != record.Identity() || parsed.Authorization().Identity() != authorization.Identity() || parsed.Outcome().Identity() != outcome.Identity() || parsed.Reconciliation().Identity() != cost.Identity() {
		t.Fatalf("record mismatch: %v", err)
	}
	if bytes.Contains(encoded, []byte(`"output"`)) || bytes.Contains(encoded, []byte(`"payload"`)) {
		t.Fatal("completed attempt invented an output or retained response content")
	}
	again, err := EncodeCompletedRouteAttemptRecord(parsed)
	if err != nil || !bytes.Equal(encoded, again) {
		t.Fatalf("noncanonical round trip: %v", err)
	}
	for _, invalid := range [][]byte{
		append(append([]byte(nil), encoded...), '\n'),
		bytes.Replace(encoded, []byte(`"schema_version":1`), []byte(`"schema_version":99`), 1),
		bytes.Replace(encoded, []byte(`"contract":`), []byte(`"unknown":1,"contract":`), 1),
		bytes.Replace(encoded, []byte(record.Identity()), []byte(strings.Repeat("f", 64)), 1),
		bytes.Replace(encoded, []byte(`"duration_milliseconds":25`), []byte(`"duration_milliseconds":26`), 1),
		bytes.Replace(encoded, []byte(`"actual_total_cost_micro_usd":`), []byte(`"actual_total_cost_micro_usd":1,"ignored":`), 1),
	} {
		if value, err := ParseCompletedRouteAttemptRecord(invalid); !errors.Is(err, ErrInvalidCompletedRouteAttemptRecord) || value.Identity() != "" {
			t.Fatalf("invalid record admitted: %v", err)
		}
	}
	otherOutcome := outcome
	otherOutcome.authorizationIdentity = strings.Repeat("f", 64)
	if value, err := NewCompletedRouteAttemptRecord(authorization, otherOutcome, cost); !errors.Is(err, ErrInvalidCompletedRouteAttemptRecord) || value.Identity() != "" {
		t.Fatalf("cross wired outcome admitted: %v", err)
	}
	otherCost := cost
	otherCost.attemptAuthorizationIdentity = strings.Repeat("f", 64)
	if value, err := NewCompletedRouteAttemptRecord(authorization, outcome, otherCost); !errors.Is(err, ErrInvalidCompletedRouteAttemptRecord) || value.Identity() != "" {
		t.Fatalf("cross wired cost admitted: %v", err)
	}
}
