package gateway

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

func TestRouteAttemptAuthorizationEncodingRoundTripsCanonicalAuthority(t *testing.T) {
	request, fixture, _ := newInitialAttemptFixture(t)
	authorization, err := NewInitialRouteAttemptAuthorization(request, fixture.selection, fixture.ranking)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeRouteAttemptAuthorization(authorization)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseRouteAttemptAuthorization(encoded)
	if err != nil || parsed.Identity() != authorization.Identity() || parsed.RouteReference() != authorization.RouteReference() || parsed.MaxOutputTokens() != authorization.MaxOutputTokens() || parsed.Validate() != nil {
		t.Fatalf("parsed authorization = (%#v, %v)", parsed, err)
	}
	reencoded, _ := EncodeRouteAttemptAuthorization(parsed)
	if !bytes.Equal(encoded, reencoded) {
		t.Fatal("authorization encoding was not canonical")
	}
	for _, malformed := range [][]byte{
		append(append([]byte(nil), encoded...), '\n'),
		bytes.Replace(encoded, []byte(authorization.Identity()), []byte(strings.Repeat("f", 64)), 1),
		bytes.Replace(encoded, []byte(`"identity":"`), []byte(`"unknown":1,"identity":"`), 1),
	} {
		if parsed, err := ParseRouteAttemptAuthorization(malformed); !errors.Is(err, ErrInvalidRouteAttemptAuthorizationEncoding) || parsed.Identity() != "" {
			t.Fatalf("malformed authorization = (%#v, %v)", parsed, err)
		}
	}
}

func TestRouteExecutionRecordRoundTripsSuccessfulAttempt(t *testing.T) {
	request, fixture, _ := newInitialAttemptFixture(t)
	authorization, _ := NewInitialRouteAttemptAuthorization(request, fixture.selection, fixture.ranking)
	dispatcher := &recordingRouteDispatcher{adapterID: authorization.RouteReference().AdapterID(), result: successfulDispatchResult(t)}
	result, err := DispatchAuthorizedRoute(context.Background(), dispatcher, authorization, request)
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := NewRouteAttemptOutcomeFromDispatch(authorization, result, 25)
	if err != nil {
		t.Fatal(err)
	}
	reconciliation, err := ReconcileAuthorizedRouteAttemptCost(authorization, outcome)
	if err != nil {
		t.Fatal(err)
	}
	output, err := NewSuccessfulRouteOutputReceipt(
		RouteOutputCandidateBatch, strings.Repeat("c", 64), strings.Repeat("d", 64),
		request, authorization, outcome,
	)
	if err != nil {
		t.Fatal(err)
	}
	record, err := NewRouteExecutionRecord(authorization, outcome, reconciliation, output)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeRouteExecutionRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseRouteExecutionRecord(encoded)
	if err != nil || parsed.Validate() != nil || parsed.Identity() != record.Identity() || parsed.Authorization().Identity() != authorization.Identity() || parsed.Outcome().Identity() != outcome.Identity() || parsed.Reconciliation().Identity() != reconciliation.Identity() || parsed.Output().Identity() != output.Identity() {
		t.Fatalf("parsed route execution = (%#v, %v)", parsed, err)
	}
	reencoded, _ := EncodeRouteExecutionRecord(parsed)
	if !bytes.Equal(encoded, reencoded) {
		t.Fatal("route execution encoding was not canonical")
	}
	for _, malformed := range [][]byte{
		append(append([]byte(nil), encoded...), '\n'),
		bytes.Replace(encoded, []byte(`"response_identity":"`), []byte(`"response_identity":"ffffffff`), 1),
		bytes.Replace(encoded, []byte(record.Identity()), []byte(strings.Repeat("f", 64)), 1),
	} {
		if parsed, err := ParseRouteExecutionRecord(malformed); !errors.Is(err, ErrInvalidRouteExecutionRecordEncoding) || parsed.Identity() != "" {
			t.Fatalf("malformed route execution = (%#v, %v)", parsed, err)
		}
	}
}

func TestNewRouteExecutionRecordRejectsCrossWiredOutput(t *testing.T) {
	request, fixture, _ := newInitialAttemptFixture(t)
	authorization, _ := NewInitialRouteAttemptAuthorization(request, fixture.selection, fixture.ranking)
	dispatcher := &recordingRouteDispatcher{adapterID: authorization.RouteReference().AdapterID(), result: successfulDispatchResult(t)}
	result, _ := DispatchAuthorizedRoute(context.Background(), dispatcher, authorization, request)
	outcome, _ := NewRouteAttemptOutcomeFromDispatch(authorization, result, 1)
	reconciliation, _ := ReconcileAuthorizedRouteAttemptCost(authorization, outcome)
	otherOutput, _ := NewSuccessfulRouteOutputReceipt(
		RouteOutputCandidateBatch, strings.Repeat("c", 64), strings.Repeat("d", 64),
		request, authorization, outcome,
	)
	forged := otherOutput
	forged.authorizationIdentity = strings.Repeat("f", 64)
	forged.identity = deriveRouteOutputReceiptIdentity(forged)
	if record, err := NewRouteExecutionRecord(authorization, outcome, reconciliation, forged); !errors.Is(err, ErrInvalidRouteExecutionRecord) || record.Identity() != "" {
		t.Fatalf("cross-wired record = (%#v, %v)", record, err)
	}
}
