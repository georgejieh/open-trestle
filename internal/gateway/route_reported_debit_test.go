package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/provider"
)

func TestReportedDebitLegacyBaseline(t *testing.T) {
	for _, known := range []bool{false, true} {
		request, fixture, _ := newInitialAttemptFixture(t)
		a, _ := NewInitialRouteAttemptAuthorization(request, fixture.selection, fixture.ranking)
		response := successfulDispatchResult(t).Response()
		if !known {
			response, _ = provider.NewResponse(response.Capability(), response.FinishReason(), response.Parts(), provider.NewUnknownRouteTokenUsage())
		}
		initial, _ := NewSuccessfulRouteDispatchResult(response)
		d := &recordingRouteDispatcher{adapterID: a.RouteReference().AdapterID(), result: initial}
		result, err := DispatchAuthorizedRoute(context.Background(), d, a, request)
		if err != nil {
			t.Fatal(err)
		}
		outcome, _ := NewRouteAttemptOutcomeFromDispatch(a, result, 25)
		cost, _ := ReconcileAuthorizedRouteAttemptCost(a, outcome)
		output, _ := NewSuccessfulRouteOutputReceipt(RouteOutputCandidateBatch, strings.Repeat("c", 64), strings.Repeat("d", 64), request, a, outcome)
		execution, err := NewRouteExecutionRecord(a, outcome, cost, output)
		if err != nil {
			t.Fatal(err)
		}
		completed, _ := NewCompletedRouteAttemptRecord(a, outcome, cost)
		if id, err := completed.DispatchResultIdentity(); err != nil || id != result.Identity() {
			t.Fatal("legacy reconstructed dispatch changed", err)
		}
		eb, _ := EncodeRouteExecutionRecord(execution)
		cb, _ := EncodeCompletedRouteAttemptRecord(completed)
		ab, _ := EncodeRouteAttemptAuthorization(a)
		got := strings.Join([]string{response.Identity(), result.Identity(), outcome.Identity(), cost.Identity(), a.Identity(), fmt.Sprintf("%x %x %x", sha256.Sum256(eb), sha256.Sum256(cb), sha256.Sum256(ab))}, " ")
		want := map[bool]string{false: "11dc60a6638985d2a0acf288baa296e2d9f00693af724a02a8c503c9ab0daa7d 9dd484c9743e4f00210eb35fdac562ab53b4a8470b83a950689f193ff01aad79 2b604f42bf58ea3dcee2b129072d4fd1a3b63fc8128c09e4ea311898e4d745d6 bc4c5a9aeed2e69e3d56151dd0aaaf2d9f6383fe43995e0a0518fa0b8bac20c7 a1ddbb8aa4d6a0459de31569d2856338414d74791c915425868da66ea0a1383b 4a6c180b08fdf7991c6eaeb8ab2d9242a1cd9495063ebaa38db59d6637f61dcc 4c23240eb17fa321e639e9d574a4825f8d7d7d203c45dc55be24d0fb2a435606 4f818d636b732eaad6d66f49f401861255b59017fd2565c096e5f933dde3e7b1", true: "46010ddd3409394a55ac8762e610c21cea2a56d56b3cf479d44cc5f1f6e26a61 b6db9141af5549f2c57939ca97635d396dc1da936e67227099f8eb6c6961b9af 07fa3326363ad8cfdd88968ea995817db6b287f09b3d6a4eceb9fa88eb31d7bd 85e1b35436873c1d2ade72ba494feab25fcc08cc3bbde9478754d1112714d490 a1ddbb8aa4d6a0459de31569d2856338414d74791c915425868da66ea0a1383b 95cf601665e1a5c2bbc73e82900d2132ab1eb7a4d850027e920782c742c638ae d03a3c11b14cbc4b76fd29d0ff94d7195cd2fff128b8a0d1328f84b16b73fbf2 4f818d636b732eaad6d66f49f401861255b59017fd2565c096e5f933dde3e7b1"}[known]
		if got != want {
			t.Fatalf("legacy identity or bytes changed: %t %s", known, got)
		}
	}
	turn := turnEncodingRichRecord(t, false)
	encoded, err := EncodeInvestigationTurnRecord(turn)
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%s %x", turn.Identity(), sha256.Sum256(encoded)); got != "d629c18b4df9a41156821e96ddf3ec40dcbcb2ad67dcfcd0e44801198609e8e3 4cee64f9845d1ab237526717e44cb216e2fdbde6c9074406be289f2c3f4b8099" {
		t.Fatal("legacy investigation bytes changed", got)
	}
}

func TestReportedDebitPropagationKeepsUnknownReservation(t *testing.T) {
	for _, amount := range []uint64{0, 4120, 30000} {
		request, fixture, _ := newInitialAttemptFixture(t)
		a, _ := NewInitialRouteAttemptAuthorization(request, fixture.selection, fixture.ranking)
		legacy := successfulDispatchResult(t).Response()
		bound, _ := provider.NewRouteReportedDebitUpperBoundMicroUSD(amount)
		response, err := provider.NewResponseWithReportedDebitUpperBound(legacy.Capability(), legacy.FinishReason(), legacy.Parts(), provider.NewUnknownRouteTokenUsage(), bound)
		if err != nil {
			t.Fatal(err)
		}
		initial, _ := NewSuccessfulRouteDispatchResult(response)
		d := &recordingRouteDispatcher{adapterID: a.RouteReference().AdapterID(), result: initial}
		result, err := DispatchAuthorizedRoute(context.Background(), d, a, request)
		if err != nil {
			t.Fatal(err)
		}
		outcome, err := NewRouteAttemptOutcomeFromDispatch(a, result, 25)
		if err != nil {
			t.Fatal(err)
		}
		cost, err := ReconcileAuthorizedRouteAttemptCost(a, outcome)
		if err != nil {
			t.Fatal(err)
		}
		if result.ReportedDebitUpperBound() != bound || outcome.ReportedDebitUpperBound() != bound || outcome.Usage().IsKnown() || cost.ActualCost().IsKnown() || cost.Status() != RouteCostUsageUnknown || cost.RemainingCostMicroUSD() != a.RemainingCostAfterMicroUSD() || cost.ReservedCostMicroUSD() != a.ReservedCostMicroUSD() || cost.BudgetOverrunMicroUSD() != 0 || d.calls != 1 {
			t.Fatal("bound altered accounting or dispatch")
		}
		completed, err := NewCompletedRouteAttemptRecord(a, outcome, cost)
		if err != nil {
			t.Fatal(err)
		}
		if id, err := completed.DispatchResultIdentity(); err != nil || id != result.Identity() {
			t.Fatal("reconstructed dispatch mismatch", err)
		}
		output, _ := NewSuccessfulRouteOutputReceipt(RouteOutputCandidateBatch, strings.Repeat("c", 64), strings.Repeat("d", 64), request, a, outcome)
		execution, err := NewRouteExecutionRecord(a, outcome, cost, output)
		if err != nil {
			t.Fatal(err)
		}
		eb, _ := EncodeRouteExecutionRecord(execution)
		cb, _ := EncodeCompletedRouteAttemptRecord(completed)
		for _, codec := range []struct {
			data  []byte
			parse func([]byte) (provider.RouteReportedDebitUpperBound, []byte, error)
		}{
			{eb, func(b []byte) (provider.RouteReportedDebitUpperBound, []byte, error) {
				r, e := ParseRouteExecutionRecord(b)
				if e != nil {
					return provider.RouteReportedDebitUpperBound{}, nil, e
				}
				out, e := EncodeRouteExecutionRecord(r)
				return r.Outcome().ReportedDebitUpperBound(), out, e
			}},
			{cb, func(b []byte) (provider.RouteReportedDebitUpperBound, []byte, error) {
				r, e := ParseCompletedRouteAttemptRecord(b)
				if e != nil {
					return provider.RouteReportedDebitUpperBound{}, nil, e
				}
				out, e := EncodeCompletedRouteAttemptRecord(r)
				return r.Outcome().ReportedDebitUpperBound(), out, e
			}},
		} {
			got, again, err := codec.parse(codec.data)
			if err != nil || got != bound || !bytes.Equal(again, codec.data) {
				t.Fatal("codec lost bound", err)
			}
			member := []byte(fmt.Sprintf(`,"reported_debit_upper_bound":{"micro_usd":%d}`, amount))
			for _, invalid := range [][]byte{
				bytes.Replace(codec.data, member, nil, 1),
				bytes.Replace(codec.data, member, []byte(`,"reported_debit_upper_bound":null`), 1),
				bytes.Replace(codec.data, member, []byte(`,"reported_debit_upper_bound":{}`), 1),
				bytes.Replace(codec.data, member, append(append([]byte{}, member...), member...), 1),
				bytes.Replace(codec.data, member, []byte(fmt.Sprintf(`,"reported_debit_upper_bound":{"micro_usd":%d}`, amount+1)), 1),
				bytes.Replace(codec.data, member, []byte(`,"reported_debit_upper_bound":{"micro_usd":4611686018427387905}`), 1),
			} {
				if _, _, err := codec.parse(invalid); err == nil {
					t.Fatal("tampered bound admitted")
				}
			}
		}
	}
}

func TestReportedDebitAuditRejectsMismatchedEvidence(t *testing.T) {
	request, fixture, _ := newInitialAttemptFixture(t)
	a, _ := NewInitialRouteAttemptAuthorization(request, fixture.selection, fixture.ranking)
	legacy := successfulDispatchResult(t).Response()
	bound, _ := provider.NewRouteReportedDebitUpperBoundMicroUSD(0)
	response, _ := provider.NewResponseWithReportedDebitUpperBound(legacy.Capability(), legacy.FinishReason(), legacy.Parts(), legacy.Usage(), bound)
	initial, _ := NewSuccessfulRouteDispatchResult(response)
	d := &recordingRouteDispatcher{adapterID: a.RouteReference().AdapterID(), result: initial}
	result, _ := DispatchAuthorizedRoute(context.Background(), d, a, request)
	mismatched, _ := NewSuccessfulRouteAttemptOutcome(a, response.Identity(), response.Usage(), 25)
	ledger := audit.NewMemoryLedger()
	scope := newRoutingScope(t)
	if _, err := RecordRouteDispatchCompleted(context.Background(), ledger, scope, a, result, mismatched, time.Unix(1, 0)); !errors.Is(err, ErrRouteAuditRecordMismatch) {
		t.Fatal("audit admitted mismatched evidence", err)
	}
}

func TestReportedDebitInvestigationCodec(t *testing.T) {
	for _, amount := range []uint64{0, 4120, 1 << 62} {
		options, original, _, _ := investigationOwnerOptionsFixture(t, "", 40000, 2)
		legacy := successfulDispatchResult(t).Response()
		bound, _ := provider.NewRouteReportedDebitUpperBoundMicroUSD(amount)
		response, _ := provider.NewResponseWithReportedDebitUpperBound(legacy.Capability(), legacy.FinishReason(), legacy.Parts(), legacy.Usage(), bound)
		options.Catalog, _ = NewRouteDispatcherCatalog([]RouteDispatcher{&turnEncodingDispatcher{original, response}})
		owner, err := NewInvestigationRouteOwner(options)
		if err != nil {
			t.Fatal(err)
		}
		record, err := owner.Dispatch(context.Background(), InvestigationGenerationTurn, ownerRequest(t, "bound"))
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := EncodeInvestigationTurnRecord(record)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParseInvestigationTurnRecord(encoded)
		if err != nil {
			t.Fatal(err)
		}
		again, _ := EncodeInvestigationTurnRecord(parsed)
		estimate, sizeErr := EstimateInvestigationTurnPayloadBytes(uint64(len(record.request.Payload())))
		if sizeErr != nil || uint64(len(encoded)) > estimate {
			t.Fatal("present bound exceeds conservative estimate", sizeErr)
		}
		if parsed.Dispatch().ReportedDebitUpperBound() != bound || parsed.Dispatch().Response().ReportedDebitUpperBound() != bound || parsed.Outcome().ReportedDebitUpperBound() != bound || !bytes.Equal(encoded, again) {
			t.Fatal("investigation lost evidence")
		}
		for _, path := range []string{"/dispatch/reported_debit_upper_bound", "/dispatch/response/reported_debit_upper_bound", "/outcome/reported_debit_upper_bound"} {
			for _, value := range []string{"null", "{}", `{"micro_usd":4611686018427387905}`, fmt.Sprintf(`{"micro_usd":%d}`, amount+1), `{"micro_usd":0,"micro_usd":0}`, `{"micro_usd":0,"unknown":0}`} {
				turnEncodingRefuse(t, turnEncodingAt(t, encoded, path, []byte(value)))
			}
		}
		member := []byte(fmt.Sprintf(`,"reported_debit_upper_bound":{"micro_usd":%d}`, amount))
		turnEncodingRefuse(t, bytes.Replace(encoded, member, nil, 1))
		turnEncodingRefuse(t, bytes.Replace(encoded, member, append(append([]byte{}, member...), member...), 1))
	}
}

func TestReportedDebitFailuresRemainAbsent(t *testing.T) {
	request, fixture, _ := newInitialAttemptFixture(t)
	a, _ := NewInitialRouteAttemptAuthorization(request, fixture.selection, fixture.ranking)
	initial, err := NewFailedRouteDispatchResult(RouteFailureRateLimited, RouteReplayNoSideEffect, provider.NewUnknownRouteTokenUsage(), 0)
	if err != nil {
		t.Fatal(err)
	}
	d := &recordingRouteDispatcher{adapterID: a.RouteReference().AdapterID(), result: initial}
	result, err := DispatchAuthorizedRoute(context.Background(), d, a, request)
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := NewRouteAttemptOutcomeFromDispatch(a, result, 25)
	if err != nil {
		t.Fatal(err)
	}
	if result.ReportedDebitUpperBound().IsPresent() || outcome.ReportedDebitUpperBound().IsPresent() {
		t.Fatal("failure invented evidence")
	}
	bound, _ := provider.NewRouteReportedDebitUpperBoundMicroUSD(0)
	result.reportedDebitUpperBound = bound
	result.identity = deriveRouteDispatchResultIdentity(result)
	if result.Validate() == nil {
		t.Fatal("failure accepted debit evidence")
	}
	outcome.reportedDebitUpperBound = bound
	outcome.identity = deriveRouteAttemptOutcomeIdentity(outcome)
	if outcome.Validate() == nil {
		t.Fatal("failure outcome accepted debit evidence")
	}
}

func TestReportedDebitDoesNotAdmitUnknownInvestigation(t *testing.T) {
	options, original, _, _ := investigationOwnerOptionsFixture(t, "", 40000, 2)
	legacy := successfulDispatchResult(t).Response()
	bound, _ := provider.NewRouteReportedDebitUpperBoundMicroUSD(4120)
	response, _ := provider.NewResponseWithReportedDebitUpperBound(legacy.Capability(), legacy.FinishReason(), legacy.Parts(), provider.NewUnknownRouteTokenUsage(), bound)
	options.Catalog, _ = NewRouteDispatcherCatalog([]RouteDispatcher{&turnEncodingDispatcher{original, response}})
	owner, err := NewInvestigationRouteOwner(options)
	if err != nil {
		t.Fatal(err)
	}
	if record, err := owner.Dispatch(context.Background(), InvestigationGenerationTurn, ownerRequest(t, "unknown bound")); err == nil || record.Identity() != "" || original.count() != 1 {
		t.Fatal("upper bound admitted unknown actual cost", err)
	}
}
