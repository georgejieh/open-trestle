package provider

import "testing"

func TestRouteReportedDebitUpperBoundStates(t *testing.T) {
	var absent RouteReportedDebitUpperBound
	if absent.Validate() != nil || absent.IsPresent() || absent.MicroUSD() != 0 {
		t.Fatal("invalid absence")
	}
	for _, v := range []uint64{0, 1, maxModelCostMicroUSD} {
		bound, err := NewRouteReportedDebitUpperBoundMicroUSD(v)
		if err != nil || !bound.IsPresent() || bound.MicroUSD() != v || bound.Validate() != nil || bound == absent {
			t.Fatalf("bound %d: %v", v, err)
		}
	}
	if _, err := NewRouteReportedDebitUpperBoundMicroUSD(maxModelCostMicroUSD + 1); err == nil {
		t.Fatal("unsupported bound")
	}
	for _, bound := range []RouteReportedDebitUpperBound{{microUSD: 1}, {present: true, microUSD: maxModelCostMicroUSD + 1}} {
		if bound.Validate() == nil {
			t.Fatal("invalid storage accepted")
		}
	}
	part, _ := NewResponsePart(ResponsePartAssistantText, "text/plain", []byte("ok"))
	legacy, _ := NewResponse(CapabilityReviewV1, ResponseFinishStop, []ResponsePart{part}, NewUnknownRouteTokenUsage())
	zero, _ := NewRouteReportedDebitUpperBoundMicroUSD(0)
	present, err := NewResponseWithReportedDebitUpperBound(legacy.Capability(), legacy.FinishReason(), legacy.Parts(), legacy.Usage(), zero)
	if err != nil || present.Validate() != nil || present.ReportedDebitUpperBound() != zero || present.Identity() == legacy.Identity() {
		t.Fatal("present zero identity not distinct", err)
	}
}
