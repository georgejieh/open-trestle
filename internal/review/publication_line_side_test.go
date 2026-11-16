package review

import (
	"testing"

	"github.com/georgejieh/open-trestle/internal/gateway"
)

func TestBaseSideFindingIsSummaryOnly(t *testing.T) {
	receipt, verified := verifiedSetFixture(t, "verified", gateway.RouteIndependenceDistinctProvider)
	policy, err := NewPublicationPolicy(SeverityLow, 10, gateway.RouteIndependenceDistinctProvider, true)
	if err != nil {
		t.Fatal(err)
	}
	head, err := SelectPublicationFindings(policy, receipt, verified)
	if err != nil || len(head.InlineFindings()) != 1 || len(head.SummaryOnlyFindings()) != 0 || head.InlinePublishableFindings()[0].Side() != LineSideHead {
		t.Fatalf("head finding is not inline: %v", err)
	}

	base := relabelBaseSide(t, verified)
	selection, err := SelectPublicationFindings(policy, receipt, base)
	if err != nil || selection.Status() != PublicationAdvisoryReady || len(selection.InlineFindings()) != 0 || len(selection.SummaryOnlyFindings()) != 1 {
		t.Fatalf("base-side finding was not summary-only: %v", err)
	}
	if projected := selection.SummaryOnlyPublishableFindings(); len(projected) != 1 || projected[0].Side() != LineSideBase || projected[0].StartLine() != base.findings[0].SourceRange().StartLine() {
		t.Fatal("summary projection lost the base side")
	}

	// A selection that puts the base-side finding inline is refused.
	forged := selection
	forged.inlineFindings, forged.summaryOnlyFindings = forged.summaryOnlyFindings, nil
	forged.inlineProjection, forged.summaryOnlyProjection = forged.summaryOnlyProjection, nil
	forged.identity = derivePublicationSelectionIdentity(forged)
	if forged.Validate() == nil {
		t.Fatal("inline base-side finding accepted")
	}
}

func TestPublicationOrderPutsHeadFindingsFirst(t *testing.T) {
	_, verified := verifiedSetFixture(t, "verified", gateway.RouteIndependenceDistinctProvider)
	head := verified.findings[0]
	base := relabelBaseSide(t, verified).findings[0]
	head.severity, base.severity = SeverityLow, SeverityCritical
	if !publicationFindingLess(head, base) || publicationFindingLess(base, head) {
		t.Fatal("a base-side finding sorted before a head finding")
	}
}
