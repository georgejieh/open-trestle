package runtimeconfig

import (
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/diagnostics"
)

func feedbackSideSet(t *testing.T, findings ...diagnostics.Finding) diagnostics.Set {
	t.Helper()
	scope, err := audit.NewReviewScope("tenant", "repository", "run")
	if err != nil {
		t.Fatal(err)
	}
	check, err := diagnostics.NewDeterministicCheck("3f01f93e51003eb3a0deca04719a3957d6e367c97c33bdfea105174d95698092", strings.Repeat("8", 64), strings.Repeat("7", 64), diagnostics.CheckPassed, 1, 2, 1, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	set, err := diagnostics.NewSetWithDeterministicChecks(scope, strings.Repeat("d", 64), strings.Repeat("1", 40), strings.Repeat("e", 64), strings.Repeat("f", 64), uint16(len(findings)), 0, 0, 1, 1, 0, nil, []diagnostics.DeterministicCheck{check}, findings)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func TestFeedbackSelectsOnlyAHeadFindingAtItsHeadLine(t *testing.T) {
	head, err := diagnostics.NewFinding(strings.Repeat("a", 64), strings.Repeat("b", 64), "Head issue", "Remaining code.", diagnostics.SeverityError, "calc.go", 4, 5, []string{strings.Repeat("c", 64)})
	if err != nil {
		t.Fatal(err)
	}
	base, err := diagnostics.NewFindingOnSide(strings.Repeat("a", 64), strings.Repeat("9", 64), "Removed guard", "Removed code.", diagnostics.SeverityError, "calc.go", diagnostics.LineSideBase, 4, 6, []string{strings.Repeat("c", 64)})
	if err != nil {
		t.Fatal(err)
	}
	text, ok := feedbackDecisionText(feedbackSideSet(t, head, base), "calc.go", 4, "confirm", "Confirmed.")
	if !ok || !strings.Contains(text, head.Identity()) || strings.Contains(text, base.Identity()) {
		t.Fatalf("feedback did not select the head finding: %q", text)
	}
	if text, ok := feedbackDecisionText(feedbackSideSet(t, base), "calc.go", 4, "confirm", "Confirmed."); ok {
		t.Fatalf("head-line feedback matched a finding on removed base lines: %q", text)
	}
}
