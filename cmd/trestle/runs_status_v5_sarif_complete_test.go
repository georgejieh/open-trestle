package main

import (
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/diagnostics"
	"github.com/georgejieh/open-trestle/internal/review"
)

// Complete recorded coverage is not a reason to assert an unobserved gap.
// Whole-log status remains advisory rather than an approval claim.
func TestV5SARIFCompleteCoverageReasonDoesNotInventGap(t *testing.T) {
	_, receipt := remotePlanAndReceipt(t)
	check, err := diagnostics.NewDeterministicCheck(
		"3f01f93e51003eb3a0deca04719a3957d6e367c97c33bdfea105174d95698092",
		strings.Repeat("8", 64), strings.Repeat("7", 64), diagnostics.CheckPassed,
		1, 2, 1, 2, 0,
	)
	if err != nil {
		t.Fatal(err)
	}
	finding, err := diagnostics.NewFinding(
		strings.Repeat("a", 64), strings.Repeat("b", 64), "Verified issue",
		"Independent evidence confirms the changed range.", diagnostics.SeverityWarning,
		"internal/review source.go", 4, 6, []string{strings.Repeat("c", 64)},
	)
	if err != nil {
		t.Fatal(err)
	}
	set, err := diagnostics.NewSetWithDeterministicChecks(
		receipt.Scope(), strings.Repeat("d", 64), strings.Repeat("1", 40),
		strings.Repeat("e", 64), strings.Repeat("f", 64),
		1, 0, 0, 1, 1, 0, nil, []diagnostics.DeterministicCheck{check},
		[]diagnostics.Finding{finding},
	)
	if err != nil {
		t.Fatal(err)
	}
	log, err := buildDiagnosticSetSARIF(set)
	if err != nil {
		t.Fatal(err)
	}
	if len(log.Runs) != 1 || len(log.Runs[0].Results) != 1 {
		t.Fatalf("missing verified finding: %#v", log)
	}
	props := log.Runs[0].Properties
	if props.Status != review.OutcomeInconclusive {
		t.Fatalf("whole-log status=%s, want inconclusive", props.Status)
	}
	if strings.Contains(props.Reason, "coverage inconclusive") || strings.Contains(props.Reason, "omission") || strings.Contains(props.Reason, "failed") {
		t.Errorf("complete coverage claimed a nonexistent gap: %q", props.Reason)
	}
	if !strings.Contains(props.Reason, "no approval") {
		t.Errorf("complete coverage must remain non-approving: %q", props.Reason)
	}
}
