package main

import (
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/diagnostics"
	"github.com/georgejieh/open-trestle/internal/review"
)

// A failed match can be found before the deterministic scan has covered every applicable range.
func TestV5SARIFPartialFailedCheckExplainsIncompleteScan(t *testing.T) {
	_, receipt := remotePlanAndReceipt(t)
	const sourceCheckID = "d3c8b90d92bcd03cda89ef1796df470459571a17e78a4f5bbe30f4e7c458048a"
	check, err := diagnostics.NewDeterministicCheck(
		sourceCheckID, strings.Repeat("8", 64), strings.Repeat("7", 64),
		diagnostics.CheckFailed, 2, 3, 1, 2, 1,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := check.Validate(); err != nil {
		t.Fatalf("partial failed check is invalid: %v", err)
	}
	if check.Complete() {
		t.Fatal("partial failed check unexpectedly reports complete coverage")
	}
	omission, err := diagnostics.NewOmissionSummary(diagnostics.OmissionSelectionLimit, 1)
	if err != nil {
		t.Fatal(err)
	}
	set, err := diagnostics.NewSetWithDeterministicChecks(
		receipt.Scope(), strings.Repeat("d", 64), strings.Repeat("1", 40),
		strings.Repeat("e", 64), strings.Repeat("f", 64),
		1, 0, 1, 2, 1, 1,
		[]diagnostics.OmissionSummary{omission}, []diagnostics.DeterministicCheck{check}, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := set.Validate(); err != nil || set.SchemaVersion() != 5 {
		t.Fatalf("invalid canonical v5 fixture: version=%d error=%v", set.SchemaVersion(), err)
	}
	log, err := buildDiagnosticSetSARIF(set)
	if err != nil {
		t.Fatal(err)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("SARIF runs=%d, want 1", len(log.Runs))
	}
	run := log.Runs[0]
	if len(run.Results) != 0 {
		t.Fatalf("check match without a verified finding generated %d SARIF results", len(run.Results))
	}
	props := run.Properties
	if props.Status != review.OutcomeInconclusive {
		t.Errorf("whole-log status=%s, want inconclusive", props.Status)
	}
	if props.SourceCheckID != sourceCheckID || props.CheckID != check.Identity() ||
		props.CheckAnalysisResultID != check.AnalysisResultIdentity() ||
		props.ChangeID != check.ChangeIdentity() || props.CheckState != "failed" ||
		props.CheckKey != check.Key() {
		t.Errorf("check identity/state properties differ: %+v", props)
	}
	if props.CheckRuleVersion == nil || *props.CheckRuleVersion != 1 {
		t.Errorf("check rule version=%v, want 1", props.CheckRuleVersion)
	}
	for _, tc := range []struct {
		name string
		got  *uint32
		want uint32
	}{
		{"applicable files", props.ApplicableFiles, 2},
		{"applicable ranges", props.ApplicableRanges, 3},
		{"checked files", props.CheckedFiles, 1},
		{"checked ranges", props.CheckedRanges, 2},
		{"matches", props.MatchCount, 1},
		{"source analyzed", props.SourceAnalyzedCount, 2},
		{"source selected", props.SourceSelectedCount, 1},
		{"source omitted", props.SourceOmittedCount, 1},
	} {
		if tc.got == nil || *tc.got != tc.want {
			t.Errorf("%s=%v, want %d", tc.name, tc.got, tc.want)
		}
	}
	for _, tc := range []struct {
		name string
		got  *uint16
		want uint16
	}{
		{"candidates", props.CandidateCount, 1},
		{"verified", props.VerifiedCount, 0},
		{"rejected", props.RejectedCount, 0},
		{"inconclusive", props.InconclusiveCount, 1},
	} {
		if tc.got == nil || *tc.got != tc.want {
			t.Errorf("%s=%v, want %d", tc.name, tc.got, tc.want)
		}
	}
	if len(props.Omissions) != 1 || props.Omissions[0].Reason != "selection_limit" || props.Omissions[0].Count != 1 {
		t.Errorf("omissions=%v, want selection_limit=1", props.Omissions)
	}
	if !strings.Contains(props.Reason, "failed") || !strings.Contains(props.Reason, "no approval") {
		t.Errorf("failed check reason must remain non-approving: %q", props.Reason)
	}
	if !strings.Contains(props.Reason, "incomplete") ||
		!(strings.Contains(props.Reason, "scan") || strings.Contains(props.Reason, "coverage")) {
		t.Errorf("partial failed check reason must explicitly state incomplete scan/coverage: %q", props.Reason)
	}
}
