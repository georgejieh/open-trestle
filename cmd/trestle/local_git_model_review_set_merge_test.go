package main

import (
	"testing"

	"github.com/georgejieh/open-trestle/diagnostics"
	"github.com/georgejieh/open-trestle/localreview"
)

// A finding that overlaps an already-absorbed finding's claims must not merge
// into that group when it shares no claims with the group's representative.
// Otherwise a distinct defect is reported under another defect's title and
// severity, and the finding count under-reports the defects present.
func TestMergedFindingDoesNotInheritAbsorbedEntryClaims(t *testing.T) {
	representative := localreview.ReportFinding{
		Identity: "a", Title: "Missing authorization check allows account takeover",
		Claim:    "The request reaches the account mutation without an authorization check.",
		Severity: diagnostics.SeverityError, Path: "account.go", StartLine: 10, EndLine: 20,
		Category: "security", EvidenceIDs: []string{"hunk-1"},
	}
	absorbed := localreview.ReportFinding{
		Identity: "b", Title: "Account takeover is possible because authorization is missing",
		Claim:    "The authorization check for the account mutation is absent, permitting takeover.",
		Severity: diagnostics.SeverityError, Path: "account.go", StartLine: 18, EndLine: 30,
		Category: "security", EvidenceIDs: []string{"hunk-2"},
	}
	distinct := localreview.ReportFinding{
		Identity: "c", Title: "Unscoped query returns another tenant's token",
		Claim:    "The tenant scoped query is unscoped and returns another tenant's token.",
		Severity: diagnostics.SeverityError, Path: "account.go", StartLine: 28, EndLine: 40,
		Category: "security", EvidenceIDs: []string{"hunk-3"},
	}
	merged, duplicates := mergeVerifiedFindings(
		[]string{"m0", "m1", "m2"},
		[][]localreview.ReportFinding{{representative}, {absorbed}, {distinct}},
	)
	if len(merged) != 2 {
		t.Fatalf("three distinct findings collapsed into %d", len(merged))
	}
	if duplicates != 1 {
		t.Fatalf("duplicates = %d, want 1 (only the true duplicate merges)", duplicates)
	}
	for _, finding := range merged {
		if finding.Title == representative.Title && len(finding.Contributors) != 2 {
			t.Fatalf("the true duplicate group has %d contributors, want 2", len(finding.Contributors))
		}
	}
}

// The merge must stay deterministic and must still merge a genuine duplicate
// that arrives from a different member.
func TestMergeStillCollapsesGenuineDuplicates(t *testing.T) {
	first := localreview.ReportFinding{
		Identity: "a", Title: "Missing authorization check allows account takeover",
		Claim:    "The request reaches the account mutation without an authorization check.",
		Severity: diagnostics.SeverityError, Path: "account.go", StartLine: 20, EndLine: 24,
		Category: "security", EvidenceIDs: []string{"changed-hunk"},
	}
	second := localreview.ReportFinding{
		Identity: "b", Title: "Account takeover is possible because authorization is missing",
		Claim:    "The authorization check for the account mutation is absent, permitting takeover.",
		Severity: diagnostics.SeverityError, Path: "account.go", StartLine: 20, EndLine: 24,
		Category: "security", EvidenceIDs: []string{"changed-hunk"},
	}
	merged, duplicates := mergeVerifiedFindings([]string{"m0", "m1"}, [][]localreview.ReportFinding{{first}, {second}})
	if len(merged) != 1 || duplicates != 1 {
		t.Fatalf("a genuine duplicate was not merged: merged=%d duplicates=%d", len(merged), duplicates)
	}
}
