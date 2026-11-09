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

// Base and head line numbers are different coordinates: a finding on removed
// base lines never merges with a head finding of the same text and numbers.
func TestMergeKeepsBaseAndHeadFindingsApart(t *testing.T) {
	head := localreview.ReportFinding{
		Identity: "a", Title: "Missing zero guard", Claim: "The division by b is no longer guarded.",
		Severity: diagnostics.SeverityError, Path: "calc.go", StartLine: 4, EndLine: 6,
		Category: "correctness", EvidenceIDs: []string{"window"},
	}
	base := head
	base.Identity, base.Side, base.HeadLine, base.EvidenceIDs = "b", diagnostics.LineSideBase, 3, []string{"removed"}
	merged, duplicates := mergeVerifiedFindings([]string{"m0", "m1"}, [][]localreview.ReportFinding{{head}, {base}})
	if len(merged) != 2 || duplicates != 0 {
		t.Fatalf("base and head findings merged: merged=%d duplicates=%d", len(merged), duplicates)
	}
	if merged[0].Side != "" || merged[1].Side != "base" || merged[1].HeadLine != 3 || merged[1].Contributors[0].Side != "base" {
		t.Fatalf("merged sides: %+v", merged)
	}
	// Two base-side duplicates still merge.
	again := base
	again.Identity = "c"
	if merged, duplicates := mergeVerifiedFindings([]string{"m0", "m1"}, [][]localreview.ReportFinding{{base}, {again}}); len(merged) != 1 || duplicates != 1 {
		t.Fatalf("base-side duplicates did not merge: merged=%d duplicates=%d", len(merged), duplicates)
	}
}
