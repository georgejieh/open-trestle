package main

import (
	"testing"

	"github.com/georgejieh/open-trestle/diagnostics"
	"github.com/georgejieh/open-trestle/localreview"
)

const (
	takeoverTitle = "Missing authorization check allows account takeover"
	takeoverClaim = "The request reaches the account mutation without an authorization check."
)

// The set merges with the shared rule: a finding joins a group only through
// the representative's own range, never through a finding the group already
// absorbed, so a distinct defect is never reported under another's title.
func TestMergedFindingDoesNotInheritAbsorbedEntryClaims(t *testing.T) {
	representative := localreview.ReportFinding{
		Identity: "a", Title: takeoverTitle, Claim: takeoverClaim,
		Severity: diagnostics.SeverityError, Path: "account.go", StartLine: 10, EndLine: 20,
		Category: "security", EvidenceIDs: []string{"hunk-1", "hunk-0"},
	}
	absorbed := localreview.ReportFinding{
		Identity: "b", Title: takeoverTitle, Claim: takeoverClaim,
		Severity: diagnostics.SeverityError, Path: "account.go", StartLine: 18, EndLine: 30,
		Category: "security", EvidenceIDs: []string{"hunk-2"},
	}
	// Same statement, but it overlaps only the absorbed finding's range.
	late := localreview.ReportFinding{
		Identity: "c", Title: takeoverTitle, Claim: takeoverClaim,
		Severity: diagnostics.SeverityError, Path: "account.go", StartLine: 28, EndLine: 40,
		Category: "security", EvidenceIDs: []string{"hunk-3"},
	}
	merged, duplicates := mergeVerifiedFindings(
		[]string{"m0", "m1", "m2"},
		[][]localreview.ReportFinding{{representative}, {absorbed}, {late}},
	)
	if len(merged) != 2 || duplicates != 1 {
		t.Fatalf("merged=%d duplicates=%d, want 2 groups and 1 duplicate", len(merged), duplicates)
	}
	for _, finding := range merged {
		if finding.FindingIdentity == "a" && len(finding.Contributors) != 2 {
			t.Fatalf("the true duplicate group has %d contributors, want 2", len(finding.Contributors))
		}
	}
}

// Near-identical statements from different members merge; a paraphrase of
// the same defect is not near-identical and stays a separate, ranked finding.
func TestMergeCollapsesNearIdenticalDuplicatesOnly(t *testing.T) {
	first := localreview.ReportFinding{
		Identity: "a", Title: takeoverTitle, Claim: takeoverClaim,
		Severity: diagnostics.SeverityError, Path: "account.go", StartLine: 20, EndLine: 24,
		Category: "security", EvidenceIDs: []string{"changed-hunk"},
	}
	second := first
	second.Identity, second.Title = "b", takeoverTitle+"."
	merged, duplicates := mergeVerifiedFindings([]string{"m0", "m1"}, [][]localreview.ReportFinding{{first}, {second}})
	if len(merged) != 1 || duplicates != 1 || merged[0].Rank != 1 || len(merged[0].Contributors) != 2 {
		t.Fatalf("a near-identical duplicate was not merged: merged=%d duplicates=%d", len(merged), duplicates)
	}
	paraphrase := first
	paraphrase.Identity, paraphrase.Title, paraphrase.Claim = "c", "Account takeover is possible because authorization is missing", "The authorization check for the account mutation is absent, permitting takeover."
	merged, duplicates = mergeVerifiedFindings([]string{"m0", "m1"}, [][]localreview.ReportFinding{{first}, {paraphrase}})
	if len(merged) != 2 || duplicates != 0 || merged[0].Rank != 1 || merged[1].Rank != 2 {
		t.Fatalf("a paraphrase merged or lost its rank: merged=%d duplicates=%d", len(merged), duplicates)
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
	// Head before base on equal rank keys.
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
