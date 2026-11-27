package localreview

import (
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/diagnostics"
)

func TestLocalReadinessDispositionPreservesTerminalMeaning(t *testing.T) {
	tests := []struct {
		name                            string
		verified, omitted, inconclusive uint32
		status, ci                      string
	}{
		{"verified", 1, 0, 0, "findings", "blocked"},
		{"omitted", 0, 1, 0, "incomplete", "inconclusive"},
		{"inconclusive", 0, 0, 1, "incomplete", "inconclusive"},
		{"no candidates, or every candidate rejected", 0, 0, 0, "no_candidates", "inconclusive"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			status, ci := localReadinessDisposition(test.verified, test.omitted, test.inconclusive)
			if status != test.status || ci != test.ci {
				t.Fatalf("disposition=(%s,%s) want=(%s,%s)", status, ci, test.status, test.ci)
			}
		})
	}
}

// A completed review is blocked only by a medium, high or critical finding
// the change introduced; low-severity and pre-existing findings are advisory.
func TestBlocksCIOnlyForIntroducedMediumOrHigher(t *testing.T) {
	for _, test := range []struct {
		severity    diagnostics.Severity
		preExisting bool
		blocks      bool
	}{
		{diagnostics.SeverityError, false, true},
		{diagnostics.SeverityWarning, false, true},
		{diagnostics.SeverityInformation, false, false},
		{diagnostics.SeverityHint, false, false},
		{diagnostics.SeverityError, true, false},
		{diagnostics.SeverityWarning, true, false},
		{diagnostics.SeverityInformation, true, false},
	} {
		if got := BlocksCI(test.severity, test.preExisting); got != test.blocks {
			t.Fatalf("BlocksCI(%s, pre-existing=%t) = %t", test.severity, test.preExisting, got)
		}
	}
	// A mix of a low introduced finding and a medium pre-existing one is
	// advisory: neither group blocks.
	low := mergeFixture("l", "Low one", "A low statement.", diagnostics.SeverityInformation, "a.go", 1, 1, "style")
	old := mergeFixture("o", "Old medium", "A medium statement on old lines.", diagnostics.SeverityWarning, "a.go", 9, 9, "reliability")
	old.PreExisting = true
	groups := RankFindings(DeduplicateFindings([]FindingOrigin{{Label: "general", Findings: []ReportFinding{low, old}}}))
	if len(groups) != 2 {
		t.Fatalf("the mixed fixture merged: %d groups", len(groups))
	}
	for _, group := range groups {
		if group.Blocking() {
			t.Fatalf("an advisory group blocks: %+v", group.Finding)
		}
	}
	introduced := old
	introduced.PreExisting = false
	if !RankFindings(DeduplicateFindings([]FindingOrigin{{Label: "general", Findings: []ReportFinding{introduced}}}))[0].Blocking() {
		t.Fatal("an introduced medium finding does not block")
	}
}

// The import re-derives the disposition from the recorded severities: a
// version 6 result whose findings are all low severity must be inconclusive,
// one with a medium or higher finding must be blocked, and a result written
// before version 6 keeps the readiness disposition.
func TestExpectedImportedCIRederivesFromSeverities(t *testing.T) {
	finding := func(severity diagnostics.Severity) diagnostics.Finding {
		value, err := diagnostics.NewFinding(strings.Repeat("a", 64), strings.Repeat("b", 64), "Title", "Claim.", severity, "a.go", 1, 1, []string{strings.Repeat("c", 64)})
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	low, hint, medium, high := finding(diagnostics.SeverityInformation), finding(diagnostics.SeverityHint), finding(diagnostics.SeverityWarning), finding(diagnostics.SeverityError)
	for _, test := range []struct {
		version  int
		findings []diagnostics.Finding
		want     string
	}{
		{tokenUsageResultVersion, []diagnostics.Finding{low}, "inconclusive"},
		{tokenUsageResultVersion, []diagnostics.Finding{low, hint}, "inconclusive"},
		{tokenUsageResultVersion, []diagnostics.Finding{low, medium}, "blocked"},
		{tokenUsageResultVersion, []diagnostics.Finding{high}, "blocked"},
		{styleResultVersion, []diagnostics.Finding{low}, "blocked"},
		{guidanceResultVersion, []diagnostics.Finding{low}, "blocked"},
		{1, []diagnostics.Finding{low}, "blocked"},
	} {
		if got := expectedImportedCI(test.version, test.findings, "blocked"); got != test.want {
			t.Fatalf("version %d with %d findings: %s, want %s", test.version, len(test.findings), got, test.want)
		}
	}
	if got := expectedImportedCI(tokenUsageResultVersion, nil, "inconclusive"); got != "inconclusive" {
		t.Fatalf("a result without findings changed disposition: %s", got)
	}
}
