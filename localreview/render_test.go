package localreview

import (
	"fmt"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/diagnostics"
)

// rankedLow builds count distinct ranked low-severity findings, one a line.
func rankedLow(count int) []MergedFinding {
	findings := make([]ReportFinding, 0, count)
	for index := range count {
		line := uint32(1 + index*10)
		findings = append(findings, mergeFixture(fmt.Sprintf("l%02d", index), fmt.Sprintf("Low finding %02d", index), fmt.Sprintf("Statement number %02d about line %d.", index, line), diagnostics.SeverityInformation, "a.go", line, line, "style"))
	}
	return RankFindings(DeduplicateFindings([]FindingOrigin{{Label: "general", Findings: findings}}))
}

// When no confirmed finding is high, critical or medium, text and Markdown
// never hide everything: they list the lower-severity findings, up to
// MaxLowerSeverityShown, and count the rest.
func TestFindingSectionsNeverHideEverything(t *testing.T) {
	for _, test := range []struct {
		count, shown, hidden int
	}{{1, 1, 0}, {3, 3, 0}, {MaxLowerSeverityShown, MaxLowerSeverityShown, 0}, {MaxLowerSeverityShown + 2, MaxLowerSeverityShown, 2}} {
		ranked := rankedLow(test.count)
		confirmed, preExisting, hidden := FindingSections(ranked, RenderOptions{})
		if len(confirmed)+len(preExisting) != test.shown || hidden != test.hidden {
			t.Fatalf("%d low findings: shown=%d hidden=%d, want %d and %d", test.count, len(confirmed)+len(preExisting), hidden, test.shown, test.hidden)
		}
		for index, group := range confirmed {
			if group.Rank != index+1 {
				t.Fatalf("the shown low findings are not the first in rank order: %d at %d", group.Rank, index)
			}
		}
		text := FindingsText(ranked, RenderOptions{}, nil)
		if !strings.Contains(text, fmt.Sprintf("confirmed findings (ranked): %d\n", test.shown)) || strings.Count(text, "finding: information ") != test.shown {
			t.Fatalf("text did not list the low findings:\n%s", text)
		}
		if note := HiddenNote(test.hidden); test.hidden > 0 && !strings.Contains(text, "hidden: "+note+"\n") || test.hidden == 0 && strings.Contains(text, "hidden:") {
			t.Fatalf("text hidden count is wrong:\n%s", text)
		}
		markdown := FindingsMarkdown(ranked, RenderOptions{}, nil)
		if strings.Contains(markdown, "None listed.") || strings.Count(markdown, "**Low: ") != test.shown {
			t.Fatalf("Markdown did not list the low findings:\n%s", markdown)
		}
		if _, _, hidden := FindingSections(ranked, RenderOptions{All: true}); hidden != 0 {
			t.Fatalf("--all hid %d findings", hidden)
		}
	}
	// Pre-existing lower-severity findings count toward the cap too.
	ranked := rankedLow(MaxLowerSeverityShown + 1)
	ranked[0].Contributors[0].PreExisting = true
	confirmed, preExisting, hidden := FindingSections(ranked, RenderOptions{})
	if len(preExisting) != 1 || len(confirmed) != MaxLowerSeverityShown-1 || hidden != 1 {
		t.Fatalf("pre-existing low finding: confirmed=%d pre-existing=%d hidden=%d", len(confirmed), len(preExisting), hidden)
	}
}

// One medium finding is enough to show: the low ones are then counted, as
// before.
func TestFindingSectionsHideLowerSeverityBehindAShownFinding(t *testing.T) {
	findings := []ReportFinding{
		mergeFixture("m", "Medium one", "A medium finding statement.", diagnostics.SeverityWarning, "a.go", 30, 30, "reliability"),
		mergeFixture("l", "Low one", "A low finding statement.", diagnostics.SeverityInformation, "a.go", 50, 50, "style"),
		mergeFixture("n", "Hint one", "A hint finding statement.", diagnostics.SeverityHint, "a.go", 70, 70, "documentation"),
	}
	ranked := RankFindings(DeduplicateFindings([]FindingOrigin{{Label: "general", Findings: findings}}))
	confirmed, preExisting, hidden := FindingSections(ranked, RenderOptions{})
	if len(confirmed) != 1 || confirmed[0].Finding.Identity != "m" || len(preExisting) != 0 || hidden != 2 {
		t.Fatalf("medium with low findings: confirmed=%d pre-existing=%d hidden=%d", len(confirmed), len(preExisting), hidden)
	}
	// A medium pre-existing finding is shown, so the low ones stay counted.
	ranked[0].Contributors[0].PreExisting = true
	if confirmed, preExisting, hidden := FindingSections(ranked, RenderOptions{}); len(confirmed) != 0 || len(preExisting) != 1 || hidden != 2 {
		t.Fatalf("pre-existing medium with low findings: confirmed=%d pre-existing=%d hidden=%d", len(confirmed), len(preExisting), hidden)
	}
}
