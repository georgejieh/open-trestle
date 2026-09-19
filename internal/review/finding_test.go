package review

import (
	"testing"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

func TestNewFindingCreatesEvidenceLinkedFinding(t *testing.T) {
	sourceRange, err := evidence.NewSourceRange("main.go", 8, 10)
	if err != nil {
		t.Fatalf("evidence.NewSourceRange() error = %v", err)
	}

	finding, err := NewFinding("finding-1", "Unchecked error", SeverityHigh, sourceRange, []string{"evidence-1"})
	if err != nil {
		t.Fatalf("NewFinding() error = %v", err)
	}

	if finding.ID() != "finding-1" || finding.Title() != "Unchecked error" || finding.Severity() != SeverityHigh {
		t.Fatalf("NewFinding() returned unexpected identity, title, or severity")
	}
	if finding.SourceRange() != sourceRange {
		t.Fatalf("SourceRange() = %#v, want %#v", finding.SourceRange(), sourceRange)
	}
	if got := finding.EvidenceIDs(); len(got) != 1 || got[0] != "evidence-1" {
		t.Fatalf("EvidenceIDs() = %#v, want %#v", got, []string{"evidence-1"})
	}
}

func TestNewFindingRejectsIncompleteOrUnsupportedInput(t *testing.T) {
	sourceRange, err := evidence.NewSourceRange("main.go", 1, 1)
	if err != nil {
		t.Fatalf("evidence.NewSourceRange() error = %v", err)
	}
	testCases := []struct {
		name        string
		id          string
		title       string
		severity    Severity
		sourceRange evidence.SourceRange
		evidenceIDs []string
	}{
		{name: "missing identity", title: "Title", severity: SeverityLow, sourceRange: sourceRange, evidenceIDs: []string{"evidence-1"}},
		{name: "missing title", id: "finding-1", severity: SeverityLow, sourceRange: sourceRange, evidenceIDs: []string{"evidence-1"}},
		{name: "unknown severity", id: "finding-1", title: "Title", severity: Severity("unknown"), sourceRange: sourceRange, evidenceIDs: []string{"evidence-1"}},
		{name: "missing range", id: "finding-1", title: "Title", severity: SeverityLow, evidenceIDs: []string{"evidence-1"}},
		{name: "missing evidence", id: "finding-1", title: "Title", severity: SeverityLow, sourceRange: sourceRange},
		{name: "empty evidence identity", id: "finding-1", title: "Title", severity: SeverityLow, sourceRange: sourceRange, evidenceIDs: []string{""}},
		{name: "duplicate evidence identity", id: "finding-1", title: "Title", severity: SeverityLow, sourceRange: sourceRange, evidenceIDs: []string{"evidence-1", "evidence-1"}},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := NewFinding(testCase.id, testCase.title, testCase.severity, testCase.sourceRange, testCase.evidenceIDs); err == nil {
				t.Fatal("NewFinding() error = nil, want validation error")
			}
		})
	}
}

func TestFindingDoesNotExposeMutableEvidenceIDs(t *testing.T) {
	sourceRange, err := evidence.NewSourceRange("main.go", 1, 1)
	if err != nil {
		t.Fatalf("evidence.NewSourceRange() error = %v", err)
	}
	evidenceIDs := []string{"evidence-1"}
	finding, err := NewFinding("finding-1", "Title", SeverityLow, sourceRange, evidenceIDs)
	if err != nil {
		t.Fatalf("NewFinding() error = %v", err)
	}

	evidenceIDs[0] = "changed-input"
	returnedIDs := finding.EvidenceIDs()
	returnedIDs[0] = "changed-output"
	if got := finding.EvidenceIDs()[0]; got != "evidence-1" {
		t.Fatalf("EvidenceIDs()[0] = %q, want %q", got, "evidence-1")
	}
}
