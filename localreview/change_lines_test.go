package localreview

import (
	"reflect"
	"testing"

	"github.com/georgejieh/open-trestle/diagnostics"
)

// The fresh diff of a modified file records added and removed line counts,
// the changed head ranges, and the head line after each pure deletion, also
// where a file both adds and deletes lines.
func TestDiffModifiedFileRecordsChangedRangesAndDeletionPoints(t *testing.T) {
	base := []byte("package p\n\nfunc A() int {\n\tif x == 0 {\n\t\treturn 0\n\t}\n\treturn 1\n}\n\nfunc B() int { return 2 }\n")
	head := []byte("package p\n\nfunc A() int {\n\treturn 1\n}\n\nfunc B() int { return 3 }\nfunc C() int { return 4 }\n")
	var value pathChange
	diffModifiedFile(&value, "p.go", base, head)
	if !value.known || value.added != 2 || value.removed != 4 {
		t.Fatalf("counts: known=%t added=%d removed=%d", value.known, value.added, value.removed)
	}
	if !reflect.DeepEqual(value.changed, [][2]uint32{{7, 8}}) {
		t.Fatalf("changed ranges = %v", value.changed)
	}
	// The guard (base lines 4-6) was removed before head line 4.
	if !reflect.DeepEqual(value.deletions, []uint32{4}) {
		t.Fatalf("deletion points = %v", value.deletions)
	}
}

func TestLineCountCountsAFinalLineWithoutNewline(t *testing.T) {
	for content, want := range map[string]uint32{"": 0, "a": 1, "a\n": 1, "a\nb": 2, "a\nb\n": 2} {
		if got := lineCount([]byte(content)); got != want {
			t.Fatalf("lineCount(%q) = %d, want %d", content, got, want)
		}
	}
}

func preExistingFixture(path string, start, end uint32, evidence ...string) ReportFinding {
	return ReportFinding{Identity: "f", Path: path, StartLine: start, EndLine: end, EvidenceIDs: evidence, Side: diagnostics.LineSideHead}
}

// A finding is pre-existing only when it is on unchanged head lines, outside
// every deletion window, and cites no change evidence.
// Every uncertain case keeps it introduced, so it keeps blocking.
func TestChangeLinesPreExistingClassification(t *testing.T) {
	lines := changeLines{
		paths: map[string]*pathChange{
			"mod.go":     {kind: "modified", known: true, changed: [][2]uint32{{20, 22}}, deletions: []uint32{50}},
			"added.go":   {kind: "added", known: true, changed: [][2]uint32{{1, 10}}},
			"removed.go": {kind: "removed", known: true},
			"binary.go":  {kind: "modified"},
		},
		evidence: map[string]bool{"changed-hunk": true, "removed-lines": true},
	}
	cases := []struct {
		name    string
		finding ReportFinding
		want    bool
	}{
		{"unchanged lines of a modified file", preExistingFixture("mod.go", 5, 8, "enclosing"), true},
		{"overlaps a changed range", preExistingFixture("mod.go", 18, 20, "enclosing"), false},
		{"inside the window before a deletion", preExistingFixture("mod.go", 42, 43, "enclosing"), false},
		{"inside the window after a deletion", preExistingFixture("mod.go", 57, 57, "enclosing"), false},
		{"just past the deletion window", preExistingFixture("mod.go", 58, 60, "enclosing"), true},
		{"cites a changed hunk", preExistingFixture("mod.go", 5, 8, "enclosing", "changed-hunk"), false},
		{"cites removed lines", preExistingFixture("mod.go", 5, 8, "caller", "removed-lines"), false},
		{"a caller in an unchanged file citing only itself", preExistingFixture("caller.go", 5, 5, "caller"), true},
		{"in an added file", preExistingFixture("added.go", 30, 30, "enclosing"), false},
		{"in a modified file with unknown lines", preExistingFixture("binary.go", 5, 5, "enclosing"), false},
	}
	for _, value := range cases {
		if got := lines.preExisting(value.finding); got != value.want {
			t.Fatalf("%s: pre-existing = %t, want %t", value.name, got, value.want)
		}
	}
	base := preExistingFixture("mod.go", 5, 8, "enclosing")
	base.Side = diagnostics.LineSideBase
	if lines.preExisting(base) {
		t.Fatal("a finding on removed base lines was classified pre-existing")
	}
	unknown := lines
	unknown.evidence = nil
	if unknown.preExisting(preExistingFixture("mod.go", 5, 8, "enclosing")) {
		t.Fatal("a finding was classified pre-existing without the run's change evidence")
	}
}
