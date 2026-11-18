package localreview

import (
	"reflect"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/diagnostics"
	"github.com/georgejieh/open-trestle/semanticimpact"
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

// A finding is on unchanged lines when it is on unchanged head lines, outside
// every deletion window, and cites no change evidence; every uncertain case
// keeps it introduced. Unchanged lines alone leave its origin unproven: a
// caller of a changed function, or unchanged lines of a modified file, can be
// broken by the change. Only an unchanged Go file in a run whose profile
// proves the change isolated is pre-existing.
func TestChangeLinesOriginClassification(t *testing.T) {
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
		name             string
		finding          ReportFinding
		linked, isolated findingOrigin
	}{
		{"unchanged lines of a modified file", preExistingFixture("mod.go", 5, 8, "enclosing"), originUnproven, originUnproven},
		{"overlaps a changed range", preExistingFixture("mod.go", 18, 20, "enclosing"), originIntroduced, originIntroduced},
		{"inside the window before a deletion", preExistingFixture("mod.go", 42, 43, "enclosing"), originIntroduced, originIntroduced},
		{"inside the window after a deletion", preExistingFixture("mod.go", 57, 57, "enclosing"), originIntroduced, originIntroduced},
		{"just past the deletion window", preExistingFixture("mod.go", 58, 60, "enclosing"), originUnproven, originUnproven},
		{"cites a changed hunk", preExistingFixture("mod.go", 5, 8, "enclosing", "changed-hunk"), originIntroduced, originIntroduced},
		{"cites removed lines", preExistingFixture("mod.go", 5, 8, "caller", "removed-lines"), originIntroduced, originIntroduced},
		{"a caller in an unchanged file citing only itself", preExistingFixture("caller.go", 5, 5, "caller"), originUnproven, originPreExisting},
		{"an unchanged file that is not Go", preExistingFixture("caller.py", 5, 5, "caller"), originUnproven, originUnproven},
		{"in an added file", preExistingFixture("added.go", 30, 30, "enclosing"), originIntroduced, originIntroduced},
		{"in a modified file with unknown lines", preExistingFixture("binary.go", 5, 5, "enclosing"), originIntroduced, originIntroduced},
	}
	isolated := lines
	isolated.isolated = true
	for _, value := range cases {
		if got := lines.origin(value.finding); got != value.linked {
			t.Fatalf("%s: origin = %d, want %d", value.name, got, value.linked)
		}
		if got := isolated.origin(value.finding); got != value.isolated {
			t.Fatalf("%s in an isolated change: origin = %d, want %d", value.name, got, value.isolated)
		}
		if lines.preExisting(value.finding) {
			t.Fatalf("%s: pre-existing without proof that the change is isolated", value.name)
		}
	}
	base := preExistingFixture("mod.go", 5, 8, "enclosing")
	base.Side = diagnostics.LineSideBase
	if isolated.origin(base) != originIntroduced {
		t.Fatal("a finding on removed base lines was not introduced")
	}
	unknown := isolated
	unknown.evidence = nil
	if unknown.origin(preExistingFixture("caller.go", 5, 5, "caller")) != originIntroduced {
		t.Fatal("a finding was classified without the run's change evidence")
	}
}

// goProfile analyses one changed Go file, with other head Go files that the
// change did not touch.
func goProfile(t *testing.T, changedPath, base, head string, unchanged map[string]string) semanticimpact.Profile {
	t.Helper()
	file := func(path, content string) semanticimpact.File {
		value, err := semanticimpact.NewFile(path, []byte(content))
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	changed, err := semanticimpact.NewChangedPath(changedPath)
	if err != nil {
		t.Fatal(err)
	}
	headFiles := []semanticimpact.File{file(changedPath, head)}
	for path, content := range unchanged {
		headFiles = append(headFiles, file(path, content))
	}
	input, err := semanticimpact.NewInput(strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), []semanticimpact.ChangedPath{changed}, []semanticimpact.File{file(changedPath, base)}, headFiles)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := semanticimpact.AnalyzeGo(input)
	if err != nil {
		t.Fatal(err)
	}
	return profile
}

// The profile proves a change isolated only when nothing outside the changed
// declarations names them, no changed declaration is a method or an init
// function, and nothing was left unanalysed.
func TestIsolatedChangeNeedsAProfileWithoutDependents(t *testing.T) {
	const base = "package p\n\nfunc Avg(xs []int) int {\n\treturn 0\n}\n"
	const head = "package p\n\nfunc Avg(xs []int) int {\n\treturn 1\n}\n"
	const caller = "package p\n\nfunc Use() int {\n\treturn Avg(nil)\n}\n"
	const indirect = "package p\n\nfunc Report() int {\n\treturn Use()\n}\n"
	const other = "package p\n\nfunc Max(xs []int) int {\n\treturn xs[0]\n}\n"
	if isolatedChange(semanticimpact.Profile{}) {
		t.Fatal("no profile proved the change isolated")
	}
	if !isolatedChange(goProfile(t, "p.go", base, head, map[string]string{"other.go": other})) {
		t.Fatal("a change nothing references was not isolated")
	}
	for name, profile := range map[string]semanticimpact.Profile{
		"a direct caller": goProfile(t, "p.go", base, head, map[string]string{"caller.go": caller}),
		// Report reaches Avg only through Use, whose own reference to Avg
		// already proves a dependent.
		"an indirect caller":                      goProfile(t, "p.go", base, head, map[string]string{"caller.go": caller, "report.go": indirect}),
		"an unchanged caller in the changed file": goProfile(t, "p.go", base+"\nfunc Use() int { return Avg(nil) }\n", head+"\nfunc Use() int { return Avg(nil) }\n", nil),
		"a changed method":                        goProfile(t, "p.go", "package p\n\ntype T struct{}\n\nfunc (T) String() string { return \"a\" }\n", "package p\n\ntype T struct{}\n\nfunc (T) String() string { return \"b\" }\n", nil),
		"a changed init function":                 goProfile(t, "p.go", "package p\n\nvar x int\n\nfunc init() { x = 1 }\n", "package p\n\nvar x int\n\nfunc init() { x = 2 }\n", nil),
		"an unparsable head file":                 goProfile(t, "p.go", base, head, map[string]string{"broken.go": "package p\n\nfunc {\n"}),
	} {
		if isolatedChange(profile) {
			t.Fatalf("%s: the change was proved isolated", name)
		}
	}
	// Recursion inside the changed declaration names only itself.
	if !isolatedChange(goProfile(t, "p.go", base, "package p\n\nfunc Avg(xs []int) int {\n\tif len(xs) > 1 {\n\t\treturn Avg(xs[1:])\n\t}\n\treturn 1\n}\n", nil)) {
		t.Fatal("a self-reference inside the changed declaration made the change linked")
	}
}
