package localreview

import (
	"bytes"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/diagnostics"
)

// baseSideDiagnostics is a verified set whose one finding is on removed base
// lines 4-6 of calc.go, beside head line 3.
func baseSideDiagnostics(t *testing.T) diagnostics.Set {
	t.Helper()
	scope, err := audit.NewReviewScope("tenant", "repository", "run")
	if err != nil {
		t.Fatal(err)
	}
	finding, err := diagnostics.NewBaseSideFinding(strings.Repeat("a", 64), strings.Repeat("b", 64), "Removed guard", "The zero check was removed.", diagnostics.SeverityError, "calc.go", 4, 6, 3, []string{strings.Repeat("c", 64)})
	if err != nil {
		t.Fatal(err)
	}
	check, err := diagnostics.NewDeterministicCheck("3f01f93e51003eb3a0deca04719a3957d6e367c97c33bdfea105174d95698092", strings.Repeat("8", 64), strings.Repeat("7", 64), diagnostics.CheckPassed, 1, 2, 1, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	set, err := diagnostics.NewSetWithDeterministicChecks(scope, strings.Repeat("d", 64), strings.Repeat("1", 40), strings.Repeat("e", 64), strings.Repeat("f", 64), 1, 0, 0, 1, 1, 0, nil, []diagnostics.DeterministicCheck{check}, []diagnostics.Finding{finding})
	if err != nil || set.SchemaVersion() != 8 {
		t.Fatalf("base-side set: %v", err)
	}
	return set
}

func TestResultProjectionsNameRemovedBaseLines(t *testing.T) {
	result := Result{wire: resultWire{Status: "findings", RunStatus: "succeeded"}, diagnostics: baseSideDiagnostics(t), valid: true}
	report, err := result.Report()
	if err != nil || len(report.Findings) != 1 {
		t.Fatalf("report: %v", err)
	}
	if finding := report.Findings[0]; finding.Side != diagnostics.LineSideBase || finding.HeadLine != 3 || finding.StartLine != 4 || finding.EndLine != 6 {
		t.Fatalf("report finding side=%s head line=%d", finding.Side, finding.HeadLine)
	}
	var text bytes.Buffer
	if err := RenderResult(&text, result); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text.String(), "source: calc.go removed base lines 4-6 (beside head line 3)\n") || strings.Contains(text.String(), "calc.go:4-6") {
		t.Fatalf("text shows base lines as head lines:\n%s", text.String())
	}
}

func TestSourceTextNamesTheSide(t *testing.T) {
	for _, tc := range []struct {
		side     diagnostics.LineSide
		headLine uint32
		want     string
	}{
		{diagnostics.LineSideHead, 0, "calc.go:4-6"},
		{diagnostics.LineSideBase, 3, "calc.go removed base lines 4-6 (beside head line 3)"},
		{diagnostics.LineSideBase, 0, "calc.go removed base lines 4-6"},
	} {
		if got := SourceText("calc.go", tc.side, 4, 6, tc.headLine); got != tc.want {
			t.Fatalf("SourceText(%s, %d) = %q, want %q", tc.side, tc.headLine, got, tc.want)
		}
	}
}
