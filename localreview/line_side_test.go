package localreview

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/diagnostics"
)

// baseSideDiagnostics is a verified set whose one finding is on removed base
// lines 4-6 of calc.go.
func baseSideDiagnostics(t *testing.T) diagnostics.Set {
	t.Helper()
	scope, err := audit.NewReviewScope("tenant", "repository", "run")
	if err != nil {
		t.Fatal(err)
	}
	finding, err := diagnostics.NewFindingOnSide(strings.Repeat("a", 64), strings.Repeat("b", 64), "Removed guard", "The zero check was removed.", diagnostics.SeverityError, "calc.go", diagnostics.LineSideBase, 4, 6, []string{strings.Repeat("c", 64)})
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

func TestResultProjectionsRefuseABaseSideFinding(t *testing.T) {
	result := Result{wire: resultWire{Status: "findings", RunStatus: "succeeded"}, diagnostics: baseSideDiagnostics(t), valid: true}
	if _, err := result.Report(); !errors.Is(err, ErrBaseSideFindingUnsupported) {
		t.Fatalf("report accepted a base-side finding: %v", err)
	}
	var text bytes.Buffer
	if err := RenderResult(&text, result); !errors.Is(err, ErrBaseSideFindingUnsupported) || text.Len() != 0 {
		t.Fatalf("text rendered a base-side finding: %q, %v", text.String(), err)
	}
}
