package tui

import (
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/diagnostics"
)

func TestRunNeverShowsBaseLinesAsHeadLines(t *testing.T) {
	service, deterministic, _ := tuiFinalEvidence(t)
	head := service.set.Findings()[0]
	base, err := diagnostics.NewFindingOnSide(strings.Repeat("e", 64), strings.Repeat("9", 64), "Removed guard", "The zero check was removed.", diagnostics.SeverityError, head.Path(), diagnostics.LineSideBase, 1, 2, []string{"evidence:one"})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := diagnostics.NewSetWithDeterministicChecks(deterministic.Scope(), service.set.SnapshotIdentity(), service.set.HeadRevision(), service.set.VerifiedSetIdentity(), strings.Repeat("f", 64), 2, 0, 0, 1, 1, 0, nil, deterministic.DeterministicChecks(), []diagnostics.Finding{head, base})
	if err != nil || verified.SchemaVersion() != 8 {
		t.Fatalf("verified=%v", err)
	}
	final, err := diagnostics.NewFinalReviewSet(deterministic.Scope(), deterministic.SnapshotIdentity(), deterministic.HeadRevision(), diagnostics.FinalOutcomeCompleted, deterministic, verified)
	if err != nil {
		t.Fatal(err)
	}
	for name, set := range map[string]diagnostics.Set{"version 8": verified, "final version 7": final} {
		service.set = set
		output := renderFinalService(t, service)
		if !strings.Contains(output, "src/main.go:7-8") || strings.Contains(output, "src/main.go:1-2") {
			t.Fatalf("%s: base-side finding shown as a head location:\n%s", name, output)
		}
		if !strings.Contains(output, "src/main.go (removed base lines 1-2)") || !strings.Contains(output, "Removed guard") {
			t.Fatalf("%s: base-side finding is not labelled:\n%s", name, output)
		}
		if name == "version 8" && !strings.Contains(output, "changed Go range(s)") {
			t.Fatalf("version 8 lost its deterministic check summary:\n%s", output)
		}
	}
}
