package main

import (
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/diagnostics"
)

// baseSideSARIFSets returns a version 8 verified set whose finding is on
// removed base lines, and the final set that embeds it.
func baseSideSARIFSets(t *testing.T) (diagnostics.Set, diagnostics.Set) {
	t.Helper()
	_, receipt := remotePlanAndReceipt(t)
	check, err := diagnostics.NewDeterministicCheck("24b00a4f30827fb105067c28f424b27c8743be48316d4f88326c0153ec7e8f4b", strings.Repeat("8", 64), strings.Repeat("7", 64), diagnostics.CheckFailed, 1, 1, 1, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	observation, err := diagnostics.NewDeterministicObservation(strings.Repeat("6", 64), strings.Repeat("5", 64), strings.Repeat("8", 64), check.Identity(), "Static observation", "Exact range", diagnostics.SeverityWarning, "static source.go", 2, 3, []string{strings.Repeat("4", 64)})
	if err != nil {
		t.Fatal(err)
	}
	deterministic, err := diagnostics.NewSetWithDeterministicObservations(receipt.Scope(), strings.Repeat("d", 64), strings.Repeat("1", 40), strings.Repeat("8", 64), []diagnostics.DeterministicCheck{check}, []diagnostics.DeterministicObservation{observation})
	if err != nil {
		t.Fatal(err)
	}
	finding, err := diagnostics.NewFindingOnSide(strings.Repeat("a", 64), strings.Repeat("b", 64), "Removed guard", "The zero check was removed.", diagnostics.SeverityError, "calc.go", diagnostics.LineSideBase, 4, 6, []string{strings.Repeat("c", 64)})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := diagnostics.NewSetWithDeterministicChecks(receipt.Scope(), strings.Repeat("9", 64), deterministic.HeadRevision(), strings.Repeat("e", 64), strings.Repeat("f", 64), 1, 0, 0, 1, 1, 0, nil, deterministic.DeterministicChecks(), []diagnostics.Finding{finding})
	if err != nil || verified.SchemaVersion() != 8 {
		t.Fatalf("verified=%v", err)
	}
	final, err := diagnostics.NewFinalReviewSet(receipt.Scope(), deterministic.SnapshotIdentity(), deterministic.HeadRevision(), diagnostics.FinalOutcomeCompleted, deterministic, verified)
	if err != nil {
		t.Fatal(err)
	}
	return verified, final
}

func TestDiagnosticSARIFNeverPlacesBaseLinesAsAHeadRegion(t *testing.T) {
	verified, final := baseSideSARIFSets(t)
	for name, set := range map[string]diagnostics.Set{"version 8": verified, "final version 7": final} {
		if log, err := buildDiagnosticSetSARIF(set); err == nil {
			t.Fatalf("%s: SARIF built with %d run(s) from a base-side finding", name, len(log.Runs))
		}
	}
}
