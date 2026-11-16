package main

import (
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/diagnostics"
	"github.com/georgejieh/open-trestle/localreview"
)

// baseSideSARIFSets returns a version 8 verified set with a base-side finding
// at a deletion point of calc.go (base lines 4-6, beside head line 3) and one
// in the removed file gone.go (no head line), and the final set embedding it.
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
	placed, err := diagnostics.NewBaseSideFinding(strings.Repeat("a", 64), strings.Repeat("b", 64), "Removed guard", "The zero check was removed.", diagnostics.SeverityError, "calc.go", 4, 6, 3, []string{strings.Repeat("c", 64)})
	if err != nil {
		t.Fatal(err)
	}
	unplaced, err := diagnostics.NewBaseSideFinding(strings.Repeat("a", 64), strings.Repeat("9", 64), "Removed helper", "Callers still import it.", diagnostics.SeverityError, "gone.go", 1, 2, 0, []string{strings.Repeat("c", 64)})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := diagnostics.NewSetWithDeterministicChecks(receipt.Scope(), strings.Repeat("9", 64), deterministic.HeadRevision(), strings.Repeat("e", 64), strings.Repeat("f", 64), 2, 0, 0, 1, 1, 0, nil, deterministic.DeterministicChecks(), []diagnostics.Finding{placed, unplaced})
	if err != nil || verified.SchemaVersion() != 8 {
		t.Fatalf("verified=%v", err)
	}
	final, err := diagnostics.NewFinalReviewSet(receipt.Scope(), deterministic.SnapshotIdentity(), deterministic.HeadRevision(), diagnostics.FinalOutcomeCompleted, deterministic, verified)
	if err != nil {
		t.Fatal(err)
	}
	return verified, final
}

// requireBaseSideSARIF checks that the deletion-point finding is a result at
// its head line naming the removed base lines, and that the removed-file
// finding is a run notification, never a result at base line numbers.
func requireBaseSideSARIF(t *testing.T, name string, log sarifLog) {
	t.Helper()
	run := log.Runs[0]
	var found *sarifResult
	for index := range run.Results {
		result := run.Results[index]
		uri := result.Locations[0].PhysicalLocation.ArtifactLocation.URI
		if uri == sarifArtifactURI("gone.go") {
			t.Fatalf("%s: removed-file finding became a result", name)
		}
		if uri == sarifArtifactURI("calc.go") {
			found = &result
		}
	}
	if found == nil {
		t.Fatalf("%s: deletion-point finding is missing", name)
	}
	region, properties := found.Locations[0].PhysicalLocation.Region, found.Properties
	if region.StartLine != 3 || region.EndLine != 3 || !strings.Contains(found.Message.Text, "(removed base lines 4-6)") ||
		properties.Side != "base" || properties.BaseStartLine == nil || *properties.BaseStartLine != 4 || properties.BaseEndLine == nil || *properties.BaseEndLine != 6 {
		t.Fatalf("%s: deletion-point finding region=%+v message=%q side=%q", name, region, found.Message.Text, properties.Side)
	}
	notified := false
	for _, invocation := range run.Invocations {
		for _, notification := range invocation.ToolExecutionNotifications {
			notified = notified || strings.Contains(notification.Message.Text, "removed base lines 1-2 of gone.go") && strings.Contains(notification.Message.Text, "Removed helper")
		}
	}
	if !notified {
		t.Fatalf("%s: removed-file finding was silently dropped: %+v", name, run.Invocations)
	}
}

func TestDiagnosticSARIFNeverPlacesBaseLinesAsAHeadRegion(t *testing.T) {
	verified, final := baseSideSARIFSets(t)
	for name, set := range map[string]diagnostics.Set{"version 8": verified, "final version 7": final} {
		log, err := buildDiagnosticSetSARIF(set)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		requireBaseSideSARIF(t, name, log)
	}
}

func TestModelReviewSARIFNeverPlacesBaseLinesAsAHeadRegion(t *testing.T) {
	report := localreview.Report{Status: "findings", RunStatus: "succeeded", Findings: []localreview.ReportFinding{
		{Identity: strings.Repeat("a", 64), Fingerprint: strings.Repeat("b", 64), Title: "Removed guard", Claim: "The zero check was removed.", Severity: diagnostics.SeverityError, Path: "calc.go", StartLine: 4, EndLine: 6, EvidenceIDs: []string{"e1"}, Category: "correctness", Side: diagnostics.LineSideBase, HeadLine: 3},
		{Identity: strings.Repeat("c", 64), Fingerprint: strings.Repeat("d", 64), Title: "Removed helper", Claim: "Callers still import it.", Severity: diagnostics.SeverityError, Path: "gone.go", StartLine: 1, EndLine: 2, EvidenceIDs: []string{"e2"}, Category: "correctness", Side: diagnostics.LineSideBase},
	}}
	log, err := buildModelReviewSARIF(report)
	if err != nil {
		t.Fatal(err)
	}
	requireBaseSideSARIF(t, "model review", log)
	if len(log.Runs[0].Results) != 1 {
		t.Fatalf("results=%d", len(log.Runs[0].Results))
	}
	// A base-side finding never shares a content hash with a head finding of
	// the same text at the same path.
	head := report.Findings[0]
	head.Side, head.HeadLine = diagnostics.LineSideHead, 0
	if modelReviewContentHash(head) == modelReviewContentHash(report.Findings[0]) {
		t.Fatal("base and head findings share a content hash")
	}
}
