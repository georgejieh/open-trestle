package tui

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/diagnostics"
	analysishandler "github.com/georgejieh/open-trestle/handlers/analysis"
)

func tuiFinalEvidence(t *testing.T) (*fakeService, diagnostics.Set, diagnostics.Set) {
	t.Helper()
	service, scope := tuiFixture(t)
	source, err := analysishandler.NewDeterministicCheck(strings.Repeat("7", 64), analysishandler.CheckFailed, 1, 1, 1, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	analysisIdentity := strings.Repeat("8", 64)
	check, err := diagnostics.NewDeterministicCheck(source.Identity(), analysisIdentity, strings.Repeat("7", 64), diagnostics.CheckFailed, 1, 1, 1, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	observation, err := diagnostics.NewDeterministicObservation(strings.Repeat("a", 64), strings.Repeat("b", 64), analysisIdentity, check.Identity(), "Debug output left in source", "Not independently verified.", diagnostics.SeverityWarning, "observed.go", 3, 3, []string{strings.Repeat("c", 64)})
	if err != nil {
		t.Fatal(err)
	}
	deterministic, err := diagnostics.NewSetWithDeterministicObservations(scope, service.set.SnapshotIdentity(), service.set.HeadRevision(), analysisIdentity, []diagnostics.DeterministicCheck{check}, []diagnostics.DeterministicObservation{observation})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := diagnostics.NewSetWithDeterministicChecks(scope, service.set.SnapshotIdentity(), service.set.HeadRevision(), service.set.VerifiedSetIdentity(), strings.Repeat("f", 64), 1, 0, 0, 1, 1, 0, nil, []diagnostics.DeterministicCheck{check}, service.set.Findings())
	if err != nil {
		t.Fatal(err)
	}
	return service, deterministic, verified
}

func renderFinalService(t *testing.T, service *fakeService) string {
	t.Helper()
	var output bytes.Buffer
	terminal, err := New(service, strings.NewReader(""), &output, Options{Scope: service.receipt.Scope(), Plain: true, Once: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := terminal.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	return output.String()
}

func TestRunRendersFinalOutcomesAndDistinctEvidence(t *testing.T) {
	for _, outcome := range []diagnostics.FinalOutcome{diagnostics.FinalOutcomeCompleted, diagnostics.FinalOutcomeFailed, diagnostics.FinalOutcomeCanceled, diagnostics.FinalOutcomeAbstained, diagnostics.FinalOutcomeInconclusive} {
		t.Run(string(outcome), func(t *testing.T) {
			service, deterministic, verified := tuiFinalEvidence(t)
			final, err := diagnostics.NewFinalReviewSet(service.receipt.Scope(), deterministic.SnapshotIdentity(), deterministic.HeadRevision(), outcome, deterministic, verified)
			if err != nil {
				t.Fatal(err)
			}
			service.set = final
			rendered := renderFinalService(t, service)
			for _, want := range []string{"Final review outcome: " + string(outcome), "Deterministic observations (not independently verified)", "1 deterministic observation(s)", "observed.go:3", "Verified findings", "1 verified finding(s)", "src/main.go:7", "does not approve"} {
				if !strings.Contains(rendered, want) {
					t.Errorf("missing %q in:\n%s", want, rendered)
				}
			}
		})
	}
}

func TestRunRendersMissingFinalEvidenceAsUnknown(t *testing.T) {
	for _, outcome := range []diagnostics.FinalOutcome{diagnostics.FinalOutcomeFailed, diagnostics.FinalOutcomeCanceled, diagnostics.FinalOutcomeAbstained, diagnostics.FinalOutcomeInconclusive} {
		for _, hasDeterministic := range []bool{false, true} {
			name := string(outcome)
			if hasDeterministic {
				name += "/deterministic-only"
			}
			t.Run(name, func(t *testing.T) {
				service, deterministic, _ := tuiFinalEvidence(t)
				snapshot, head := deterministic.SnapshotIdentity(), deterministic.HeadRevision()
				if !hasDeterministic {
					deterministic = diagnostics.Set{}
					snapshot, head = "", ""
				}
				final, err := diagnostics.NewFinalReviewSet(service.receipt.Scope(), snapshot, head, outcome, deterministic, diagnostics.Set{})
				if err != nil {
					t.Fatal(err)
				}
				service.set = final
				rendered := renderFinalService(t, service)
				if !strings.Contains(rendered, "Final review outcome: "+string(outcome)) || !strings.Contains(rendered, "Verified findings: unknown (evidence unavailable).") {
					t.Fatal(rendered)
				}
				if !hasDeterministic && !strings.Contains(rendered, "Deterministic observations: unknown (evidence unavailable).") {
					t.Fatal(rendered)
				}
				for _, misleading := range []string{"0 verified finding(s)", "0 candidate(s)", "Cleared gate:"} {
					if strings.Contains(rendered, misleading) {
						t.Fatalf("missing evidence reported as %q:\n%s", misleading, rendered)
					}
				}
			})
		}
	}
}

func TestRunDistinguishesObservedZeroFromMissingFinalEvidence(t *testing.T) {
	service, scope := tuiFixture(t)
	source, err := analysishandler.NewDeterministicCheck(strings.Repeat("7", 64), analysishandler.CheckPassed, 1, 1, 1, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	check, err := diagnostics.NewDeterministicCheck(source.Identity(), strings.Repeat("8", 64), strings.Repeat("7", 64), diagnostics.CheckPassed, 1, 1, 1, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	deterministic, err := diagnostics.NewSetWithDeterministicObservations(scope, service.set.SnapshotIdentity(), service.set.HeadRevision(), strings.Repeat("8", 64), []diagnostics.DeterministicCheck{check}, nil)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := diagnostics.NewSetWithDeterministicChecks(scope, service.set.SnapshotIdentity(), service.set.HeadRevision(), service.set.VerifiedSetIdentity(), strings.Repeat("f", 64), 0, 0, 0, 1, 1, 0, nil, []diagnostics.DeterministicCheck{check}, nil)
	if err != nil {
		t.Fatal(err)
	}
	service.set, err = diagnostics.NewFinalReviewSet(scope, deterministic.SnapshotIdentity(), deterministic.HeadRevision(), diagnostics.FinalOutcomeCompleted, deterministic, verified)
	if err != nil {
		t.Fatal(err)
	}
	rendered := renderFinalService(t, service)
	if !strings.Contains(rendered, "0 deterministic observation(s)") || !strings.Contains(rendered, "0 verified finding(s)") || !strings.Contains(rendered, "does not approve the change") || strings.Contains(rendered, "unknown (evidence unavailable)") {
		t.Fatal(rendered)
	}
}
