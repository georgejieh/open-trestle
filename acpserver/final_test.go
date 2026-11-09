package acpserver

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/diagnostics"
)

func TestServerLabelsFinalOutcomesAndDistinctEvidence(t *testing.T) {
	for _, outcome := range []diagnostics.FinalOutcome{diagnostics.FinalOutcomeCompleted, diagnostics.FinalOutcomeFailed, diagnostics.FinalOutcomeCanceled, diagnostics.FinalOutcomeAbstained, diagnostics.FinalOutcomeInconclusive} {
		t.Run(string(outcome), func(t *testing.T) {
			scope, receipt, deterministic := acpV6Fixture(t, 1, 64)
			finding, err := diagnostics.NewFinding(strings.Repeat("a", 64), strings.Repeat("b", 64), "Verified issue", "Independent verification.", diagnostics.SeverityError, "verified.go", 4, 4, []string{strings.Repeat("c", 64)})
			if err != nil {
				t.Fatal(err)
			}
			verified, err := diagnostics.NewSetWithDeterministicChecks(scope, deterministic.SnapshotIdentity(), deterministic.HeadRevision(), strings.Repeat("e", 64), strings.Repeat("f", 64), 1, 0, 0, 1, 1, 0, nil, deterministic.DeterministicChecks(), []diagnostics.Finding{finding})
			if err != nil {
				t.Fatal(err)
			}
			final, err := diagnostics.NewFinalReviewSet(scope, deterministic.SnapshotIdentity(), deterministic.HeadRevision(), outcome, deterministic, verified)
			if err != nil {
				t.Fatal(err)
			}
			messages := promptMessages(t, &serviceStub{receipt: receipt, set: final}, scope)
			for _, want := range []string{"Final review diagnostics:", "Final review outcome: " + string(outcome), "Deterministic observations: 1 (not independently verified).", "Verified findings: 1.", "Debug output left in source", "Verified issue", final.Identity()} {
				if !bytes.Contains(messages[0], []byte(want)) {
					t.Errorf("missing %q in %s", want, messages[0])
				}
			}
			if bytes.Contains(messages[0], []byte("Verified diagnostics:")) {
				t.Fatalf("combined evidence mislabeled: %s", messages[0])
			}
		})
	}
}

func TestServerReportsMissingFinalEvidenceAsUnknown(t *testing.T) {
	for _, outcome := range []diagnostics.FinalOutcome{diagnostics.FinalOutcomeFailed, diagnostics.FinalOutcomeCanceled, diagnostics.FinalOutcomeAbstained, diagnostics.FinalOutcomeInconclusive} {
		t.Run(string(outcome), func(t *testing.T) {
			scope, receipt, _ := acpFixture(t)
			final, err := diagnostics.NewFinalReviewSet(scope, "", "", outcome, diagnostics.Set{}, diagnostics.Set{})
			if err != nil {
				t.Fatal(err)
			}
			messages := promptMessages(t, &serviceStub{receipt: receipt, set: final}, scope)
			for _, want := range []string{"Final review outcome: " + string(outcome), "Deterministic observations: unknown (evidence unavailable).", "Verified findings: unknown (evidence unavailable)."} {
				if !bytes.Contains(messages[0], []byte(want)) {
					t.Errorf("missing %q in %s", want, messages[0])
				}
			}
			for _, misleading := range []string{"Verified diagnostics:", "Verified findings: 0.", "Deterministic observations: 0.", "Cleared gate:"} {
				if bytes.Contains(messages[0], []byte(misleading)) {
					t.Fatalf("missing evidence reported as %q: %s", misleading, messages[0])
				}
			}
		})
	}
}

func TestServerRetainsFinalOutcomeWhenEvidenceExceedsFrameBound(t *testing.T) {
	scope, receipt, deterministic := acpV6Fixture(t, 37, 4096)
	final, err := diagnostics.NewFinalReviewSet(scope, deterministic.SnapshotIdentity(), deterministic.HeadRevision(), diagnostics.FinalOutcomeFailed, deterministic, diagnostics.Set{})
	if err != nil {
		t.Fatal(err)
	}
	messages := promptMessages(t, &serviceStub{receipt: receipt, set: final}, scope)
	for _, want := range []string{"Final review outcome: failed", "Deterministic observations: 37 (not independently verified).", "Verified findings: unknown (evidence unavailable).", "Final review diagnostics omitted: ACP message size limit."} {
		if !bytes.Contains(messages[0], []byte(want)) {
			t.Errorf("missing %q in %s", want, messages[0][:min(len(messages[0]), 2048)])
		}
	}
	for _, message := range messages {
		if len(message)+1 > maxACPMessageBytes {
			t.Fatalf("ACP frame bytes=%d", len(message)+1)
		}
		if bytes.Contains(message, []byte("Verified diagnostics")) {
			t.Fatal("final evidence mislabeled")
		}
	}
}

func TestServerDistinguishesObservedZeroFromMissingFinalEvidence(t *testing.T) {
	scope, receipt, verified := acpFixture(t)
	deterministic, err := diagnostics.NewSetWithDeterministicObservations(scope, verified.SnapshotIdentity(), verified.HeadRevision(), verified.DeterministicChecks()[0].AnalysisResultIdentity(), verified.DeterministicChecks(), nil)
	if err != nil {
		t.Fatal(err)
	}
	final, err := diagnostics.NewFinalReviewSet(scope, deterministic.SnapshotIdentity(), deterministic.HeadRevision(), diagnostics.FinalOutcomeCompleted, deterministic, verified)
	if err != nil {
		t.Fatal(err)
	}
	messages := promptMessages(t, &serviceStub{receipt: receipt, set: final}, scope)
	for _, want := range []string{"Deterministic observations: 0 (not independently verified).", "Verified findings: 0.", "does not approve the change"} {
		if !bytes.Contains(messages[0], []byte(want)) {
			t.Errorf("missing %q in %s", want, messages[0])
		}
	}
	if bytes.Contains(messages[0], []byte("unknown (evidence unavailable)")) {
		t.Fatalf("present evidence reported unknown: %s", messages[0])
	}
}

// A failed final result names its recorded context route refusal and hint.
func TestServerNamesFinalContextRefusal(t *testing.T) {
	scope, receipt, _ := acpFixture(t)
	failed, err := diagnostics.NewFinalReviewSet(scope, "", "", diagnostics.FinalOutcomeFailed, diagnostics.Set{}, diagnostics.Set{})
	if err != nil {
		t.Fatal(err)
	}
	for refusal, want := range map[diagnostics.ContextRefusal]string{
		{Reason: diagnostics.ContextRefusalRouteContextInsufficient, RequiredTokens: 14282, EstimatedInputTokens: 10186, MaxOutputTokens: 4096, DeclaredContextTokens: 4097}: "Context refusal: route_context_insufficient (the review request needs more context than the route declares).\nHint: the review needs up to 14282 tokens (a byte-based upper bound: 10186 input plus 4096 output) but the route declares max_context_tokens 4097; raise max_context_tokens on the route and the model server's context length to at least 14282 (docs/named-local-runtimes.md#context-length)",
		{Reason: diagnostics.ContextRefusalNoEligibleRoute}: "Context refusal: no_eligible_route (no configured route met the runtime policy for this request).",
	} {
		set, err := failed.WithContextRefusal(refusal)
		if err != nil {
			t.Fatal(err)
		}
		messages := promptMessages(t, &serviceStub{receipt: receipt, set: set}, scope)
		text := string(messages[0])
		if !strings.Contains(text, jsonEscaped(t, want)) {
			t.Errorf("missing %q in %s", want, messages[0])
		}
	}
	messages := promptMessages(t, &serviceStub{receipt: receipt, set: failed}, scope)
	if bytes.Contains(messages[0], []byte("Context refusal")) {
		t.Fatalf("refusal-free result named a refusal: %s", messages[0])
	}
}

// jsonEscaped renders text as it appears inside a JSON string.
func jsonEscaped(t *testing.T, text string) string {
	t.Helper()
	encoded, err := json.Marshal(text)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded[1 : len(encoded)-1])
}
