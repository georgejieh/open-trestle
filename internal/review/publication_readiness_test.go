package review

import (
	"errors"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/gateway"
)

func verifiedSetFixture(t *testing.T, outcome string, level gateway.RouteIndependenceLevel) (IndependentVerificationReceipt, VerifiedFindingSet) {
	t.Helper()
	generationContext, candidates, candidateOutput, verificationContext, verification, verificationOutput, independence := independentVerificationFixtureAtLevel(t, outcome, level)
	receipt, err := NewIndependentVerificationReceipt(IndependentVerificationArtifacts{
		GenerationContext: generationContext, Candidates: candidates, CandidateOutput: candidateOutput,
		VerificationContext: verificationContext, Verification: verification,
		VerificationOutput: verificationOutput, RouteIndependence: independence,
	})
	if err != nil {
		t.Fatal(err)
	}
	set, err := PromoteVerifiedCandidates(receipt, candidates, verification)
	if err != nil {
		t.Fatal(err)
	}
	return receipt, set
}

func TestEvaluatePublicationReadinessSelectsBoundedAdvisoryFindings(t *testing.T) {
	receipt, set := verifiedSetFixture(t, "verified", gateway.RouteIndependenceDistinctProvider)
	policy, err := NewPublicationPolicy(SeverityMedium, 10, gateway.RouteIndependenceDistinctProvider, true)
	if err != nil {
		t.Fatal(err)
	}
	readiness, err := EvaluatePublicationReadiness(policy, receipt, set)
	if err != nil {
		t.Fatal(err)
	}
	if readiness.Identity() == "" || readiness.Status() != PublicationAdvisoryReady || readiness.PolicyIdentity() != policy.Identity() || readiness.VerificationReceiptIdentity() != receipt.Identity() || readiness.VerifiedFindingSetIdentity() != set.Identity() || len(readiness.InlineFindings()) != 1 || readiness.SummaryOnlyCount() != 0 || readiness.BelowThresholdCount() != 0 || readiness.Validate() != nil {
		t.Fatalf("publication readiness did not round trip: %#v", readiness)
	}
	findings := readiness.InlineFindings()
	findings[0] = VerifiedFinding{}
	if len(readiness.InlineFindings()) != 1 {
		t.Fatal("readiness exposed mutable findings")
	}
	if readiness.AuthorizesPublication() {
		t.Fatal("readiness incorrectly authorized an external write")
	}
}

func TestEvaluatePublicationReadinessPreservesNoFindingAndInconclusiveStates(t *testing.T) {
	policy, _ := NewPublicationPolicy(SeverityLow, 10, gateway.RouteIndependenceDistinctRoute, true)
	rejectedReceipt, rejectedSet := verifiedSetFixture(t, "rejected", gateway.RouteIndependenceDistinctRoute)
	rejected, err := EvaluatePublicationReadiness(policy, rejectedReceipt, rejectedSet)
	if err != nil || rejected.Status() != PublicationNoVerifiedFindings || rejected.RejectedCount() != 1 || rejected.Validate() != nil {
		t.Fatalf("rejected readiness = (%#v, %v)", rejected, err)
	}
	inconclusiveReceipt, inconclusiveSet := verifiedSetFixture(t, "inconclusive", gateway.RouteIndependenceDistinctRoute)
	inconclusive, err := EvaluatePublicationReadiness(policy, inconclusiveReceipt, inconclusiveSet)
	if err != nil || inconclusive.Status() != PublicationBlockedInconclusive || inconclusive.InconclusiveCount() != 1 || inconclusive.Validate() != nil {
		t.Fatalf("inconclusive readiness = (%#v, %v)", inconclusive, err)
	}
	permissive, _ := NewPublicationPolicy(SeverityLow, 10, gateway.RouteIndependenceDistinctRoute, false)
	visible, _ := EvaluatePublicationReadiness(permissive, inconclusiveReceipt, inconclusiveSet)
	if visible.Status() != PublicationNoVerifiedFindings || visible.InconclusiveCount() != 1 {
		t.Fatalf("visible inconclusive readiness = %#v", visible)
	}
}

func TestEvaluatePublicationReadinessBlocksWeakIndependenceAndThreshold(t *testing.T) {
	receipt, set := verifiedSetFixture(t, "verified", gateway.RouteIndependenceDistinctRoute)
	strict, _ := NewPublicationPolicy(SeverityLow, 10, gateway.RouteIndependenceDistinctProvider, true)
	blocked, err := EvaluatePublicationReadiness(strict, receipt, set)
	if err != nil || blocked.Status() != PublicationBlockedIndependence || len(blocked.InlineFindings()) != 0 || blocked.Validate() != nil {
		t.Fatalf("independence block = (%#v, %v)", blocked, err)
	}
	threshold, _ := NewPublicationPolicy(SeverityCritical, 10, gateway.RouteIndependenceDistinctRoute, true)
	below, err := EvaluatePublicationReadiness(threshold, receipt, set)
	if err != nil || below.Status() != PublicationBelowThreshold || below.BelowThresholdCount() != 1 || below.Validate() != nil {
		t.Fatalf("threshold result = (%#v, %v)", below, err)
	}
}

func TestPublicationPolicyAndReadinessRejectForgery(t *testing.T) {
	if policy, err := NewPublicationPolicy(Severity("unknown"), 1, gateway.RouteIndependenceDistinctRoute, true); !errors.Is(err, ErrInvalidPublicationSeverity) || policy.Identity() != "" {
		t.Fatalf("invalid policy = (%#v, %v)", policy, err)
	}
	policy, _ := NewPublicationPolicy(SeverityLow, maxPublicationInlineFindings+1, gateway.RouteIndependenceDistinctRoute, true)
	if policy.Identity() != "" {
		t.Fatal("excessive policy accepted")
	}
	receipt, set := verifiedSetFixture(t, "verified", gateway.RouteIndependenceDistinctProvider)
	policy, _ = NewPublicationPolicy(SeverityLow, 1, gateway.RouteIndependenceDistinctProvider, true)
	readiness, _ := EvaluatePublicationReadiness(policy, receipt, set)
	forged := readiness
	forged.identity = strings.Repeat("f", 64)
	if !errors.Is(forged.Validate(), ErrInvalidPublicationReadinessIdentity) {
		t.Fatal("forged readiness accepted")
	}
}

func TestPublicationReadinessStatusRoundTrips(t *testing.T) {
	for _, token := range []string{"advisory_ready", "no_verified_findings", "below_threshold", "blocked_inconclusive", "blocked_independence"} {
		status, err := ParsePublicationReadinessStatus(token)
		if err != nil || status.String() != token || status.Validate() != nil {
			t.Fatalf("status %q = (%v, %v)", token, status, err)
		}
	}
}
