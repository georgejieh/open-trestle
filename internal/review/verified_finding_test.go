package review

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/policy"
	"github.com/georgejieh/open-trestle/internal/provider"
)

type reviewRouteRegistryReader struct{ record provider.RouteRegistryRecord }

func (r reviewRouteRegistryReader) LookupRouteRegistryRecord(_ context.Context, _ string) (provider.RouteRegistryRecord, error) {
	return r.record, nil
}

type reviewRouteManifestReader struct{ content []byte }

func (r reviewRouteManifestReader) OpenRouteEvidenceManifest(_ context.Context, _ string) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader(string(r.content))), nil
}

func reviewRouteAuthorization(t *testing.T, scope audit.ReviewScope, request provider.Request, providerID, modelID string) gateway.RouteAttemptAuthorization {
	t.Helper()
	reference, err := provider.NewRouteReference(provider.ProviderZoneLocal, providerID, "fake", providerID+"-connection", modelID, "v1")
	if err != nil {
		t.Fatal(err)
	}
	capabilities, _ := provider.NewModelCapabilities(128_000, 16_000, []provider.ModelFeature{provider.ModelFeatureStructuredOutput})
	declaration, _ := provider.NewRouteCapabilityDeclaration(reference, capabilities)
	pricing, _ := provider.NewRoutePricing(0, 0)
	candidate, _ := provider.NewRouteCandidateDeclaration(declaration, provider.ContentLoggingDisabled, pricing, provider.RouteQualityTier4)
	manifest := []byte("route evidence")
	digest := sha256.Sum256(manifest)
	record, _ := provider.NewRouteRegistryRecord(1, candidate, provider.RouteRegistryApproved, hex.EncodeToString(digest[:]))
	resolved, err := gateway.ResolveRouteRegistryRecord(context.Background(), record.Identity(), reviewRouteRegistryReader{record}, reviewRouteManifestReader{manifest})
	if err != nil {
		t.Fatal(err)
	}
	operational, _ := provider.NewRouteOperationalState(record.Identity(), 1, provider.RouteHealthHealthy, provider.RouteQuotaAvailable)
	observed, _ := gateway.NewObservedRouteCandidate(resolved, operational)
	requirements, _ := provider.NewModelRequirements(1, 1, []provider.ModelFeature{provider.ModelFeatureStructuredOutput})
	zones, _ := policy.NewAllowedProviderZones(provider.ProviderZoneLocal)
	constraints, _ := policy.NewProviderDataConstraints(policy.DataClassificationConfidential, zones, false)
	routing, _ := gateway.NewReviewRoutingInput(scope, request, requirements, constraints)
	budget, _ := provider.NewModelCostBudget(1, 16_000, 0)
	eligibility, err := gateway.FilterEligibleRoutes(routing, budget, 1, []gateway.ObservedRouteCandidate{observed})
	if err != nil {
		t.Fatal(err)
	}
	rankingPolicy, _ := gateway.NewRouteRankingPolicy(nil)
	performance, _ := provider.NewUnknownRoutePerformanceObservation(record.Identity(), 1)
	ranking, _ := gateway.RankEligibleRoutes(eligibility, rankingPolicy, 1, []provider.RoutePerformanceObservation{performance})
	selection, _ := gateway.NewRouteSelectionReceipt(eligibility, ranking)
	authorization, err := gateway.NewInitialRouteAttemptAuthorization(request, selection, ranking)
	if err != nil {
		t.Fatal(err)
	}
	return authorization
}

func independentVerificationFixture(t *testing.T, outcome string) (ContextPacket, CandidateBatch, gateway.RouteOutputReceipt, VerificationContextPacket, VerificationBatch, gateway.RouteOutputReceipt, gateway.RouteIndependenceReceipt) {
	return independentVerificationFixtureAtLevel(t, outcome, gateway.RouteIndependenceDistinctProvider)
}

func independentVerificationFixtureAtLevel(t *testing.T, outcome string, level gateway.RouteIndependenceLevel) (ContextPacket, CandidateBatch, gateway.RouteOutputReceipt, VerificationContextPacket, VerificationBatch, gateway.RouteOutputReceipt, gateway.RouteIndependenceReceipt) {
	t.Helper()
	generationContext, candidates := verificationContextFixture(t)
	scope, _ := audit.NewReviewScope("tenant", "repository", "review-run")
	generationRequest, _ := generationContext.ProviderRequest()
	generationAuthorization := reviewRouteAuthorization(t, scope, generationRequest, "generator", "model-a")
	generationOutcome, _ := gateway.NewSuccessfulRouteAttemptOutcome(generationAuthorization, candidates.ResponseIdentity(), provider.NewUnknownRouteTokenUsage(), 1)
	candidateOutput, _ := gateway.NewSuccessfulRouteOutputReceipt(gateway.RouteOutputCandidateBatch, generationContext.Identity(), candidates.Identity(), generationRequest, generationAuthorization, generationOutcome)
	verificationContext, _ := NewVerificationContextPacket(generationContext, candidates)
	candidateID := candidates.Findings()[0].Identity()
	severity, evidenceIDs := "none", `[]`
	if outcome == "verified" {
		severity, evidenceIDs = "high", `["source-1"]`
	}
	document := `{"schema_version":1,"verdicts":[{"candidate_id":"` + candidateID + `","outcome":"` + outcome + `","severity":"` + severity + `","rationale":"Independent review completed.","evidence_ids":` + evidenceIDs + `}]}`
	part, _ := provider.NewResponsePart(provider.ResponsePartStructuredData, "application/json", []byte(document))
	response, _ := provider.NewResponse(provider.CapabilityReviewV1, provider.ResponseFinishStop, []provider.ResponsePart{part}, provider.NewUnknownRouteTokenUsage())
	verification, err := ParseVerificationBatch(response, candidates, verificationContext.EvidenceItems())
	if err != nil {
		t.Fatal(err)
	}
	verificationRequest, _ := verificationContext.ProviderRequest()
	verificationAuthorization := reviewRouteAuthorization(t, scope, verificationRequest, "verifier", "model-b")
	verificationOutcome, _ := gateway.NewSuccessfulRouteAttemptOutcome(verificationAuthorization, verification.ResponseIdentity(), provider.NewUnknownRouteTokenUsage(), 1)
	verificationOutput, _ := gateway.NewSuccessfulRouteOutputReceipt(gateway.RouteOutputVerificationBatch, verificationContext.Identity(), verification.Identity(), verificationRequest, verificationAuthorization, verificationOutcome)
	independencePolicy, _ := gateway.NewRouteIndependencePolicy(level)
	independence, err := gateway.VerifyIndependentRouteAttempts(independencePolicy, generationAuthorization, generationOutcome, verificationAuthorization, verificationOutcome)
	if err != nil {
		t.Fatal(err)
	}
	return generationContext, candidates, candidateOutput, verificationContext, verification, verificationOutput, independence
}

func TestNewIndependentVerificationReceiptAndPromoteVerifiedCandidates(t *testing.T) {
	generationContext, candidates, candidateOutput, verificationContext, verification, verificationOutput, independence := independentVerificationFixture(t, "verified")
	receipt, err := NewIndependentVerificationReceipt(IndependentVerificationArtifacts{
		GenerationContext: generationContext, Candidates: candidates, CandidateOutput: candidateOutput,
		VerificationContext: verificationContext, Verification: verification,
		VerificationOutput: verificationOutput, RouteIndependence: independence,
	})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Identity() == "" || receipt.ReviewScopeIdentity() != generationContext.ReviewScopeIdentity() || receipt.CandidateBatchIdentity() != candidates.Identity() || receipt.VerificationBatchIdentity() != verification.Identity() || receipt.RouteIndependenceIdentity() != independence.Identity() || receipt.VerifiedCount() != 1 || receipt.RejectedCount() != 0 || receipt.InconclusiveCount() != 0 || receipt.Validate() != nil {
		t.Fatalf("independent receipt did not round trip: %#v", receipt)
	}
	generationRequest, _ := generationContext.ProviderRequest()
	verificationRequest, _ := verificationContext.ProviderRequest()
	fromRecords, err := NewIndependentVerificationReceiptFromRecords(IndependentVerificationRecords{
		ReviewScopeIdentity: generationContext.ReviewScopeIdentity(), SnapshotIdentity: candidates.SnapshotIdentity(),
		GenerationContextIdentity: generationContext.Identity(), VerificationContextIdentity: verificationContext.Identity(),
		GenerationRequestIdentity: generationRequest.Identity(), VerificationRequestIdentity: verificationRequest.Identity(),
		Candidates: candidates, CandidateOutput: candidateOutput, Verification: verification,
		VerificationOutput: verificationOutput, RouteIndependence: independence,
	})
	if err != nil || fromRecords.Identity() != receipt.Identity() {
		t.Fatalf("record receipt=(%#v,%v), want %s", fromRecords, err, receipt.Identity())
	}
	set, err := PromoteVerifiedCandidates(receipt, candidates, verification)
	if err != nil {
		t.Fatal(err)
	}
	findings := set.Findings()
	if set.Identity() == "" || len(findings) != 1 || set.RejectedCount() != 0 || set.InconclusiveCount() != 0 || set.Validate() != nil {
		t.Fatalf("verified set did not round trip: %#v", set)
	}
	finding := findings[0]
	if finding.Identity() == "" || finding.Fingerprint() == "" || finding.CandidateIdentity() != candidates.Findings()[0].Identity() || finding.VerificationIdentity() != verification.Results()[0].Identity() || finding.Severity() != SeverityHigh || finding.SourceRange() != candidates.Findings()[0].SourceRange() || len(finding.EvidenceIDs()) != 1 || finding.Validate() != nil {
		t.Fatalf("verified finding did not round trip: %#v", finding)
	}
}

func TestPromoteVerifiedCandidatesKeepsRejectedAndInconclusiveVisible(t *testing.T) {
	for _, outcome := range []string{"rejected", "inconclusive"} {
		t.Run(outcome, func(t *testing.T) {
			generationContext, candidates, candidateOutput, verificationContext, verification, verificationOutput, independence := independentVerificationFixture(t, outcome)
			receipt, _ := NewIndependentVerificationReceipt(IndependentVerificationArtifacts{
				GenerationContext: generationContext, Candidates: candidates, CandidateOutput: candidateOutput,
				VerificationContext: verificationContext, Verification: verification,
				VerificationOutput: verificationOutput, RouteIndependence: independence,
			})
			set, err := PromoteVerifiedCandidates(receipt, candidates, verification)
			if err != nil || len(set.Findings()) != 0 || outcome == "rejected" && set.RejectedCount() != 1 || outcome == "inconclusive" && set.InconclusiveCount() != 1 || set.Validate() != nil {
				t.Fatalf("%s set = (%#v, %v)", outcome, set, err)
			}
		})
	}
}

func TestIndependentVerificationReceiptRejectsCrossWiredOutput(t *testing.T) {
	generationContext, candidates, candidateOutput, verificationContext, verification, verificationOutput, independence := independentVerificationFixture(t, "verified")
	if receipt, err := NewIndependentVerificationReceipt(IndependentVerificationArtifacts{
		GenerationContext: generationContext, Candidates: candidates, CandidateOutput: verificationOutput,
		VerificationContext: verificationContext, Verification: verification,
		VerificationOutput: candidateOutput, RouteIndependence: independence,
	}); !errors.Is(err, ErrIndependentVerificationOutputMismatch) || receipt.Identity() != "" {
		t.Fatalf("swapped outputs = (%#v, %v)", receipt, err)
	}
}
