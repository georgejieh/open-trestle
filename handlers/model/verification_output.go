package model

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
)

const maximumVerificationResultBytes = 6 << 20

// VerificationResult is one independently checked, promotion-ready review result.
type VerificationResult struct {
	identity, artifactIdentity, generationArtifactIdentity string
	verificationContext                                    review.VerificationRequestContext
	verification                                           review.VerificationBatch
	routeExecution                                         gateway.RouteExecutionRecord
	routeIndependence                                      gateway.RouteIndependenceReceipt
	independentReceipt                                     review.IndependentVerificationReceipt
	verifiedFindings                                       review.VerifiedFindingSet
}

func (r VerificationResult) Identity() string                   { return r.identity }
func (r VerificationResult) ArtifactIdentity() string           { return r.artifactIdentity }
func (r VerificationResult) GenerationArtifactIdentity() string { return r.generationArtifactIdentity }
func (r VerificationResult) VerificationContext() review.VerificationRequestContext {
	return r.verificationContext
}
func (r VerificationResult) Verification() review.VerificationBatch       { return r.verification }
func (r VerificationResult) RouteExecution() gateway.RouteExecutionRecord { return r.routeExecution }
func (r VerificationResult) RouteIndependence() gateway.RouteIndependenceReceipt {
	return r.routeIndependence
}
func (r VerificationResult) IndependentReceipt() review.IndependentVerificationReceipt {
	return r.independentReceipt
}
func (r VerificationResult) VerifiedFindings() review.VerifiedFindingSet { return r.verifiedFindings }
func (r VerificationResult) String() string                              { return "model verification result" }
func (r VerificationResult) GoString() string                            { return "model.VerificationResult{<redacted>}" }
func (r VerificationResult) Format(state fmt.State, verb rune) {
	writeModelRedacted(state, verb, "model verification result", "model.VerificationResult{<redacted>}")
}

func newVerificationResult(
	generationArtifactIdentity string,
	context review.VerificationRequestContext,
	verification review.VerificationBatch,
	routeExecution gateway.RouteExecutionRecord,
	independence gateway.RouteIndependenceReceipt,
	receipt review.IndependentVerificationReceipt,
	findings review.VerifiedFindingSet,
) (VerificationResult, error) {
	result := VerificationResult{
		generationArtifactIdentity: generationArtifactIdentity, verificationContext: context,
		verification: verification, routeExecution: routeExecution, routeIndependence: independence,
		independentReceipt: receipt, verifiedFindings: findings,
	}
	result.identity = deriveVerificationResultIdentity(result)
	if err := result.Validate(); err != nil {
		return VerificationResult{}, err
	}
	return result, nil
}

// Validate verifies complete generation, route, verdict, independence, and promotion lineage.
func (r VerificationResult) Validate() error {
	if !validDigest(r.generationArtifactIdentity) || r.verificationContext.Validate() != nil ||
		r.verification.Validate() != nil || r.routeExecution.Validate() != nil ||
		r.routeIndependence.Validate() != nil || r.independentReceipt.Validate() != nil ||
		r.verifiedFindings.Validate() != nil {
		return ErrInvalidVerificationResult
	}
	output := r.routeExecution.Output()
	if output.Kind() != gateway.RouteOutputVerificationBatch ||
		output.ContextIdentity() != r.verificationContext.Identity() ||
		output.ArtifactIdentity() != r.verification.Identity() ||
		output.ResponseIdentity() != r.verification.ResponseIdentity() ||
		r.routeIndependence.SecondAuthorizationIdentity() != r.routeExecution.Authorization().Identity() ||
		r.routeIndependence.SecondOutcomeIdentity() != r.routeExecution.Outcome().Identity() ||
		r.independentReceipt.VerificationBatchIdentity() != r.verification.Identity() ||
		r.independentReceipt.RouteIndependenceIdentity() != r.routeIndependence.Identity() ||
		r.verifiedFindings.IndependentReceiptIdentity() != r.independentReceipt.Identity() ||
		r.identity != deriveVerificationResultIdentity(r) {
		return ErrInvalidVerificationResult
	}
	return nil
}

type verificationResultWire struct {
	Contract                    string          `json:"contract"`
	SchemaVersion               int             `json:"schema_version"`
	Identity                    string          `json:"identity"`
	GenerationArtifactIdentity  string          `json:"generation_artifact_identity"`
	VerificationContextIdentity string          `json:"verification_context_identity"`
	VerificationBatchIdentity   string          `json:"verification_batch_identity"`
	RouteExecutionIdentity      string          `json:"route_execution_identity"`
	IndependenceLevel           string          `json:"independence_level"`
	RouteIndependenceIdentity   string          `json:"route_independence_identity"`
	IndependentReceiptIdentity  string          `json:"independent_receipt_identity"`
	VerifiedFindingSetIdentity  string          `json:"verified_finding_set_identity"`
	VerificationBatch           json.RawMessage `json:"verification_batch"`
	RouteExecution              json.RawMessage `json:"route_execution"`
	VerifiedFindingSet          json.RawMessage `json:"verified_finding_set"`
}

func encodeVerificationResult(result VerificationResult) ([]byte, error) {
	if err := result.Validate(); err != nil {
		return nil, err
	}
	verification, err := review.EncodeVerificationBatch(result.verification)
	if err != nil {
		return nil, err
	}
	routeExecution, err := gateway.EncodeRouteExecutionRecord(result.routeExecution)
	if err != nil {
		return nil, err
	}
	findings, err := review.EncodeVerifiedFindingSet(result.verifiedFindings)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(verificationResultWire{
		Contract: "open-trestle/model-verification-result", SchemaVersion: 1,
		Identity: result.Identity(), GenerationArtifactIdentity: result.generationArtifactIdentity,
		VerificationContextIdentity: result.verificationContext.Identity(),
		VerificationBatchIdentity:   result.verification.Identity(), RouteExecutionIdentity: result.routeExecution.Identity(),
		IndependenceLevel:          result.routeIndependence.Level().String(),
		RouteIndependenceIdentity:  result.routeIndependence.Identity(),
		IndependentReceiptIdentity: result.independentReceipt.Identity(),
		VerifiedFindingSetIdentity: result.verifiedFindings.Identity(),
		VerificationBatch:          verification, RouteExecution: routeExecution, VerifiedFindingSet: findings,
	})
	if err != nil || len(encoded) == 0 || len(encoded) > maximumVerificationResultBytes {
		return nil, ErrInvalidVerificationResult
	}
	return encoded, nil
}

// VerificationResultReferences returns the exact generation artifact needed for full validation.
func VerificationResultReferences(value artifact.Artifact) (string, error) {
	if value.Validate() != nil || value.Kind() != artifact.KindVerifiedFindingSet || value.MediaType() != "application/json" || value.Origin() != artifact.OriginIndependentVerifier {
		return "", ErrInvalidVerificationResult
	}
	payload := value.Payload()
	if len(payload) == 0 || len(payload) > maximumVerificationResultBytes {
		return "", ErrInvalidVerificationResult
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var wire verificationResultWire
	if decoder.Decode(&wire) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return "", ErrInvalidVerificationResult
	}
	canonical, _ := json.Marshal(wire)
	if !bytes.Equal(canonical, payload) || wire.Contract != "open-trestle/model-verification-result" || wire.SchemaVersion != 1 || !validDigest(wire.GenerationArtifactIdentity) {
		return "", ErrInvalidVerificationResult
	}
	return wire.GenerationArtifactIdentity, nil
}

// ParseVerificationResultArtifact reconstructs and verifies complete independent-review lineage.
func ParseVerificationResultArtifact(
	value artifact.Artifact,
	generationArtifact artifact.Artifact,
	generationInputArtifact artifact.Artifact,
	generationContextArtifact artifact.Artifact,
) (VerificationResult, error) {
	if value.Validate() != nil || generationArtifact.Validate() != nil ||
		value.Kind() != artifact.KindVerifiedFindingSet || value.MediaType() != "application/json" ||
		value.Origin() != artifact.OriginIndependentVerifier || value.Scope().Identity() != generationArtifact.Scope().Identity() ||
		value.Classification() != generationArtifact.Classification() || value.Protection() != generationArtifact.Protection() ||
		!hasProvenance(value.Provenance(), generationArtifact.Identity()) {
		return VerificationResult{}, ErrInvalidVerificationResult
	}
	generation, err := ParseGenerationResultArtifact(generationArtifact, generationInputArtifact, generationContextArtifact)
	if err != nil {
		return VerificationResult{}, ErrInvalidVerificationResult
	}
	input, err := ParseGenerationInput(generationInputArtifact.Payload())
	if err != nil {
		return VerificationResult{}, ErrInvalidVerificationResult
	}
	verificationContext, err := review.ReconstructRecordedVerificationRequestContext(
		generationContextArtifact.Payload(), generation.ContextIdentity(), value.Scope().Identity(), input.MemoryScopeIdentity(), input.MemoryIdentity(),
		input.Snapshot(), input.EvidenceItems(), generation.Candidates(),
	)
	if err != nil {
		return VerificationResult{}, ErrInvalidVerificationResult
	}
	verificationRequest, err := provider.NewRequest(provider.CapabilityReviewV1, "application/json", verificationContext.Payload())
	if err != nil {
		return VerificationResult{}, ErrInvalidVerificationResult
	}
	payload := value.Payload()
	if len(payload) == 0 || len(payload) > maximumVerificationResultBytes {
		return VerificationResult{}, ErrInvalidVerificationResult
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var wire verificationResultWire
	if err := decoder.Decode(&wire); err != nil {
		return VerificationResult{}, ErrInvalidVerificationResult
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return VerificationResult{}, ErrInvalidVerificationResult
	}
	canonical, err := json.Marshal(wire)
	if err != nil || !bytes.Equal(canonical, payload) || wire.Contract != "open-trestle/model-verification-result" || wire.SchemaVersion != 1 ||
		wire.GenerationArtifactIdentity != generationArtifact.Identity() || wire.VerificationContextIdentity != verificationContext.Identity() {
		return VerificationResult{}, ErrInvalidVerificationResult
	}
	verification, err := review.ParseEncodedVerificationBatch(wire.VerificationBatch)
	if err != nil || verification.Identity() != wire.VerificationBatchIdentity || verification.CandidateBatchIdentity() != generation.Candidates().Identity() {
		return VerificationResult{}, ErrInvalidVerificationResult
	}
	routeExecution, err := gateway.ParseRouteExecutionRecord(wire.RouteExecution)
	if err != nil || routeExecution.Identity() != wire.RouteExecutionIdentity || routeExecution.Authorization().RequestIdentity() != verificationRequest.Identity() {
		return VerificationResult{}, ErrInvalidVerificationResult
	}
	level, err := gateway.ParseRouteIndependenceLevel(wire.IndependenceLevel)
	if err != nil {
		return VerificationResult{}, ErrInvalidVerificationResult
	}
	policy, err := gateway.NewRouteIndependencePolicy(level)
	if err != nil {
		return VerificationResult{}, ErrInvalidVerificationResult
	}
	independence, err := gateway.VerifyIndependentRouteAttempts(policy, generation.RouteExecution().Authorization(), generation.RouteExecution().Outcome(), routeExecution.Authorization(), routeExecution.Outcome())
	if err != nil || independence.Identity() != wire.RouteIndependenceIdentity {
		return VerificationResult{}, ErrInvalidVerificationResult
	}
	independent, err := review.NewIndependentVerificationReceiptFromRecords(review.IndependentVerificationRecords{
		ReviewScopeIdentity: value.Scope().Identity(), SnapshotIdentity: generation.Candidates().SnapshotIdentity(),
		GenerationContextIdentity: generation.ContextIdentity(), VerificationContextIdentity: verificationContext.Identity(),
		GenerationRequestIdentity: generation.RouteExecution().Authorization().RequestIdentity(), VerificationRequestIdentity: verificationRequest.Identity(),
		Candidates: generation.Candidates(), CandidateOutput: generation.RouteExecution().Output(), Verification: verification,
		VerificationOutput: routeExecution.Output(), RouteIndependence: independence,
	})
	if err != nil || independent.Identity() != wire.IndependentReceiptIdentity {
		return VerificationResult{}, ErrInvalidVerificationResult
	}
	findings, err := review.ParseEncodedVerifiedFindingSet(wire.VerifiedFindingSet)
	if err != nil || findings.Identity() != wire.VerifiedFindingSetIdentity {
		return VerificationResult{}, ErrInvalidVerificationResult
	}
	expectedFindings, err := review.PromoteVerifiedCandidates(independent, generation.Candidates(), verification)
	if err != nil || expectedFindings.Identity() != findings.Identity() {
		return VerificationResult{}, ErrInvalidVerificationResult
	}
	result, err := newVerificationResult(generationArtifact.Identity(), verificationContext, verification, routeExecution, independence, independent, findings)
	if err != nil || result.Identity() != wire.Identity {
		return VerificationResult{}, ErrInvalidVerificationResult
	}
	result.artifactIdentity = value.Identity()
	reencoded, err := encodeVerificationResult(result)
	if err != nil || !bytes.Equal(reencoded, payload) {
		return VerificationResult{}, ErrInvalidVerificationResult
	}
	for _, identity := range []string{
		generationInputArtifact.Identity(), generationContextArtifact.Identity(), verification.Identity(),
		routeExecution.Identity(), routeExecution.Authorization().Identity(), routeExecution.Outcome().Identity(),
		routeExecution.Reconciliation().Identity(), routeExecution.Output().Identity(), independence.Identity(),
		independent.Identity(), findings.Identity(),
	} {
		if !hasProvenance(value.Provenance(), identity) {
			return VerificationResult{}, ErrInvalidVerificationResult
		}
	}
	return result, nil
}

func deriveVerificationResultIdentity(result VerificationResult) string {
	encoded, err := json.Marshal(struct {
		Contract            string `json:"contract"`
		SchemaVersion       int    `json:"schema_version"`
		GenerationArtifact  string `json:"generation_artifact"`
		VerificationContext string `json:"verification_context"`
		Verification        string `json:"verification"`
		RouteExecution      string `json:"route_execution"`
		RouteIndependence   string `json:"route_independence"`
		IndependentReceipt  string `json:"independent_receipt"`
		VerifiedFindings    string `json:"verified_findings"`
	}{"open-trestle/model-verification-result", 1, result.generationArtifactIdentity, result.verificationContext.Identity(), result.verification.Identity(), result.routeExecution.Identity(), result.routeIndependence.Identity(), result.independentReceipt.Identity(), result.verifiedFindings.Identity()})
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
