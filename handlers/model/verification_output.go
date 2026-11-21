package model

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
)

const maximumVerificationResultBytes = 6 << 20

type VerificationEgressArtifacts struct {
	SanitizedRequest artifact.Artifact
	Receipt          artifact.Artifact
}

type verificationEgressBinding struct {
	rawRequestIdentity               string
	sanitizedRequestIdentity         string
	sanitizedRequestArtifactIdentity string
	receiptArtifactIdentity          string
	receiptIdentity                  string
	sanitizerIdentity                string
	helperSHA256                     string
}

func newVerificationEgressBinding(raw, sanitized provider.Request, requestArtifact, receiptArtifact artifact.Artifact, receipt review.SanitizedEgressReceipt, sanitizerIdentity string, expected review.ScannerBinaryDigests) (verificationEgressBinding, error) {
	value := verificationEgressBinding{
		rawRequestIdentity: raw.Identity(), sanitizedRequestIdentity: sanitized.Identity(),
		sanitizedRequestArtifactIdentity: requestArtifact.Identity(), receiptArtifactIdentity: receiptArtifact.Identity(),
		receiptIdentity: receipt.Identity(), sanitizerIdentity: sanitizerIdentity,
		helperSHA256: expected.HelperSHA256,
	}
	if !value.valid() || receipt.RawRequestIdentity() != value.rawRequestIdentity || receipt.SanitizedRequestIdentity() != value.sanitizedRequestIdentity || receipt.Scanner().HelperSHA256 != expected.HelperSHA256 {
		return verificationEgressBinding{}, ErrInvalidVerificationResult
	}
	return value, nil
}

func (value verificationEgressBinding) empty() bool {
	return value == (verificationEgressBinding{})
}

func (value verificationEgressBinding) valid() bool {
	return validDigest(value.rawRequestIdentity) && validDigest(value.sanitizedRequestIdentity) && value.rawRequestIdentity != value.sanitizedRequestIdentity &&
		validDigest(value.sanitizedRequestArtifactIdentity) && validDigest(value.receiptArtifactIdentity) && validDigest(value.receiptIdentity) &&
		validDigest(value.sanitizerIdentity) && validDigest(value.helperSHA256)
}

// VerificationResult is one independently checked, promotion-ready review result.
type VerificationResult struct {
	identity, artifactIdentity, generationArtifactIdentity string
	verificationContext                                    review.VerificationRequestContext
	verification                                           review.VerificationBatch
	routeExecution                                         gateway.RouteExecutionRecord
	routeIndependence                                      gateway.RouteIndependenceReceipt
	independentReceipt                                     review.IndependentVerificationReceipt
	verifiedFindings                                       review.VerifiedFindingSet
	egress                                                 verificationEgressBinding
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

// SanitizedEgressReceiptArtifactIdentity names the stored secret-scan receipt of
// the verification request; it is empty when the request was not sanitized.
func (r VerificationResult) SanitizedEgressReceiptArtifactIdentity() string {
	return r.egress.receiptArtifactIdentity
}
func (r VerificationResult) String() string   { return "model verification result" }
func (r VerificationResult) GoString() string { return "model.VerificationResult{<redacted>}" }
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

func newSanitizedVerificationResult(
	generationArtifactIdentity string,
	context review.VerificationRequestContext,
	verification review.VerificationBatch,
	routeExecution gateway.RouteExecutionRecord,
	independence gateway.RouteIndependenceReceipt,
	receipt review.IndependentVerificationReceipt,
	findings review.VerifiedFindingSet,
	egress verificationEgressBinding,
) (VerificationResult, error) {
	result := VerificationResult{
		generationArtifactIdentity: generationArtifactIdentity, verificationContext: context,
		verification: verification, routeExecution: routeExecution, routeIndependence: independence,
		independentReceipt: receipt, verifiedFindings: findings, egress: egress,
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
	if !r.egress.empty() {
		rawRequest, rawRequestErr := r.verificationContext.ProviderRequest()
		if rawRequestErr != nil || !r.egress.valid() || r.egress.rawRequestIdentity != rawRequest.Identity() || r.egress.sanitizedRequestIdentity != r.routeExecution.Authorization().RequestIdentity() {
			return ErrInvalidVerificationResult
		}
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
	Contract                             string          `json:"contract"`
	SchemaVersion                        int             `json:"schema_version"`
	Identity                             string          `json:"identity"`
	GenerationArtifactIdentity           string          `json:"generation_artifact_identity"`
	VerificationContextIdentity          string          `json:"verification_context_identity"`
	VerificationBatchIdentity            string          `json:"verification_batch_identity"`
	RouteExecutionIdentity               string          `json:"route_execution_identity"`
	IndependenceLevel                    string          `json:"independence_level"`
	RouteIndependenceIdentity            string          `json:"route_independence_identity"`
	IndependentReceiptIdentity           string          `json:"independent_receipt_identity"`
	VerifiedFindingSetIdentity           string          `json:"verified_finding_set_identity"`
	RawVerificationRequestIdentity       string          `json:"raw_verification_request_identity,omitempty"`
	SanitizedVerificationRequestIdentity string          `json:"sanitized_verification_request_identity,omitempty"`
	SanitizedRequestArtifactIdentity     string          `json:"sanitized_request_artifact_identity,omitempty"`
	SanitizedReceiptArtifactIdentity     string          `json:"sanitized_receipt_artifact_identity,omitempty"`
	SanitizedReceiptIdentity             string          `json:"sanitized_receipt_identity,omitempty"`
	VerificationSanitizerIdentity        string          `json:"verification_sanitizer_identity,omitempty"`
	ScannerHelperSHA256                  string          `json:"scanner_helper_sha256,omitempty"`
	VerificationBatch                    json.RawMessage `json:"verification_batch"`
	RouteExecution                       json.RawMessage `json:"route_execution"`
	VerifiedFindingSet                   json.RawMessage `json:"verified_finding_set"`
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
	version := 1
	if !result.egress.empty() {
		version = 2
	}
	encoded, err := json.Marshal(verificationResultWire{
		Contract: "open-trestle/model-verification-result", SchemaVersion: version,
		Identity: result.Identity(), GenerationArtifactIdentity: result.generationArtifactIdentity,
		VerificationContextIdentity: result.verificationContext.Identity(),
		VerificationBatchIdentity:   result.verification.Identity(), RouteExecutionIdentity: result.routeExecution.Identity(),
		IndependenceLevel:                    result.routeIndependence.Level().String(),
		RouteIndependenceIdentity:            result.routeIndependence.Identity(),
		IndependentReceiptIdentity:           result.independentReceipt.Identity(),
		VerifiedFindingSetIdentity:           result.verifiedFindings.Identity(),
		RawVerificationRequestIdentity:       result.egress.rawRequestIdentity,
		SanitizedVerificationRequestIdentity: result.egress.sanitizedRequestIdentity,
		SanitizedRequestArtifactIdentity:     result.egress.sanitizedRequestArtifactIdentity,
		SanitizedReceiptArtifactIdentity:     result.egress.receiptArtifactIdentity,
		SanitizedReceiptIdentity:             result.egress.receiptIdentity,
		VerificationSanitizerIdentity:        result.egress.sanitizerIdentity,
		ScannerHelperSHA256:                  result.egress.helperSHA256,
		VerificationBatch:                    verification, RouteExecution: routeExecution, VerifiedFindingSet: findings,
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
	if !bytes.Equal(canonical, payload) || wire.Contract != "open-trestle/model-verification-result" || (wire.SchemaVersion != 1 && wire.SchemaVersion != 2) || !validDigest(wire.GenerationArtifactIdentity) {
		return "", ErrInvalidVerificationResult
	}
	return wire.GenerationArtifactIdentity, nil
}

// VerificationResultEgressReferences returns the v2 sanitized artifact identities.
func VerificationResultEgressReferences(value artifact.Artifact) (string, string, bool, error) {
	if value.Validate() != nil || value.Kind() != artifact.KindVerifiedFindingSet || value.MediaType() != "application/json" || value.Origin() != artifact.OriginIndependentVerifier {
		return "", "", false, ErrInvalidVerificationResult
	}
	payload := value.Payload()
	if len(payload) == 0 || len(payload) > maximumVerificationResultBytes {
		return "", "", false, ErrInvalidVerificationResult
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var wire verificationResultWire
	if decoder.Decode(&wire) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return "", "", false, ErrInvalidVerificationResult
	}
	canonical, err := json.Marshal(wire)
	if err != nil || !bytes.Equal(canonical, payload) || wire.Contract != "open-trestle/model-verification-result" || (wire.SchemaVersion != 1 && wire.SchemaVersion != 2) {
		return "", "", false, ErrInvalidVerificationResult
	}
	if wire.SchemaVersion == 1 {
		return "", "", false, nil
	}
	if !validDigest(wire.SanitizedRequestArtifactIdentity) || !validDigest(wire.SanitizedReceiptArtifactIdentity) {
		return "", "", false, ErrInvalidVerificationResult
	}
	return wire.SanitizedRequestArtifactIdentity, wire.SanitizedReceiptArtifactIdentity, true, nil
}

// ParseStoredVerificationResultArtifact reloads and validates v2 egress authority.
func ParseStoredVerificationResultArtifact(ctx context.Context, store artifact.Store, at time.Time, value, generationArtifact, generationInputArtifact, generationContextArtifact artifact.Artifact) (VerificationResult, error) {
	if nilInterface(ctx) || nilInterface(store) || at.UnixMilli() <= 0 {
		return VerificationResult{}, ErrInvalidVerificationResult
	}
	requestIdentity, receiptIdentity, present, err := VerificationResultEgressReferences(value)
	if err != nil {
		return VerificationResult{}, ErrInvalidVerificationResult
	}
	if !present {
		return ParseVerificationResultArtifact(value, generationArtifact, generationInputArtifact, generationContextArtifact)
	}
	requestArtifact, err := store.Get(ctx, value.Scope(), requestIdentity, at)
	if err != nil || requestArtifact.Identity() != requestIdentity {
		return VerificationResult{}, ErrInvalidVerificationResult
	}
	receiptArtifact, err := store.Get(ctx, value.Scope(), receiptIdentity, at)
	if err != nil || receiptArtifact.Identity() != receiptIdentity {
		return VerificationResult{}, ErrInvalidVerificationResult
	}
	return ParseVerificationResultArtifact(value, generationArtifact, generationInputArtifact, generationContextArtifact, VerificationEgressArtifacts{SanitizedRequest: requestArtifact, Receipt: receiptArtifact})
}

// ParseVerificationResultArtifact reconstructs and verifies complete independent-review lineage.
func ParseVerificationResultArtifact(
	value artifact.Artifact,
	generationArtifact artifact.Artifact,
	generationInputArtifact artifact.Artifact,
	generationContextArtifact artifact.Artifact,
	egressArtifacts ...VerificationEgressArtifacts,
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
	verificationContext, err := review.NewVerificationRequestContext(
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
	if err != nil || !bytes.Equal(canonical, payload) || wire.Contract != "open-trestle/model-verification-result" || (wire.SchemaVersion != 1 && wire.SchemaVersion != 2) ||
		wire.GenerationArtifactIdentity != generationArtifact.Identity() || wire.VerificationContextIdentity != verificationContext.Identity() {
		return VerificationResult{}, ErrInvalidVerificationResult
	}
	verification, err := review.ParseEncodedVerificationBatch(wire.VerificationBatch)
	if err != nil || verification.Identity() != wire.VerificationBatchIdentity || verification.CandidateBatchIdentity() != generation.Candidates().Identity() ||
		!review.VerificationBatchMatchesContext(verificationContext, generation.Candidates(), verification) {
		return VerificationResult{}, ErrInvalidVerificationResult
	}
	routeExecution, err := gateway.ParseRouteExecutionRecord(wire.RouteExecution)
	if err != nil || routeExecution.Identity() != wire.RouteExecutionIdentity {
		return VerificationResult{}, ErrInvalidVerificationResult
	}
	egress := verificationEgressBinding{}
	if wire.SchemaVersion == 1 {
		expectedRequestIdentity := verificationRequest.Identity()
		if routeExecution.Authorization().RequestIdentity() != expectedRequestIdentity {
			localRequest, requestErr := review.NewLocalVerificationRequest(verificationRequest, value.Scope().Identity())
			if requestErr != nil || routeExecution.Authorization().RouteReference().Zone() != provider.ProviderZoneLocal || routeExecution.Authorization().RequestIdentity() != localRequest.Identity() {
				return VerificationResult{}, ErrInvalidVerificationResult
			}
		}
	} else {
		egress = verificationEgressBinding{wire.RawVerificationRequestIdentity, wire.SanitizedVerificationRequestIdentity, wire.SanitizedRequestArtifactIdentity, wire.SanitizedReceiptArtifactIdentity, wire.SanitizedReceiptIdentity, wire.VerificationSanitizerIdentity, wire.ScannerHelperSHA256}
		if !egress.valid() || egress.rawRequestIdentity != verificationRequest.Identity() || egress.sanitizedRequestIdentity != routeExecution.Authorization().RequestIdentity() || len(egressArtifacts) != 1 {
			return VerificationResult{}, ErrInvalidVerificationResult
		}
		authority := egressArtifacts[0]
		expected := review.ScannerBinaryDigests{HelperSHA256: egress.helperSHA256}
		if authority.SanitizedRequest.Identity() != egress.sanitizedRequestArtifactIdentity || authority.Receipt.Identity() != egress.receiptArtifactIdentity ||
			review.ValidateSanitizedVerificationEgressArtifacts(verificationRequest, generation.ContextIdentity(), generation.Candidates().Identity(), generationArtifact, generationInputArtifact, generationContextArtifact, authority.SanitizedRequest, authority.Receipt, expected) != nil {
			return VerificationResult{}, ErrInvalidVerificationResult
		}
		sanitizedAuthority, requestErr := review.ParseSanitizedModelRequest(authority.SanitizedRequest.Payload())
		receiptAuthority, receiptErr := review.ParseSanitizedEgressReceipt(authority.Receipt.Payload())
		providerAuthority, providerErr := sanitizedAuthority.ProviderRequest()
		if requestErr != nil || receiptErr != nil || providerErr != nil || receiptAuthority.Identity() != egress.receiptIdentity || providerAuthority.Identity() != egress.sanitizedRequestIdentity || receiptAuthority.Scanner().HelperSHA256 != egress.helperSHA256 {
			return VerificationResult{}, ErrInvalidVerificationResult
		}
	}
	if wire.SchemaVersion == 1 && len(egressArtifacts) != 0 {
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
		GenerationRequestIdentity: generation.RouteExecution().Authorization().RequestIdentity(), VerificationRequestIdentity: routeExecution.Authorization().RequestIdentity(),
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
	var result VerificationResult
	if wire.SchemaVersion == 2 {
		result, err = newSanitizedVerificationResult(generationArtifact.Identity(), verificationContext, verification, routeExecution, independence, independent, findings, egress)
	} else {
		result, err = newVerificationResult(generationArtifact.Identity(), verificationContext, verification, routeExecution, independence, independent, findings)
	}
	if err != nil || result.Identity() != wire.Identity {
		return VerificationResult{}, ErrInvalidVerificationResult
	}
	result.artifactIdentity = value.Identity()
	reencoded, err := encodeVerificationResult(result)
	if err != nil || !bytes.Equal(reencoded, payload) {
		return VerificationResult{}, ErrInvalidVerificationResult
	}
	provenance := []string{
		generationInputArtifact.Identity(), generationContextArtifact.Identity(), verification.Identity(),
		routeExecution.Identity(), routeExecution.Authorization().Identity(), routeExecution.Outcome().Identity(),
		routeExecution.Reconciliation().Identity(), routeExecution.Output().Identity(), independence.Identity(),
		independent.Identity(), findings.Identity(),
	}
	if wire.SchemaVersion == 2 {
		provenance = append(provenance, routeExecution.Authorization().SelectionReceiptIdentity(), egress.sanitizedRequestArtifactIdentity, egress.receiptArtifactIdentity, egress.receiptIdentity, egress.sanitizedRequestIdentity)
	}
	for _, identity := range provenance {
		if !hasProvenance(value.Provenance(), identity) {
			return VerificationResult{}, ErrInvalidVerificationResult
		}
	}
	return result, nil
}

func deriveVerificationResultIdentity(result VerificationResult) string {
	version := 1
	if !result.egress.empty() {
		version = 2
	}
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
		RawRequest          string `json:"raw_request,omitempty"`
		SanitizedRequest    string `json:"sanitized_request,omitempty"`
		RequestArtifact     string `json:"request_artifact,omitempty"`
		ReceiptArtifact     string `json:"receipt_artifact,omitempty"`
		Receipt             string `json:"receipt,omitempty"`
		Sanitizer           string `json:"sanitizer,omitempty"`
		Helper              string `json:"helper,omitempty"`
	}{"open-trestle/model-verification-result", version, result.generationArtifactIdentity, result.verificationContext.Identity(), result.verification.Identity(), result.routeExecution.Identity(), result.routeIndependence.Identity(), result.independentReceipt.Identity(), result.verifiedFindings.Identity(), result.egress.rawRequestIdentity, result.egress.sanitizedRequestIdentity, result.egress.sanitizedRequestArtifactIdentity, result.egress.receiptArtifactIdentity, result.egress.receiptIdentity, result.egress.sanitizerIdentity, result.egress.helperSHA256})
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
