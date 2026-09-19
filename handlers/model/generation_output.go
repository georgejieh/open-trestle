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

const maximumGenerationResultBytes = 4 << 20

// GenerationResult is one admitted candidate set with complete successful route lineage.
type GenerationResult struct {
	identity, artifactIdentity               string
	inputArtifactIdentity                    string
	contextArtifactIdentity, contextIdentity string
	candidates                               review.CandidateBatch
	routeExecution                           gateway.RouteExecutionRecord
}

func (r GenerationResult) Identity() string                             { return r.identity }
func (r GenerationResult) ArtifactIdentity() string                     { return r.artifactIdentity }
func (r GenerationResult) InputArtifactIdentity() string                { return r.inputArtifactIdentity }
func (r GenerationResult) ContextArtifactIdentity() string              { return r.contextArtifactIdentity }
func (r GenerationResult) ContextIdentity() string                      { return r.contextIdentity }
func (r GenerationResult) Candidates() review.CandidateBatch            { return r.candidates }
func (r GenerationResult) RouteExecution() gateway.RouteExecutionRecord { return r.routeExecution }
func (r GenerationResult) String() string                               { return "model generation result" }
func (r GenerationResult) GoString() string                             { return "model.GenerationResult{<redacted>}" }
func (r GenerationResult) Format(state fmt.State, verb rune) {
	writeModelRedacted(state, verb, "model generation result", "model.GenerationResult{<redacted>}")
}

func newGenerationResult(
	inputArtifactIdentity, contextArtifactIdentity, contextIdentity string,
	candidates review.CandidateBatch,
	routeExecution gateway.RouteExecutionRecord,
) (GenerationResult, error) {
	result := GenerationResult{
		inputArtifactIdentity:   inputArtifactIdentity,
		contextArtifactIdentity: contextArtifactIdentity, contextIdentity: contextIdentity,
		candidates: candidates, routeExecution: routeExecution,
	}
	result.identity = deriveGenerationResultIdentity(result)
	if err := result.Validate(); err != nil {
		return GenerationResult{}, err
	}
	return result, nil
}

// Validate verifies candidate, route, request, response, and context lineage.
func (r GenerationResult) Validate() error {
	if !validDigest(r.inputArtifactIdentity) || !validDigest(r.contextArtifactIdentity) || !validDigest(r.contextIdentity) ||
		r.candidates.Validate() != nil || r.routeExecution.Validate() != nil {
		return ErrInvalidGenerationResult
	}
	output := r.routeExecution.Output()
	if output.Kind() != gateway.RouteOutputCandidateBatch || output.ContextIdentity() != r.contextIdentity ||
		output.ArtifactIdentity() != r.candidates.Identity() ||
		output.ResponseIdentity() != r.candidates.ResponseIdentity() {
		return ErrInvalidGenerationResult
	}
	if r.identity != deriveGenerationResultIdentity(r) {
		return ErrInvalidGenerationResult
	}
	return nil
}

type generationResultWire struct {
	Contract                string          `json:"contract"`
	SchemaVersion           int             `json:"schema_version"`
	Identity                string          `json:"identity"`
	InputArtifactIdentity   string          `json:"input_artifact_identity"`
	ContextArtifactIdentity string          `json:"context_artifact_identity"`
	ContextIdentity         string          `json:"context_identity"`
	CandidateBatchIdentity  string          `json:"candidate_batch_identity"`
	RouteExecutionIdentity  string          `json:"route_execution_identity"`
	CandidateBatch          json.RawMessage `json:"candidate_batch"`
	RouteExecution          json.RawMessage `json:"route_execution"`
}

func encodeGenerationResult(result GenerationResult) ([]byte, error) {
	if err := result.Validate(); err != nil {
		return nil, err
	}
	candidates, err := review.EncodeCandidateBatch(result.candidates)
	if err != nil {
		return nil, err
	}
	routeExecution, err := gateway.EncodeRouteExecutionRecord(result.routeExecution)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(generationResultWire{
		Contract: "open-trestle/model-generation-result", SchemaVersion: 1,
		Identity: result.Identity(), InputArtifactIdentity: result.inputArtifactIdentity,
		ContextArtifactIdentity: result.contextArtifactIdentity,
		ContextIdentity:         result.contextIdentity, CandidateBatchIdentity: result.candidates.Identity(),
		RouteExecutionIdentity: result.routeExecution.Identity(), CandidateBatch: candidates,
		RouteExecution: routeExecution,
	})
	if err != nil || len(encoded) == 0 || len(encoded) > maximumGenerationResultBytes {
		return nil, ErrInvalidGenerationResult
	}
	return encoded, nil
}

// GenerationResultReferences returns only bounded artifact references needed for full validation.
func GenerationResultReferences(value artifact.Artifact) (string, string, error) {
	if value.Validate() != nil || value.Kind() != artifact.KindCandidateBatch ||
		value.MediaType() != "application/json" || value.Origin() != artifact.OriginModel {
		return "", "", ErrInvalidGenerationResult
	}
	payload := value.Payload()
	if len(payload) == 0 || len(payload) > maximumGenerationResultBytes {
		return "", "", ErrInvalidGenerationResult
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var wire generationResultWire
	if err := decoder.Decode(&wire); err != nil {
		return "", "", ErrInvalidGenerationResult
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return "", "", ErrInvalidGenerationResult
	}
	canonical, err := json.Marshal(wire)
	if err != nil || !bytes.Equal(canonical, payload) ||
		wire.Contract != "open-trestle/model-generation-result" || wire.SchemaVersion != 1 ||
		!validDigest(wire.InputArtifactIdentity) || !validDigest(wire.ContextArtifactIdentity) {
		return "", "", ErrInvalidGenerationResult
	}
	return wire.InputArtifactIdentity, wire.ContextArtifactIdentity, nil
}

// ParseGenerationResultArtifact verifies one scoped model-produced candidate artifact.
func ParseGenerationResultArtifact(
	value artifact.Artifact,
	inputArtifact artifact.Artifact,
	contextArtifact artifact.Artifact,
) (GenerationResult, error) {
	if value.Validate() != nil || inputArtifact.Validate() != nil || contextArtifact.Validate() != nil ||
		inputArtifact.Kind() != artifact.KindTaskInput || inputArtifact.MediaType() != "application/json" ||
		inputArtifact.Origin() != artifact.OriginHost || contextArtifact.Kind() != artifact.KindContextPacket ||
		contextArtifact.MediaType() != "application/json" || contextArtifact.Origin() != artifact.OriginHost ||
		inputArtifact.Classification() != contextArtifact.Classification() ||
		inputArtifact.Protection() != contextArtifact.Protection() ||
		value.Kind() != artifact.KindCandidateBatch || value.MediaType() != "application/json" ||
		value.Origin() != artifact.OriginModel || value.Scope().Identity() != inputArtifact.Scope().Identity() ||
		value.Scope().Identity() != contextArtifact.Scope().Identity() ||
		value.Classification() != contextArtifact.Classification() || value.Protection() != contextArtifact.Protection() ||
		!hasProvenance(value.Provenance(), inputArtifact.Identity()) ||
		!hasProvenance(value.Provenance(), contextArtifact.Identity()) {
		return GenerationResult{}, ErrInvalidGenerationResult
	}
	input, err := ParseGenerationInput(inputArtifact.Payload())
	if err != nil || input.ContextArtifactIdentity() != contextArtifact.Identity() ||
		input.ReviewScopeIdentity() != contextArtifact.Scope().Identity() ||
		!hasProvenance(inputArtifact.Provenance(), contextArtifact.Identity()) ||
		!hasProvenance(inputArtifact.Provenance(), input.Authorization().Identity()) ||
		review.ValidateRecordedContextPacketRequest(
			contextArtifact.Payload(), input.ContextIdentity(), input.ReviewScopeIdentity(), input.MemoryScopeIdentity(), input.MemoryIdentity(),
			input.Snapshot(), input.EvidenceItems(),
		) != nil {
		return GenerationResult{}, ErrInvalidGenerationResult
	}
	providerRequest, err := provider.NewRequest(
		provider.CapabilityReviewV1, contextArtifact.MediaType(), contextArtifact.Payload(),
	)
	if err != nil || providerRequest.Identity() != input.Authorization().RequestIdentity() {
		return GenerationResult{}, ErrInvalidGenerationResult
	}
	payload := value.Payload()
	if len(payload) == 0 || len(payload) > maximumGenerationResultBytes {
		return GenerationResult{}, ErrInvalidGenerationResult
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var wire generationResultWire
	if err := decoder.Decode(&wire); err != nil {
		return GenerationResult{}, ErrInvalidGenerationResult
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return GenerationResult{}, ErrInvalidGenerationResult
	}
	canonical, err := json.Marshal(wire)
	if err != nil || !bytes.Equal(canonical, payload) || wire.Contract != "open-trestle/model-generation-result" ||
		wire.SchemaVersion != 1 || wire.InputArtifactIdentity != inputArtifact.Identity() ||
		wire.ContextArtifactIdentity != contextArtifact.Identity() ||
		wire.ContextIdentity != input.ContextIdentity() {
		return GenerationResult{}, ErrInvalidGenerationResult
	}
	candidates, err := review.ParseEncodedCandidateBatch(wire.CandidateBatch)
	if err != nil || candidates.Identity() != wire.CandidateBatchIdentity ||
		candidates.SnapshotIdentity() != input.Snapshot().Identity() {
		return GenerationResult{}, ErrInvalidGenerationResult
	}
	routeExecution, err := gateway.ParseRouteExecutionRecord(wire.RouteExecution)
	if err != nil || routeExecution.Identity() != wire.RouteExecutionIdentity ||
		routeExecution.Authorization().Identity() != input.Authorization().Identity() ||
		routeExecution.Authorization().ReviewScopeIdentity() != value.Scope().Identity() {
		return GenerationResult{}, ErrInvalidGenerationResult
	}
	result, err := newGenerationResult(inputArtifact.Identity(), contextArtifact.Identity(), input.ContextIdentity(), candidates, routeExecution)
	if err != nil || result.Identity() != wire.Identity {
		return GenerationResult{}, ErrInvalidGenerationResult
	}
	result.artifactIdentity = value.Identity()
	reencoded, err := encodeGenerationResult(result)
	if err != nil || !bytes.Equal(reencoded, payload) {
		return GenerationResult{}, ErrInvalidGenerationResult
	}
	for _, identity := range []string{
		result.Candidates().Identity(), result.RouteExecution().Identity(),
		result.RouteExecution().Authorization().Identity(), result.RouteExecution().Outcome().Identity(),
		result.RouteExecution().Reconciliation().Identity(), result.RouteExecution().Output().Identity(),
	} {
		if !hasProvenance(value.Provenance(), identity) {
			return GenerationResult{}, ErrInvalidGenerationResult
		}
	}
	return result, nil
}

func deriveGenerationResultIdentity(result GenerationResult) string {
	encoded, err := json.Marshal(struct {
		Contract                string `json:"contract"`
		SchemaVersion           int    `json:"schema_version"`
		InputArtifactIdentity   string `json:"input_artifact_identity"`
		ContextArtifactIdentity string `json:"context_artifact_identity"`
		ContextIdentity         string `json:"context_identity"`
		CandidateBatchIdentity  string `json:"candidate_batch_identity"`
		RouteExecutionIdentity  string `json:"route_execution_identity"`
	}{
		"open-trestle/model-generation-result", 1, result.inputArtifactIdentity,
		result.contextArtifactIdentity, result.contextIdentity, result.candidates.Identity(), result.routeExecution.Identity(),
	})
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func hasProvenance(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
