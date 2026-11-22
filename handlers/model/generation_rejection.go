package model

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/review"
)

// ErrInvalidGenerationRejection identifies incomplete or cross-wired rejection evidence.
var ErrInvalidGenerationRejection = errors.New("invalid model generation rejection")

// GenerationRejection records a host-observed document shape rejection, not model output.
// It does not authorize retry, resume, publication, or startup recovery.
type GenerationRejection struct {
	identity, inputArtifactIdentity, contextArtifactIdentity, contextIdentity, handlerIdentity string
	attempt                                                                                    gateway.CompletedRouteAttemptRecord
}

func (r GenerationRejection) Identity() string                             { return r.identity }
func (r GenerationRejection) HandlerIdentity() string                      { return r.handlerIdentity }
func (r GenerationRejection) Attempt() gateway.CompletedRouteAttemptRecord { return r.attempt }
func (r GenerationRejection) String() string                               { return "model generation rejection" }
func (r GenerationRejection) GoString() string                             { return "model.GenerationRejection{<redacted>}" }
func (r GenerationRejection) Format(s fmt.State, verb rune) {
	writeModelRedacted(s, verb, "model generation rejection", "model.GenerationRejection{<redacted>}")
}
func (r GenerationRejection) Validate() error {
	if !validDigest(r.inputArtifactIdentity) || !validDigest(r.contextArtifactIdentity) || !validDigest(r.contextIdentity) || !validDigest(r.handlerIdentity) || r.attempt.Validate() != nil || r.attempt.Outcome().Status() != gateway.RouteAttemptSucceeded || r.attempt.Reconciliation().Status() == gateway.RouteCostBudgetExceeded || r.identity != r.deriveIdentity() {
		return ErrInvalidGenerationRejection
	}
	return nil
}
func (r GenerationRejection) deriveIdentity() string {
	encoded, err := json.Marshal([]any{"open-trestle/model-generation-rejection", 1, r.inputArtifactIdentity, r.contextArtifactIdentity, r.contextIdentity, r.handlerIdentity, r.attempt.Identity(), "candidate_document_shape"})
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

type generationRejectionWire struct {
	Contract                string          `json:"contract"`
	SchemaVersion           int             `json:"schema_version"`
	Identity                string          `json:"identity"`
	InputArtifactIdentity   string          `json:"input_artifact_identity"`
	ContextArtifactIdentity string          `json:"context_artifact_identity"`
	ContextIdentity         string          `json:"context_identity"`
	HandlerIdentity         string          `json:"handler_identity"`
	FailureClass            string          `json:"failure_class"`
	Attempt                 json.RawMessage `json:"attempt"`
}

func encodeGenerationRejection(r GenerationRejection) ([]byte, error) {
	if r.Validate() != nil {
		return nil, ErrInvalidGenerationRejection
	}
	attempt, err := gateway.EncodeCompletedRouteAttemptRecord(r.attempt)
	if err != nil {
		return nil, ErrInvalidGenerationRejection
	}
	encoded, err := json.Marshal(generationRejectionWire{"open-trestle/model-generation-rejection", 1, r.Identity(), r.inputArtifactIdentity, r.contextArtifactIdentity, r.contextIdentity, r.handlerIdentity, "candidate_document_shape", attempt})
	if err != nil || len(encoded) > maximumGenerationInputBytes {
		return nil, ErrInvalidGenerationRejection
	}
	return encoded, nil
}

// ParseGenerationRejectionArtifact proves the stored receipt's exact input and context lineage.
// The host assertion cannot be reparsed without response content, which is deliberately absent.
func ParseGenerationRejectionArtifact(value, inputArtifact, contextArtifact artifact.Artifact) (GenerationRejection, error) {
	fail := func() (GenerationRejection, error) { return GenerationRejection{}, ErrInvalidGenerationRejection }
	if value.Validate() != nil || inputArtifact.Validate() != nil || contextArtifact.Validate() != nil ||
		value.Kind() != artifact.KindGenerationRejection || value.Origin() != artifact.OriginHost || value.MediaType() != "application/json" ||
		inputArtifact.Kind() != artifact.KindTaskInput || inputArtifact.Origin() != artifact.OriginHost || inputArtifact.MediaType() != "application/json" ||
		contextArtifact.Kind() != artifact.KindContextPacket || contextArtifact.Origin() != artifact.OriginHost || contextArtifact.MediaType() != "application/json" ||
		value.Scope() != inputArtifact.Scope() || value.Scope() != contextArtifact.Scope() ||
		value.Classification() != contextArtifact.Classification() || value.Protection() != contextArtifact.Protection() ||
		inputArtifact.Classification() != contextArtifact.Classification() || inputArtifact.Protection() != contextArtifact.Protection() ||
		!value.ExpiresAt().Equal(contextArtifact.ExpiresAt()) || value.CreatedAt().Before(inputArtifact.CreatedAt()) {
		return fail()
	}
	input, err := ParseGenerationInput(inputArtifact.Payload())
	if err != nil || !input.IsSanitized() || input.ContextArtifactIdentity() != contextArtifact.Identity() || input.ReviewScopeIdentity() != value.Scope().Identity() || review.ValidateContextPacketRequest(contextArtifact.Payload(), input.ContextIdentity(), input.ReviewScopeIdentity(), input.MemoryScopeIdentity(), input.MemoryIdentity(), input.Snapshot(), input.EvidenceItems()) != nil {
		return fail()
	}
	for _, id := range []string{contextArtifact.Identity(), input.Authorization().Identity(), input.SanitizedRequestArtifactIdentity(), input.SanitizedEgressReceiptArtifactIdentity()} {
		if !hasProvenance(inputArtifact.Provenance(), id) {
			return fail()
		}
	}
	payload := value.Payload()
	if len(payload) == 0 || len(payload) > maximumGenerationInputBytes {
		return fail()
	}
	var wire generationRejectionWire
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&wire) != nil || wire.Contract != "open-trestle/model-generation-rejection" || wire.SchemaVersion != 1 || wire.FailureClass != "candidate_document_shape" || wire.InputArtifactIdentity != inputArtifact.Identity() || wire.ContextArtifactIdentity != contextArtifact.Identity() || wire.ContextIdentity != input.ContextIdentity() {
		return fail()
	}
	attempt, err := gateway.ParseCompletedRouteAttemptRecord(wire.Attempt)
	// The rejected reply may come from a rate-limited request's retry.
	if err != nil || !gateway.IsSameReservationRetryOf(input.Authorization(), attempt.Authorization()) {
		return fail()
	}
	r := GenerationRejection{identity: wire.Identity, inputArtifactIdentity: wire.InputArtifactIdentity, contextArtifactIdentity: wire.ContextArtifactIdentity, contextIdentity: wire.ContextIdentity, handlerIdentity: wire.HandlerIdentity, attempt: attempt}
	encoded, err := encodeGenerationRejection(r)
	if err != nil || !bytes.Equal(encoded, payload) {
		return fail()
	}
	expected := []string{inputArtifact.Identity(), contextArtifact.Identity(), r.HandlerIdentity(), r.Attempt().Identity(), input.SanitizedRequestArtifactIdentity(), input.SanitizedEgressReceiptArtifactIdentity()}
	slices.Sort(expected)
	if !slices.Equal(expected, value.Provenance()) {
		return fail()
	}
	return r, nil
}

func (h *GenerationHandler) recordDocumentShapeRejection(ctx context.Context, task controlplane.TaskExecutionRequest, inputArtifact, contextArtifact artifact.Artifact, input GenerationInput, authorization gateway.RouteAttemptAuthorization, outcome gateway.RouteAttemptOutcome, cost gateway.RouteCostReconciliation) error {
	if !h.requiresSanitized || !input.IsSanitized() {
		return ErrInvalidGenerationRejection
	}
	live := func() bool {
		now := h.clock.Now().UTC()
		return ctx.Err() == nil && now.Before(task.Lease().ExpiresAt()) && now.Before(contextArtifact.ExpiresAt())
	}
	if !live() {
		return ErrInvalidGenerationRejection
	}
	attempt, err := gateway.NewCompletedRouteAttemptRecord(authorization, outcome, cost)
	if err != nil {
		return err
	}
	r := GenerationRejection{inputArtifactIdentity: inputArtifact.Identity(), contextArtifactIdentity: contextArtifact.Identity(), contextIdentity: input.ContextIdentity(), handlerIdentity: h.HandlerIdentity(), attempt: attempt}
	r.identity = r.deriveIdentity()
	payload, err := encodeGenerationRejection(r)
	if err != nil {
		return err
	}
	value, err := artifact.New(task.Plan().Scope(), artifact.KindGenerationRejection, "application/json", contextArtifact.Classification(), artifact.OriginHost, contextArtifact.Protection(), []string{inputArtifact.Identity(), contextArtifact.Identity(), h.HandlerIdentity(), attempt.Identity(), input.SanitizedRequestArtifactIdentity(), input.SanitizedEgressReceiptArtifactIdentity()}, payload, h.clock.Now().UTC(), contextArtifact.ExpiresAt())
	if err != nil {
		return err
	}
	if !live() {
		return ErrInvalidGenerationRejection
	}
	if _, err = h.store.Put(ctx, value, h.clock.Now().UTC()); err != nil {
		return err
	}
	if !live() {
		return ErrInvalidGenerationRejection
	}
	stored, err := h.store.Get(ctx, task.Plan().Scope(), value.Identity(), h.clock.Now().UTC())
	if err != nil {
		return err
	}
	parsed, err := ParseGenerationRejectionArtifact(stored, inputArtifact, contextArtifact)
	if err != nil || parsed.Identity() != r.Identity() || stored.Identity() != value.Identity() {
		return ErrInvalidGenerationRejection
	}
	if _, err = artifact.Encode(stored); err != nil {
		return err
	}
	if !live() {
		return ErrInvalidGenerationRejection
	}
	head, exists, err := h.ledger.Head(ctx, task.Plan().Scope())
	if err != nil || !exists {
		return ErrInvalidGenerationRejection
	}
	event, err := audit.NewEvent(task.Plan().Scope(), head.Sequence()+1, head.Identity(), audit.EventGenerationRejected, value.Identity(), []string{inputArtifact.Identity(), contextArtifact.Identity(), attempt.Identity()}, h.clock.Now().UTC())
	if err != nil {
		return err
	}
	if !live() {
		return ErrInvalidGenerationRejection
	}
	return h.ledger.Append(ctx, head.Identity(), event)
}
