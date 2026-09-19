package review

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/gateway"
)

const maxModelPipelineAuditConflicts = 16

var (
	// ErrInvalidModelPipelineAuditLedger identifies a missing audit ledger.
	ErrInvalidModelPipelineAuditLedger = errors.New("invalid model pipeline audit ledger")
	// ErrModelPipelineAuditScopeMismatch identifies artifacts from another review scope.
	ErrModelPipelineAuditScopeMismatch = errors.New("model pipeline audit scope mismatch")
	// ErrModelPipelineAuditArtifactMismatch identifies cross-wired derived records.
	ErrModelPipelineAuditArtifactMismatch = errors.New("model pipeline audit artifact mismatch")
	// ErrModelPipelineAuditConflict identifies incompatible existing event lineage or sustained head contention.
	ErrModelPipelineAuditConflict = errors.New("model pipeline audit conflict")
	// ErrInvalidModelPipelineAuditReceipt identifies malformed event coverage.
	ErrInvalidModelPipelineAuditReceipt = errors.New("invalid model pipeline audit receipt")
	// ErrInvalidModelPipelineAuditReceiptIdentity identifies receipt content inconsistent with its identity.
	ErrInvalidModelPipelineAuditReceiptIdentity = errors.New("invalid model pipeline audit receipt identity")
)

// ModelPipelineArtifacts supplies the complete checked generation-to-readiness lineage.
type ModelPipelineArtifacts struct {
	GenerationContext       ContextPacket
	CandidateOutput         gateway.RouteOutputReceipt
	Candidates              CandidateBatch
	VerificationContext     VerificationContextPacket
	VerificationOutput      gateway.RouteOutputReceipt
	Verification            VerificationBatch
	RouteIndependence       gateway.RouteIndependenceReceipt
	IndependentVerification IndependentVerificationReceipt
	VerifiedFindings        VerifiedFindingSet
	PublicationReadiness    PublicationReadiness
}

// ModelPipelineAuditReceipt binds the exact audit events recorded for one model review pipeline.
type ModelPipelineAuditReceipt struct {
	identity            string
	reviewScopeIdentity string
	events              []audit.Event
}

// RecordModelPipelineAudit validates all artifacts and idempotently appends content-free events.
func RecordModelPipelineAudit(ctx context.Context, ledger audit.Ledger, scope audit.ReviewScope, artifacts ModelPipelineArtifacts, occurredAt time.Time) (ModelPipelineAuditReceipt, error) {
	if isNilModelAuditLedger(ledger) {
		return ModelPipelineAuditReceipt{}, ErrInvalidModelPipelineAuditLedger
	}
	if err := scope.Validate(); err != nil {
		return ModelPipelineAuditReceipt{}, err
	}
	if err := validateModelPipelineArtifacts(scope, artifacts); err != nil {
		return ModelPipelineAuditReceipt{}, err
	}
	generation := artifacts.GenerationContext
	selection := generation.SourceSelection()
	specifications := []modelAuditEventSpecification{
		{audit.EventContextSourcesSelected, selection.Identity(), []string{generation.Retrieval().Identity(), generation.SnapshotIdentity()}},
		{audit.EventContextPacketAssembled, generation.Identity(), []string{selection.Identity(), generation.Retrieval().Identity(), generation.SnapshotIdentity()}},
		{audit.EventCandidateBatchAdmitted, artifacts.Candidates.Identity(), []string{generation.Identity(), artifacts.CandidateOutput.Identity(), artifacts.Candidates.ResponseIdentity()}},
		{audit.EventVerificationContextAssembled, artifacts.VerificationContext.Identity(), []string{generation.Identity(), artifacts.Candidates.Identity()}},
		{audit.EventVerificationBatchAdmitted, artifacts.Verification.Identity(), []string{artifacts.VerificationContext.Identity(), artifacts.VerificationOutput.Identity(), artifacts.Verification.ResponseIdentity()}},
		{
			audit.EventIndependentVerificationCompleted,
			artifacts.IndependentVerification.Identity(),
			[]string{
				artifacts.CandidateOutput.Identity(), artifacts.VerificationOutput.Identity(),
				artifacts.RouteIndependence.Identity(), artifacts.Verification.Identity(),
			},
		},
		{audit.EventPublicationReadinessEvaluated, artifacts.PublicationReadiness.Identity(), []string{artifacts.IndependentVerification.Identity(), artifacts.VerifiedFindings.Identity(), artifacts.PublicationReadiness.PolicyIdentity()}},
	}
	events := make([]audit.Event, len(specifications))
	for index, specification := range specifications {
		event, err := appendUniqueModelAuditEvent(ctx, ledger, scope, specification, occurredAt)
		if err != nil {
			return ModelPipelineAuditReceipt{}, err
		}
		events[index] = event
	}
	receipt := ModelPipelineAuditReceipt{reviewScopeIdentity: scope.Identity(), events: events}
	receipt.identity = deriveModelPipelineAuditReceiptIdentity(receipt)
	if err := receipt.Validate(); err != nil {
		return ModelPipelineAuditReceipt{}, err
	}
	return receipt, nil
}

func validateModelPipelineArtifacts(scope audit.ReviewScope, artifacts ModelPipelineArtifacts) error {
	scopeIdentity := scope.Identity()
	generationMatches := artifacts.GenerationContext.ReviewScopeIdentity() == scopeIdentity && artifacts.CandidateOutput.ReviewScopeIdentity() == scopeIdentity
	verificationMatches := artifacts.VerificationOutput.ReviewScopeIdentity() == scopeIdentity && artifacts.RouteIndependence.ReviewScopeIdentity() == scopeIdentity
	if !generationMatches || !verificationMatches || artifacts.IndependentVerification.ReviewScopeIdentity() != scopeIdentity {
		return ErrModelPipelineAuditScopeMismatch
	}
	expectedIndependent, err := NewIndependentVerificationReceipt(IndependentVerificationArtifacts{
		GenerationContext: artifacts.GenerationContext, Candidates: artifacts.Candidates,
		CandidateOutput: artifacts.CandidateOutput, VerificationContext: artifacts.VerificationContext,
		Verification: artifacts.Verification, VerificationOutput: artifacts.VerificationOutput,
		RouteIndependence: artifacts.RouteIndependence,
	})
	if err != nil || expectedIndependent.Identity() != artifacts.IndependentVerification.Identity() {
		return ErrModelPipelineAuditArtifactMismatch
	}
	expectedFindings, err := PromoteVerifiedCandidates(expectedIndependent, artifacts.Candidates, artifacts.Verification)
	if err != nil || expectedFindings.Identity() != artifacts.VerifiedFindings.Identity() {
		return ErrModelPipelineAuditArtifactMismatch
	}
	expectedReadiness, err := EvaluatePublicationReadiness(artifacts.PublicationReadiness.Policy(), expectedIndependent, expectedFindings)
	if err != nil || expectedReadiness.Identity() != artifacts.PublicationReadiness.Identity() {
		return ErrModelPipelineAuditArtifactMismatch
	}
	return nil
}

type modelAuditEventSpecification struct {
	kind    audit.EventKind
	subject string
	parents []string
}

func appendUniqueModelAuditEvent(ctx context.Context, ledger audit.Ledger, scope audit.ReviewScope, specification modelAuditEventSpecification, occurredAt time.Time) (audit.Event, error) {
	canonicalParents := append([]string(nil), specification.parents...)
	sort.Strings(canonicalParents)
	for range maxModelPipelineAuditConflicts {
		before, hadBefore, err := ledger.Head(ctx, scope)
		if err != nil {
			return audit.Event{}, err
		}
		existing, found, err := findModelAuditEvent(ctx, ledger, scope, specification.kind, specification.subject)
		if err != nil {
			return audit.Event{}, err
		}
		if found {
			if !slices.Equal(existing.CausalParentIdentities(), canonicalParents) {
				return audit.Event{}, ErrModelPipelineAuditConflict
			}
			return existing, nil
		}
		head, hasHead, err := ledger.Head(ctx, scope)
		if err != nil {
			return audit.Event{}, err
		}
		if hadBefore != hasHead || hadBefore && before.Identity() != head.Identity() {
			continue
		}
		sequence, previous := uint64(1), ""
		if hasHead {
			sequence, previous = head.Sequence()+1, head.Identity()
		}
		event, err := audit.NewEvent(scope, sequence, previous, specification.kind, specification.subject, canonicalParents, occurredAt)
		if err != nil {
			return audit.Event{}, err
		}
		if err := ledger.Append(ctx, previous, event); err == nil {
			return event, nil
		} else if !errors.Is(err, audit.ErrAuditHeadConflict) {
			return audit.Event{}, err
		}
	}
	return audit.Event{}, ErrModelPipelineAuditConflict
}

func findModelAuditEvent(ctx context.Context, ledger audit.Ledger, scope audit.ReviewScope, kind audit.EventKind, subject string) (audit.Event, bool, error) {
	var after uint64
	for {
		events, err := ledger.Read(ctx, scope, after, 1_000)
		if err != nil {
			return audit.Event{}, false, err
		}
		for _, event := range events {
			if event.Kind() == kind && event.SubjectIdentity() == subject {
				return event, true, nil
			}
		}
		if len(events) < 1_000 {
			return audit.Event{}, false, nil
		}
		after = events[len(events)-1].Sequence()
	}
}

func isNilModelAuditLedger(ledger audit.Ledger) bool {
	if ledger == nil {
		return true
	}
	value := reflect.ValueOf(ledger)
	return value.Kind() == reflect.Pointer && value.IsNil()
}

func (r ModelPipelineAuditReceipt) Identity() string            { return r.identity }
func (r ModelPipelineAuditReceipt) ReviewScopeIdentity() string { return r.reviewScopeIdentity }
func (r ModelPipelineAuditReceipt) Events() []audit.Event {
	return append([]audit.Event(nil), r.events...)
}
func (r ModelPipelineAuditReceipt) String() string { return "model pipeline audit receipt" }
func (r ModelPipelineAuditReceipt) GoString() string {
	return "review.ModelPipelineAuditReceipt{<redacted>}"
}
func (r ModelPipelineAuditReceipt) Format(state fmt.State, verb rune) {
	writeRedactedReviewFormat(state, verb, "model pipeline audit receipt", "review.ModelPipelineAuditReceipt{<redacted>}")
}

// Validate verifies exact event coverage, scope, kinds, subjects, and identity.
func (r ModelPipelineAuditReceipt) Validate() error {
	if !validCandidateDigest(r.reviewScopeIdentity) || len(r.events) != 7 {
		return ErrInvalidModelPipelineAuditReceipt
	}
	wantKinds := [...]audit.EventKind{
		audit.EventContextSourcesSelected, audit.EventContextPacketAssembled,
		audit.EventCandidateBatchAdmitted, audit.EventVerificationContextAssembled,
		audit.EventVerificationBatchAdmitted, audit.EventIndependentVerificationCompleted,
		audit.EventPublicationReadinessEvaluated,
	}
	seen := make(map[string]struct{}, len(r.events))
	for index, event := range r.events {
		if err := event.Validate(); err != nil {
			return err
		}
		if event.Scope().Identity() != r.reviewScopeIdentity || event.Kind() != wantKinds[index] {
			return ErrInvalidModelPipelineAuditReceipt
		}
		if _, exists := seen[event.Identity()]; exists {
			return ErrInvalidModelPipelineAuditReceipt
		}
		seen[event.Identity()] = struct{}{}
	}
	if r.identity != deriveModelPipelineAuditReceiptIdentity(r) {
		return ErrInvalidModelPipelineAuditReceiptIdentity
	}
	return nil
}

func deriveModelPipelineAuditReceiptIdentity(receipt ModelPipelineAuditReceipt) string {
	eventIdentities := make([]string, len(receipt.events))
	for index, event := range receipt.events {
		eventIdentities[index] = event.Identity()
	}
	preimage := struct {
		Contract string   `json:"contract"`
		Version  int      `json:"version"`
		Scope    string   `json:"scope"`
		Events   []string `json:"events"`
	}{
		Contract: "open-trestle/model-pipeline-audit-receipt", Version: 1,
		Scope: receipt.reviewScopeIdentity, Events: eventIdentities,
	}
	encoded, _ := json.Marshal(preimage)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
