package publication

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	analysishandler "github.com/georgejieh/open-trestle/handlers/analysis"
	changehandler "github.com/georgejieh/open-trestle/handlers/change"
	modelhandler "github.com/georgejieh/open-trestle/handlers/model"
	sourcehandler "github.com/georgejieh/open-trestle/handlers/source"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/review"
)

type EffectAuthorizer interface {
	Identity() string
	Authorize(context.Context, audit.ReviewScope, review.PublicationPlan, time.Time) (review.PublicationAuthorization, error)
}
type Handler struct {
	identity, reviewPolicyIdentity string
	store                          artifact.Store
	clock                          artifact.Clock
	ledger                         audit.Ledger
	policy                         review.PublicationPolicy
	authorizer                     EffectAuthorizer
	publishers                     review.PublisherCatalog
	resolvers                      review.HeadResolverCatalog
}

var ErrInvalidPublicationHandler = errors.New("invalid publication handler")

func NewHandler(store artifact.Store, clock artifact.Clock, ledger audit.Ledger, reviewPolicyIdentity string, policy review.PublicationPolicy, authorizer EffectAuthorizer, publishers review.PublisherCatalog, resolvers review.HeadResolverCatalog) (*Handler, error) {
	if nilInterface(store) || nilInterface(clock) || nilInterface(ledger) || nilInterface(authorizer) || !validDigest(reviewPolicyIdentity) || !validDigest(authorizer.Identity()) || policy.Validate() != nil || publishers.Validate() != nil || resolvers.Validate() != nil {
		return nil, ErrInvalidPublicationHandler
	}
	h := &Handler{store: store, clock: clock, ledger: ledger, reviewPolicyIdentity: reviewPolicyIdentity, policy: policy, authorizer: authorizer, publishers: publishers, resolvers: resolvers}
	h.identity = derivePublicationHandlerIdentity(h)
	return h, nil
}
func (h *Handler) HandlerIdentity() string {
	if h == nil {
		return ""
	}
	return h.identity
}
func (h *Handler) Kind() controlplane.TaskKind {
	if h == nil {
		return 0
	}
	return controlplane.TaskPublishResult
}
func (h *Handler) Validate() error {
	if h == nil || nilInterface(h.store) || nilInterface(h.clock) || nilInterface(h.ledger) || nilInterface(h.authorizer) || !validDigest(h.reviewPolicyIdentity) || !validDigest(h.authorizer.Identity()) || h.policy.Validate() != nil || h.publishers.Validate() != nil || h.resolvers.Validate() != nil || h.identity != derivePublicationHandlerIdentity(h) {
		return ErrInvalidPublicationHandler
	}
	return nil
}
func derivePublicationHandlerIdentity(h *Handler) string {
	encoded, _ := json.Marshal(struct {
		Contract          string `json:"contract"`
		Version           int    `json:"version"`
		ReviewPolicy      string `json:"review_policy"`
		PublicationPolicy string `json:"publication_policy"`
		Authorizer        string `json:"authorizer"`
		Publishers        string `json:"publishers"`
		Resolvers         string `json:"resolvers"`
	}{"open-trestle/publication-handler", 3, h.reviewPolicyIdentity, h.policy.Identity(), h.authorizer.Identity(), h.publishers.Identity(), h.resolvers.Identity()})
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

type receiptWire struct {
	Contract                   string `json:"contract"`
	SchemaVersion              int    `json:"schema_version"`
	Status                     string `json:"status"`
	ReadinessIdentity          string `json:"readiness_identity"`
	SourceBindingIdentity      string `json:"source_binding_identity"`
	PlanIdentity               string `json:"plan_identity"`
	AuthorizationIdentity      string `json:"authorization_identity"`
	ClaimIdentity              string `json:"claim_identity"`
	AttemptIdentity            string `json:"attempt_identity"`
	HeadReconciliationIdentity string `json:"head_reconciliation_identity"`
	ResultIdentity             string `json:"result_identity"`
	ExternalReferenceIdentity  string `json:"external_reference_identity"`
}

func (h *Handler) Execute(ctx context.Context, request controlplane.TaskExecutionRequest) controlplane.TaskCompletion {
	if nilInterface(ctx) || h.Validate() != nil || request.Validate() != nil || request.Plan().Mode() != controlplane.ReviewRunRequired || request.Task().Kind() != controlplane.TaskPublishResult || request.Task().HandlerIdentity() != h.identity || request.Task().MaxAttempts() != 1 || request.Plan().PolicyIdentity() != h.reviewPolicyIdentity || !equalStrings(request.Task().Dependencies(), []string{"readiness"}) {
		return failure(controlplane.RunFailureInvalidInput)
	}
	if ctx.Err() != nil {
		return failure(controlplane.RunFailureCanceled)
	}
	at := h.clock.Now().UTC()
	if at.UnixMilli() <= 0 || at.After(request.Lease().ExpiresAt()) {
		return failure(controlplane.RunFailureCanceled)
	}
	publicationInputArtifact, err := h.store.Get(ctx, request.Plan().Scope(), request.Task().InputIdentity(), at)
	if err != nil {
		return failure(readFailure(ctx, err))
	}
	if publicationInputArtifact.Kind() != artifact.KindTaskInput || publicationInputArtifact.Origin() != artifact.OriginHost {
		return failure(controlplane.RunFailureInvalidInput)
	}
	publicationInput, err := ParseInput(publicationInputArtifact.Payload())
	if err != nil {
		return failure(controlplane.RunFailureInvalidInput)
	}
	dependency, ok := request.DependencyOutput("readiness")
	if !ok || !dependency.Available() {
		return failure(controlplane.RunFailureInvalidInput)
	}
	readinessArtifact, err := h.store.Get(ctx, request.Plan().Scope(), dependency.OutputIdentity(), at)
	if err != nil {
		return failure(readFailure(ctx, err))
	}
	if publicationInputArtifact.Scope().Identity() != readinessArtifact.Scope().Identity() || publicationInputArtifact.Classification() != readinessArtifact.Classification() || publicationInputArtifact.Protection() != readinessArtifact.Protection() {
		return failure(controlplane.RunFailureInvalidInput)
	}
	verificationArtifact, verification, generationArtifact, inputArtifact, contextArtifact, err := h.loadVerification(ctx, request.Plan().Scope(), readinessArtifact, at)
	if err != nil {
		return failure(controlplane.RunFailureInvalidInput)
	}
	readinessResult, err := parseResult(readinessArtifact, verificationArtifact, verification, h.policy)
	if err != nil {
		return failure(controlplane.RunFailureInvalidInput)
	}
	readiness, err := review.EvaluatePublicationReadiness(h.policy, verification.IndependentReceipt(), verification.VerifiedFindings())
	if err != nil || readiness.Identity() != readinessResult.ReadinessIdentity() {
		return failure(controlplane.RunFailureInvalidInput)
	}
	switch readiness.Status() {
	case review.PublicationNoVerifiedFindings, review.PublicationBelowThreshold:
		return h.persistReceipt(ctx, request, readinessArtifact, publicationInputArtifact, receiptWire{Contract: "open-trestle/publication-receipt", SchemaVersion: 1, Status: "not_required", ReadinessIdentity: readiness.Identity()}, at)
	case review.PublicationBlockedInconclusive, review.PublicationBlockedIndependence:
		return failure(controlplane.RunFailurePolicy)
	case review.PublicationAdvisoryReady:
	default:
		return failure(controlplane.RunFailureInvalidInput)
	}
	target, err := publicationInput.Target()
	if err != nil {
		return failure(controlplane.RunFailureInvalidInput)
	}
	sourceBinding, err := h.buildSourceBinding(ctx, request.Plan().Scope(), target, generationArtifact, inputArtifact, contextArtifact, at)
	if err != nil {
		return failure(controlplane.RunFailureInvalidInput)
	}
	plan, err := review.NewPublicationPlanFromProtectedSource(readiness, target, sourceBinding)
	if err != nil {
		return failure(controlplane.RunFailureInvalidInput)
	}
	if _, err := review.RecordProtectedPublicationPrerequisites(ctx, h.ledger, request.Plan().Scope(), sourceBinding, readiness, at); err != nil {
		return failure(controlplane.RunFailureInternal)
	}
	authorization, err := h.authorizer.Authorize(ctx, request.Plan().Scope(), plan, at)
	if err != nil || authorization.Validate() != nil || authorization.PlanIdentity() != plan.Identity() {
		return failure(controlplane.RunFailurePolicy)
	}
	if _, err := review.RecordPublicationAuthorization(ctx, h.ledger, request.Plan().Scope(), authorization, at); err != nil {
		return failure(controlplane.RunFailureInternal)
	}
	claim, claimed, err := review.ClaimPublication(ctx, h.ledger, request.Plan().Scope(), authorization, at)
	if err != nil || !claimed {
		return failure(controlplane.RunFailureInternal)
	}
	attempt, err := review.NewInitialPublicationAttemptAuthorization(authorization, claim)
	if err != nil {
		return failure(controlplane.RunFailureInternal)
	}
	observation, err := review.ResolvePublicationHeadFromCatalog(ctx, h.resolvers, request.Plan().Scope(), authorization, claim, attempt, at)
	if err != nil {
		return failure(controlplane.RunFailureTransient)
	}
	evaluated := h.clock.Now().UTC()
	reconciliation, err := review.ReconcilePublicationHead(request.Plan().Scope(), authorization, claim, attempt, observation, evaluated)
	if err != nil {
		return failure(controlplane.RunFailureInternal)
	}
	gate, err := review.RecordPublicationHeadReconciliation(ctx, h.ledger, request.Plan().Scope(), authorization, claim, attempt, reconciliation, evaluated)
	if err != nil {
		return failure(controlplane.RunFailureInternal)
	}
	if !gate.AuthorizesPublication() {
		if reconciliation.Status() == review.PublicationHeadStale {
			return failure(controlplane.RunFailureInvalidInput)
		}
		return failure(controlplane.RunFailureTransient)
	}
	result, err := review.DispatchClaimedPublicationFromCatalog(ctx, h.publishers, request.Plan().Scope(), authorization, claim, attempt, gate, h.clock.Now().UTC())
	if err != nil {
		return failure(controlplane.RunFailureInternal)
	}
	completed := h.clock.Now().UTC()
	if _, err := review.RecordPublicationResult(ctx, h.ledger, request.Plan().Scope(), authorization, claim, attempt, result, completed); err != nil {
		return failure(controlplane.RunFailureInternal)
	}
	if result.Status() != review.PublicationSucceeded {
		return failure(mapPublicationFailure(result.Failure()))
	}
	wire := receiptWire{Contract: "open-trestle/publication-receipt", SchemaVersion: 1, Status: "published", ReadinessIdentity: readiness.Identity(), SourceBindingIdentity: sourceBinding.Identity(), PlanIdentity: plan.Identity(), AuthorizationIdentity: authorization.Identity(), ClaimIdentity: claim.Identity(), AttemptIdentity: attempt.Identity(), HeadReconciliationIdentity: reconciliation.Identity(), ResultIdentity: result.Identity(), ExternalReferenceIdentity: result.ExternalReferenceIdentity()}
	return h.persistReceipt(ctx, request, readinessArtifact, publicationInputArtifact, wire, completed)
}
func (h *Handler) loadVerification(ctx context.Context, scope audit.ReviewScope, readiness artifact.Artifact, at time.Time) (artifact.Artifact, modelhandler.VerificationResult, artifact.Artifact, artifact.Artifact, artifact.Artifact, error) {
	var zero artifact.Artifact
	var vr modelhandler.VerificationResult
	var verificationID string
	for _, id := range readiness.Provenance() {
		value, err := h.store.Get(ctx, scope, id, at)
		if err != nil {
			if errors.Is(err, artifact.ErrArtifactNotFound) || errors.Is(err, artifact.ErrErasureAdmissionMissing) {
				continue
			}
			return zero, vr, zero, zero, zero, err
		}
		if value.Kind() == artifact.KindVerifiedFindingSet {
			if verificationID != "" {
				return zero, vr, zero, zero, zero, ErrInvalidReadinessResult
			}
			verificationID = id
		}
	}
	if verificationID == "" {
		return zero, vr, zero, zero, zero, ErrInvalidReadinessResult
	}
	verificationArtifact, err := h.store.Get(ctx, scope, verificationID, at)
	if err != nil {
		return zero, vr, zero, zero, zero, err
	}
	generationID, err := modelhandler.VerificationResultReferences(verificationArtifact)
	if err != nil {
		return zero, vr, zero, zero, zero, err
	}
	generationArtifact, err := h.store.Get(ctx, scope, generationID, at)
	if err != nil {
		return zero, vr, zero, zero, zero, err
	}
	inputID, contextID, err := modelhandler.GenerationResultReferences(generationArtifact)
	if err != nil {
		return zero, vr, zero, zero, zero, err
	}
	inputArtifact, err := h.store.Get(ctx, scope, inputID, at)
	if err != nil {
		return zero, vr, zero, zero, zero, err
	}
	contextArtifact, err := h.store.Get(ctx, scope, contextID, at)
	if err != nil {
		return zero, vr, zero, zero, zero, err
	}
	vr, err = modelhandler.ParseVerificationResultArtifact(verificationArtifact, generationArtifact, inputArtifact, contextArtifact)
	return verificationArtifact, vr, generationArtifact, inputArtifact, contextArtifact, err
}
func (h *Handler) buildSourceBinding(ctx context.Context, scope audit.ReviewScope, target review.PublicationTarget, generationArtifact, inputArtifact, contextArtifact artifact.Artifact, at time.Time) (review.ProtectedSourceBinding, error) {
	input, err := modelhandler.ParseGenerationInput(inputArtifact.Payload())
	if err != nil {
		return review.ProtectedSourceBinding{}, err
	}
	var analysisArtifact artifact.Artifact
	found := false
	for _, id := range contextArtifact.Provenance() {
		value, getErr := h.store.Get(ctx, scope, id, at)
		if getErr != nil {
			if errors.Is(getErr, artifact.ErrArtifactNotFound) || errors.Is(getErr, artifact.ErrErasureAdmissionMissing) {
				continue
			}
			return review.ProtectedSourceBinding{}, getErr
		}
		if value.Kind() == artifact.KindDeterministicEvidence {
			if found {
				return review.ProtectedSourceBinding{}, ErrInvalidPublicationInput
			}
			analysisArtifact = value
			found = true
		}
	}
	if !found {
		return review.ProtectedSourceBinding{}, ErrInvalidPublicationInput
	}
	changeID, err := analysisChangeIdentity(analysisArtifact)
	if err != nil {
		return review.ProtectedSourceBinding{}, err
	}
	changeArtifact, err := h.store.Get(ctx, scope, changeID, at)
	if err != nil {
		return review.ProtectedSourceBinding{}, err
	}
	baseID, headID, err := changehandler.ResultArtifactReferences(changeArtifact)
	if err != nil {
		return review.ProtectedSourceBinding{}, err
	}
	baseArtifact, err := h.store.Get(ctx, scope, baseID, at)
	if err != nil {
		return review.ProtectedSourceBinding{}, err
	}
	headArtifact, err := h.store.Get(ctx, scope, headID, at)
	if err != nil {
		return review.ProtectedSourceBinding{}, err
	}
	change, err := changehandler.ParseResultArtifact(changeArtifact, baseArtifact, headArtifact)
	if err != nil || change.Repository().Identity() != target.RepositoryIdentity().Identity() || change.HeadRevision().Identity() != target.HeadRevision().Identity() {
		return review.ProtectedSourceBinding{}, ErrInvalidPublicationInput
	}
	analysis, err := analysishandler.ParseResultArtifact(analysisArtifact, changeArtifact, baseArtifact, headArtifact)
	if err != nil {
		return review.ProtectedSourceBinding{}, err
	}
	head, err := sourcehandler.ParseSnapshotArtifact(headArtifact)
	if err != nil {
		return review.ProtectedSourceBinding{}, err
	}
	byEvidence := make(map[string]analysishandler.Item, len(analysis.Items()))
	for _, item := range analysis.Items() {
		byEvidence[item.EvidenceID()] = item
	}
	semanticRanges := make(map[evidence.SourceRange]bool)
	for _, reference := range analysis.SemanticImpact().References() {
		sourceRange, err := evidence.NewSourceRange(reference.Path(), reference.Line(), reference.Line())
		if err != nil {
			return review.ProtectedSourceBinding{}, ErrInvalidPublicationInput
		}
		semanticRanges[sourceRange] = true
	}
	files := make(map[string]sourcehandler.FileReference, head.FileCount())
	for _, reference := range head.Files() {
		files[reference.Path()] = reference
	}
	items := input.EvidenceItems()
	bindings := make([]string, len(items))
	for index, item := range items {
		sourceRange := item.SourceRange()
		if item.Kind() != evidence.EvidenceKindSource {
			return review.ProtectedSourceBinding{}, ErrInvalidPublicationInput
		}
		sourceItem, changed := byEvidence[item.ID()]
		if changed {
			if sourceItem.Path() != sourceRange.Path() || sourceItem.StartLine() != sourceRange.StartLine() || sourceItem.EndLine() != sourceRange.EndLine() || sourceItem.Digest() != item.Digest() {
				return review.ProtectedSourceBinding{}, ErrInvalidPublicationInput
			}
		} else if !semanticRanges[sourceRange] {
			return review.ProtectedSourceBinding{}, ErrInvalidPublicationInput
		}
		reference, exists := files[sourceRange.Path()]
		if !exists {
			return review.ProtectedSourceBinding{}, ErrInvalidPublicationInput
		}
		binding, err := h.bindHeadSourceRange(ctx, scope, head, reference, sourceRange, at)
		if err != nil {
			return review.ProtectedSourceBinding{}, err
		}
		if binding.SliceDigest() != item.Digest() {
			return review.ProtectedSourceBinding{}, ErrInvalidPublicationInput
		}
		if changed {
			if binding.Identity() != sourceItem.BindingIdentity() || binding.RepositoryFileIdentity() != sourceItem.FileIdentity() || binding.RepositoryFileDigest() != sourceItem.FileDigest() || binding.SliceBytes() != sourceItem.SliceBytes() {
				return review.ProtectedSourceBinding{}, ErrInvalidPublicationInput
			}
		} else if binding.Identity() != item.ID() {
			return review.ProtectedSourceBinding{}, ErrInvalidPublicationInput
		}
		bindings[index] = binding.Identity()
	}
	return review.NewProtectedSourceBinding(scope, change.Repository(), change.HeadRevision(), headArtifact.Identity(), head.Identity(), head.ManifestIdentity(), changeArtifact.Identity(), change.Identity(), analysisArtifact.Identity(), contextArtifact.Identity(), input.ContextIdentity(), input.Snapshot().Identity(), bindings)
}
func (h *Handler) bindHeadSourceRange(ctx context.Context, scope audit.ReviewScope, head sourcehandler.Snapshot, reference sourcehandler.FileReference, sourceRange evidence.SourceRange, at time.Time) (evidence.SourceSliceBinding, error) {
	value, err := h.store.Get(ctx, scope, reference.ArtifactIdentity(), at)
	if err != nil {
		return evidence.SourceSliceBinding{}, err
	}
	file, err := sourcehandler.ParseFileArtifact(value, head, reference)
	if err != nil {
		return evidence.SourceSliceBinding{}, err
	}
	content := file.Content()
	defer clear(content)
	repositoryFile, err := evidence.NewRepositoryFile(file.Path(), content)
	if err != nil {
		return evidence.SourceSliceBinding{}, err
	}
	return evidence.BindSourceRange(repositoryFile, content, sourceRange)
}

func analysisChangeIdentity(value artifact.Artifact) (string, error) {
	var wire struct {
		ChangeArtifactIdentity string `json:"change_artifact_identity"`
	}
	if json.Unmarshal(value.Payload(), &wire) != nil || !validDigest(wire.ChangeArtifactIdentity) {
		return "", ErrInvalidPublicationInput
	}
	return wire.ChangeArtifactIdentity, nil
}
func (h *Handler) persistReceipt(ctx context.Context, request controlplane.TaskExecutionRequest, readiness, input artifact.Artifact, wire receiptWire, at time.Time) controlplane.TaskCompletion {
	payload, err := json.Marshal(wire)
	if err != nil {
		return failure(controlplane.RunFailureInternal)
	}
	provenance := []string{readiness.Identity(), input.Identity()}
	for _, id := range []string{wire.ReadinessIdentity, wire.SourceBindingIdentity, wire.PlanIdentity, wire.AuthorizationIdentity, wire.ClaimIdentity, wire.AttemptIdentity, wire.HeadReconciliationIdentity, wire.ResultIdentity} {
		if id != "" {
			provenance = append(provenance, id)
		}
	}
	sort.Strings(provenance)
	output, err := artifact.New(request.Plan().Scope(), artifact.KindPublicationReceipt, "application/json", readiness.Classification(), artifact.OriginHost, readiness.Protection(), provenance, payload, at, minimumTime(readiness.ExpiresAt(), input.ExpiresAt()))
	if err != nil {
		return failure(controlplane.RunFailureResourceLimit)
	}
	if _, err := h.store.Put(ctx, output, at); err != nil {
		return failure(writeFailure(ctx, err))
	}
	completion, err := controlplane.NewTaskSuccess(output.Identity())
	if err != nil {
		return failure(controlplane.RunFailureInternal)
	}
	return completion
}
func mapPublicationFailure(f review.PublicationFailure) controlplane.RunFailure {
	switch f {
	case review.PublicationFailureTransient, review.PublicationFailureRateLimited, review.PublicationFailureProvider:
		return controlplane.RunFailureTransient
	case review.PublicationFailureAuthorization:
		return controlplane.RunFailurePolicy
	case review.PublicationFailureCancelled:
		return controlplane.RunFailureCanceled
	case review.PublicationFailureStaleHead, review.PublicationFailureValidation:
		return controlplane.RunFailureInvalidInput
	default:
		return controlplane.RunFailureInternal
	}
}
