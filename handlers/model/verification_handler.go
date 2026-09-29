package model

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/internal/secretscan"
)

// VerificationHandler dispatches one independent verifier and persists promoted findings.
type VerificationHandler struct {
	identity          string
	store             artifact.Store
	catalog           gateway.RouteDispatcherCatalog
	ledger            audit.Ledger
	authorizer        VerificationAuthorizer
	clock             artifact.Clock
	sanitizer         review.VerificationRequestSanitizer
	sanitizerIdentity string
	expected          review.ScannerBinaryDigests
}

// NewVerificationHandler binds exact verifier routing, dispatch, audit, and storage authority.
func NewVerificationHandler(store artifact.Store, catalog gateway.RouteDispatcherCatalog, ledger audit.Ledger, authorizer VerificationAuthorizer, clock artifact.Clock, sanitizer review.VerificationRequestSanitizer) (*VerificationHandler, error) {
	if nilInterface(store) || catalog.Validate() != nil || nilInterface(ledger) || nilInterface(authorizer) || !validDigest(authorizer.Identity()) || nilInterface(clock) || nilInterface(sanitizer) || !validDigest(sanitizer.Identity()) {
		return nil, ErrInvalidVerificationHandler
	}
	h := &VerificationHandler{store: store, catalog: catalog, ledger: ledger, authorizer: authorizer, clock: clock, sanitizer: sanitizer, sanitizerIdentity: sanitizer.Identity(), expected: sanitizer.ExpectedBinaryDigests()}
	h.identity = deriveVerificationHandlerIdentity(catalog.Identity(), authorizer.Identity(), h.sanitizerIdentity, h.expected)
	if err := h.Validate(); err != nil {
		return nil, err
	}
	return h, nil
}
func (h *VerificationHandler) HandlerIdentity() string {
	if h == nil {
		return ""
	}
	return h.identity
}
func (h *VerificationHandler) Kind() controlplane.TaskKind {
	if h == nil {
		return 0
	}
	return controlplane.TaskVerifyCandidates
}
func (h *VerificationHandler) Validate() error {
	if h == nil || nilInterface(h.store) || h.catalog.Validate() != nil || nilInterface(h.ledger) || nilInterface(h.authorizer) || !validDigest(h.authorizer.Identity()) || nilInterface(h.clock) || nilInterface(h.sanitizer) || !validDigest(h.sanitizerIdentity) || h.sanitizer.Identity() != h.sanitizerIdentity || h.identity != deriveVerificationHandlerIdentity(h.catalog.Identity(), h.authorizer.Identity(), h.sanitizerIdentity, h.expected) {
		return ErrInvalidVerificationHandler
	}
	return nil
}
func deriveVerificationHandlerIdentity(catalog, authorizer, sanitizer string, expected review.ScannerBinaryDigests) string {
	if !validDigest(catalog) || !validDigest(authorizer) {
		return ""
	}
	encoded, err := json.Marshal(struct {
		Contract       string `json:"contract"`
		SchemaVersion  int    `json:"schema_version"`
		Catalog        string `json:"catalog"`
		Authorizer     string `json:"authorizer"`
		Sanitizer      string `json:"sanitizer"`
		LauncherSHA256 string `json:"launcher_sha256"`
		WorkerSHA256   string `json:"worker_sha256"`
	}{"open-trestle/model-verification-handler", 4, catalog, authorizer, sanitizer, expected.LauncherSHA256, expected.WorkerSHA256})
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

// Execute performs one policy-authorized verifier attempt and promotes only verified candidates.
func (h *VerificationHandler) Execute(ctx context.Context, task controlplane.TaskExecutionRequest) controlplane.TaskCompletion {
	if nilInterface(ctx) || h == nil || h.Validate() != nil || task.Validate() != nil || task.Task().Kind() != controlplane.TaskVerifyCandidates || task.Task().HandlerIdentity() != h.identity {
		return generationFailure(controlplane.RunFailureInvalidInput)
	}
	if task.Task().MaxAttempts() != 1 {
		return generationFailure(controlplane.RunFailurePolicy)
	}
	if ctx.Err() != nil {
		return generationFailure(controlplane.RunFailureCanceled)
	}
	started := h.clock.Now().UTC()
	if started.UnixMilli() <= 0 || started.After(task.Lease().ExpiresAt()) {
		return generationFailure(controlplane.RunFailureCanceled)
	}
	dependency, exists := task.DependencyOutput("candidates")
	if !exists || !dependency.Available() {
		return generationFailure(controlplane.RunFailureInvalidInput)
	}
	generationArtifact, err := h.store.Get(ctx, task.Plan().Scope(), dependency.OutputIdentity(), started)
	if err != nil {
		return generationFailure(generationStoreReadFailure(ctx, err))
	}
	inputIdentity, contextIdentity, err := GenerationResultReferences(generationArtifact)
	if err != nil {
		return generationFailure(controlplane.RunFailureInvalidInput)
	}
	generationInputArtifact, err := h.store.Get(ctx, task.Plan().Scope(), inputIdentity, started)
	if err != nil {
		return generationFailure(generationStoreReadFailure(ctx, err))
	}
	generationContextArtifact, err := h.store.Get(ctx, task.Plan().Scope(), contextIdentity, started)
	if err != nil {
		return generationFailure(generationStoreReadFailure(ctx, err))
	}
	generation, err := ParseGenerationResultArtifact(generationArtifact, generationInputArtifact, generationContextArtifact)
	if err != nil {
		return generationFailure(controlplane.RunFailureInvalidInput)
	}
	generationInput, err := ParseGenerationInput(generationInputArtifact.Payload())
	if err != nil {
		return generationFailure(controlplane.RunFailureInvalidInput)
	}
	verificationContext, err := review.NewVerificationRequestContext(generationContextArtifact.Payload(), generation.ContextIdentity(), task.Plan().Scope().Identity(), generationInput.MemoryScopeIdentity(), generationInput.MemoryIdentity(), generationInput.Snapshot(), generationInput.EvidenceItems(), generation.Candidates())
	if err != nil {
		return generationFailure(controlplane.RunFailureInvalidInput)
	}
	verificationRequest, err := verificationContext.ProviderRequest()
	if err != nil {
		return generationFailure(controlplane.RunFailureInvalidInput)
	}
	sanitized, receipt, sanitizeErr := h.sanitizer.SanitizeVerification(ctx, verificationRequest, task.Plan().Scope().Identity())
	if sanitizeErr != nil {
		if ctx.Err() != nil {
			return generationFailure(controlplane.RunFailureCanceled)
		}
		switch review.SanitizedEgressFailure(sanitizeErr) {
		case secretscan.FailureResourceLimit:
			return generationFailure(controlplane.RunFailureResourceLimit)
		case secretscan.FailureCanceled:
			return generationFailure(controlplane.RunFailureCanceled)
		case secretscan.FailureInvalidInput:
			return generationFailure(controlplane.RunFailureInvalidInput)
		default:
			return generationFailure(controlplane.RunFailurePolicy)
		}
	}
	sanitizedRequestArtifact, receiptArtifact, err := review.NewSanitizedVerificationEgressArtifacts(
		verificationRequest, generation.ContextIdentity(), generation.Candidates().Identity(), generationArtifact, generationInputArtifact, generationContextArtifact,
		sanitized, receipt, h.expected, started,
	)
	if err != nil {
		return generationFailure(controlplane.RunFailureInvalidInput)
	}
	for _, value := range []artifact.Artifact{sanitizedRequestArtifact, receiptArtifact} {
		if _, err := h.store.Put(ctx, value, started); err != nil {
			return generationFailure(generationStoreWriteFailure(ctx, err))
		}
	}
	reloadedRequest, err := h.store.Get(ctx, task.Plan().Scope(), sanitizedRequestArtifact.Identity(), started)
	if err != nil {
		return generationFailure(generationStoreReadFailure(ctx, err))
	}
	reloadedReceipt, err := h.store.Get(ctx, task.Plan().Scope(), receiptArtifact.Identity(), started)
	if err != nil {
		return generationFailure(generationStoreReadFailure(ctx, err))
	}
	if reloadedRequest.Identity() != sanitizedRequestArtifact.Identity() || reloadedReceipt.Identity() != receiptArtifact.Identity() ||
		review.ValidateSanitizedVerificationEgressArtifacts(
			verificationRequest, generation.ContextIdentity(), generation.Candidates().Identity(), generationArtifact, generationInputArtifact, generationContextArtifact,
			reloadedRequest, reloadedReceipt, h.expected,
		) != nil {
		return generationFailure(controlplane.RunFailureInvalidInput)
	}
	reloadedSanitized, parseErr := review.ParseSanitizedModelRequest(reloadedRequest.Payload())
	reloadedEgressReceipt, receiptErr := review.ParseSanitizedEgressReceipt(reloadedReceipt.Payload())
	dispatchRequest, requestErr := reloadedSanitized.ProviderRequest()
	if parseErr != nil || receiptErr != nil || requestErr != nil ||
		reloadedEgressReceipt.Identity() != receipt.Identity() ||
		dispatchRequest.Identity() != reloadedEgressReceipt.SanitizedRequestIdentity() {
		return generationFailure(controlplane.RunFailureInvalidInput)
	}
	authority, err := h.authorizer.Authorize(ctx, task.Plan().Scope(), dispatchRequest, generation.RouteExecution())
	if err != nil {
		if errors.Is(err, ErrVerificationAuthorizationUnavailable) {
			return generationFailure(controlplane.RunFailureTransient)
		}
		return generationFailure(controlplane.RunFailurePolicy)
	}
	if !authority.MatchesGeneration(dispatchRequest, generation.RouteExecution()) {
		return generationFailure(controlplane.RunFailurePolicy)
	}
	if _, acquired, err := gateway.ClaimRouteAttempt(ctx, h.ledger, task.Plan().Scope(), authority.Authorization(), started); err != nil || !acquired {
		return generationFailure(controlplane.RunFailureInternal)
	}
	dispatch, err := gateway.DispatchAuthorizedRouteFromCatalog(ctx, h.catalog, authority.Authorization(), dispatchRequest)
	if err != nil {
		return generationFailure(controlplane.RunFailurePolicy)
	}
	finished := h.clock.Now().UTC()
	duration, ok := boundedDurationMilliseconds(started, finished)
	if !ok {
		return generationFailure(controlplane.RunFailureInternal)
	}
	outcome, err := gateway.NewRouteAttemptOutcomeFromDispatch(authority.Authorization(), dispatch, duration)
	if err != nil {
		return generationFailure(controlplane.RunFailureInternal)
	}
	if _, err := gateway.RecordRouteDispatchCompleted(ctx, h.ledger, task.Plan().Scope(), authority.Authorization(), dispatch, outcome, finished); err != nil {
		return generationFailure(controlplane.RunFailureInternal)
	}
	reconciliation, err := gateway.ReconcileAuthorizedRouteAttemptCost(authority.Authorization(), outcome)
	if err != nil {
		return generationFailure(controlplane.RunFailureInternal)
	}
	if _, err := gateway.RecordRouteCostReconciliation(ctx, h.ledger, task.Plan().Scope(), authority.Authorization(), outcome, reconciliation, finished); err != nil {
		return generationFailure(controlplane.RunFailureInternal)
	}
	if reconciliation.Status() == gateway.RouteCostBudgetExceeded {
		return generationFailure(controlplane.RunFailurePolicy)
	}
	if dispatch.Status() == gateway.RouteDispatchFailed {
		return generationFailure(mapRouteFailure(dispatch.Failure()))
	}
	verification, err := review.ParseVerificationBatch(dispatch.Response(), generation.Candidates(), verificationContext.EvidenceItems())
	if err != nil {
		return generationFailure(controlplane.RunFailureInternal)
	}
	output, err := gateway.NewSuccessfulRouteOutputReceipt(gateway.RouteOutputVerificationBatch, verificationContext.Identity(), verification.Identity(), dispatchRequest, authority.Authorization(), outcome)
	if err != nil {
		return generationFailure(controlplane.RunFailureInternal)
	}
	routeExecution, err := gateway.NewRouteExecutionRecord(authority.Authorization(), outcome, reconciliation, output)
	if err != nil {
		return generationFailure(controlplane.RunFailureInternal)
	}
	independence, err := gateway.VerifyIndependentRouteAttempts(authority.IndependencePolicy(), generation.RouteExecution().Authorization(), generation.RouteExecution().Outcome(), authority.Authorization(), outcome)
	if err != nil {
		return generationFailure(controlplane.RunFailurePolicy)
	}
	independent, err := review.NewIndependentVerificationReceiptFromRecords(review.IndependentVerificationRecords{ReviewScopeIdentity: task.Plan().Scope().Identity(), SnapshotIdentity: generation.Candidates().SnapshotIdentity(), GenerationContextIdentity: generation.ContextIdentity(), VerificationContextIdentity: verificationContext.Identity(), GenerationRequestIdentity: generation.RouteExecution().Authorization().RequestIdentity(), VerificationRequestIdentity: dispatchRequest.Identity(), Candidates: generation.Candidates(), CandidateOutput: generation.RouteExecution().Output(), Verification: verification, VerificationOutput: output, RouteIndependence: independence})
	if err != nil {
		return generationFailure(controlplane.RunFailureInternal)
	}
	findings, err := review.PromoteVerifiedCandidates(independent, generation.Candidates(), verification)
	if err != nil {
		return generationFailure(controlplane.RunFailureInternal)
	}
	egress, err := newVerificationEgressBinding(verificationRequest, dispatchRequest, reloadedRequest, reloadedReceipt, reloadedEgressReceipt, h.sanitizerIdentity, h.expected)
	if err != nil {
		return generationFailure(controlplane.RunFailureInternal)
	}
	result, err := newSanitizedVerificationResult(generationArtifact.Identity(), verificationContext, verification, routeExecution, independence, independent, findings, egress)
	if err != nil {
		return generationFailure(controlplane.RunFailureInternal)
	}
	payload, err := encodeVerificationResult(result)
	if err != nil {
		return generationFailure(controlplane.RunFailureResourceLimit)
	}
	provenance := []string{generationArtifact.Identity(), generationInputArtifact.Identity(), generationContextArtifact.Identity(), reloadedRequest.Identity(), reloadedReceipt.Identity(), reloadedEgressReceipt.Identity(), dispatchRequest.Identity(), verification.Identity(), routeExecution.Identity(), authority.Authorization().SelectionReceiptIdentity(), authority.Authorization().Identity(), outcome.Identity(), reconciliation.Identity(), output.Identity(), independence.Identity(), independent.Identity(), findings.Identity()}
	sort.Strings(provenance)
	outputArtifact, err := artifact.New(task.Plan().Scope(), artifact.KindVerifiedFindingSet, "application/json", generationArtifact.Classification(), artifact.OriginIndependentVerifier, generationArtifact.Protection(), provenance, payload, finished, generationArtifact.ExpiresAt())
	if err != nil {
		return generationFailure(controlplane.RunFailureResourceLimit)
	}
	if _, err := h.store.Put(ctx, outputArtifact, finished); err != nil {
		return generationFailure(generationStoreWriteFailure(ctx, err))
	}
	completion, err := controlplane.NewTaskSuccess(outputArtifact.Identity())
	if err != nil {
		return generationFailure(controlplane.RunFailureInternal)
	}
	return completion
}
func (h *VerificationHandler) String() string   { return "model verification task handler" }
func (h *VerificationHandler) GoString() string { return "model.VerificationHandler{<redacted>}" }
func (h *VerificationHandler) Format(state fmt.State, verb rune) {
	writeModelRedacted(state, verb, "model verification task handler", "model.VerificationHandler{<redacted>}")
}

var _ controlplane.TaskHandler = (*VerificationHandler)(nil)
