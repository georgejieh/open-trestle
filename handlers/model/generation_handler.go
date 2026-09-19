package model

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
)

// GenerationHandler dispatches one authorized model attempt and admits candidate output.
type GenerationHandler struct {
	identity string
	store    artifact.Store
	catalog  gateway.RouteDispatcherCatalog
	ledger   audit.Ledger
	clock    artifact.Clock
}

// NewGenerationHandler binds exact dispatchers, audit ledger, and protected storage.
func NewGenerationHandler(
	store artifact.Store,
	catalog gateway.RouteDispatcherCatalog,
	ledger audit.Ledger,
	clock artifact.Clock,
) (*GenerationHandler, error) {
	if nilInterface(store) || catalog.Validate() != nil || nilInterface(ledger) || nilInterface(clock) {
		return nil, ErrInvalidGenerationHandler
	}
	handler := &GenerationHandler{store: store, catalog: catalog, ledger: ledger, clock: clock}
	handler.identity = deriveGenerationHandlerIdentity(catalog.Identity())
	if err := handler.Validate(); err != nil {
		return nil, err
	}
	return handler, nil
}

func (h *GenerationHandler) HandlerIdentity() string {
	if h == nil {
		return ""
	}
	return h.identity
}
func (h *GenerationHandler) Kind() controlplane.TaskKind {
	if h == nil {
		return 0
	}
	return controlplane.TaskGenerateCandidates
}

// Validate verifies the exact dispatcher-set and handler identity.
func (h *GenerationHandler) Validate() error {
	if h == nil || nilInterface(h.store) || h.catalog.Validate() != nil ||
		nilInterface(h.ledger) || nilInterface(h.clock) ||
		h.identity != deriveGenerationHandlerIdentity(h.catalog.Identity()) {
		return ErrInvalidGenerationHandler
	}
	return nil
}

func deriveGenerationHandlerIdentity(catalogIdentity string) string {
	if !validDigest(catalogIdentity) {
		return ""
	}
	encoded, err := json.Marshal(struct {
		Contract          string `json:"contract"`
		SchemaVersion     int    `json:"schema_version"`
		DispatcherCatalog string `json:"dispatcher_catalog"`
	}{"open-trestle/model-generation-handler", 2, catalogIdentity})
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

// Execute performs exactly one provider attempt. Control-plane retry authority is rejected.
func (h *GenerationHandler) Execute(ctx context.Context, task controlplane.TaskExecutionRequest) controlplane.TaskCompletion {
	if nilInterface(ctx) || h == nil || h.Validate() != nil || task.Validate() != nil ||
		task.Task().Kind() != controlplane.TaskGenerateCandidates ||
		task.Task().HandlerIdentity() != h.identity {
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
	contextDependency, exists := task.DependencyOutput("context")
	if !exists || !contextDependency.Available() {
		return generationFailure(controlplane.RunFailureInvalidInput)
	}
	inputArtifact, err := h.store.Get(ctx, task.Plan().Scope(), contextDependency.OutputIdentity(), started)
	if err != nil {
		return generationFailure(generationStoreReadFailure(ctx, err))
	}
	if inputArtifact.Kind() != artifact.KindTaskInput || inputArtifact.MediaType() != "application/json" ||
		inputArtifact.Origin() != artifact.OriginHost {
		return generationFailure(controlplane.RunFailureInvalidInput)
	}
	input, err := ParseGenerationInput(inputArtifact.Payload())
	if err != nil || input.ReviewScopeIdentity() != task.Plan().Scope().Identity() ||
		!hasProvenance(inputArtifact.Provenance(), input.ContextArtifactIdentity()) ||
		!hasProvenance(inputArtifact.Provenance(), input.Authorization().Identity()) {
		return generationFailure(controlplane.RunFailureInvalidInput)
	}
	contextArtifact, err := h.store.Get(ctx, task.Plan().Scope(), input.ContextArtifactIdentity(), started)
	if err != nil {
		return generationFailure(generationStoreReadFailure(ctx, err))
	}
	if contextArtifact.Kind() != artifact.KindContextPacket || contextArtifact.MediaType() != "application/json" ||
		contextArtifact.Origin() != artifact.OriginHost ||
		contextArtifact.Classification() != inputArtifact.Classification() ||
		contextArtifact.Protection() != inputArtifact.Protection() {
		return generationFailure(controlplane.RunFailureInvalidInput)
	}
	if err := review.ValidateContextPacketRequest(
		contextArtifact.Payload(), input.ContextIdentity(), task.Plan().Scope().Identity(), input.MemoryScopeIdentity(), input.MemoryIdentity(),
		input.Snapshot(), input.EvidenceItems(),
	); err != nil {
		return generationFailure(controlplane.RunFailureInvalidInput)
	}
	providerRequest, err := provider.NewRequest(
		provider.CapabilityReviewV1, contextArtifact.MediaType(), contextArtifact.Payload(),
	)
	if err != nil || providerRequest.Identity() != input.Authorization().RequestIdentity() {
		return generationFailure(controlplane.RunFailureInvalidInput)
	}
	if _, acquired, err := gateway.ClaimRouteAttempt(ctx, h.ledger, task.Plan().Scope(), input.Authorization(), started); err != nil || !acquired {
		return generationFailure(controlplane.RunFailureInternal)
	}
	dispatchResult, err := gateway.DispatchAuthorizedRouteFromCatalog(
		ctx, h.catalog, input.Authorization(), providerRequest,
	)
	if err != nil {
		return generationFailure(controlplane.RunFailurePolicy)
	}
	finished := h.clock.Now().UTC()
	duration, ok := boundedDurationMilliseconds(started, finished)
	if !ok {
		return generationFailure(controlplane.RunFailureInternal)
	}
	outcome, err := gateway.NewRouteAttemptOutcomeFromDispatch(input.Authorization(), dispatchResult, duration)
	if err != nil {
		return generationFailure(controlplane.RunFailureInternal)
	}
	if _, err := gateway.RecordRouteDispatchCompleted(
		ctx, h.ledger, task.Plan().Scope(), input.Authorization(), dispatchResult, outcome, finished,
	); err != nil {
		return generationFailure(controlplane.RunFailureInternal)
	}
	reconciliation, err := gateway.ReconcileAuthorizedRouteAttemptCost(input.Authorization(), outcome)
	if err != nil {
		return generationFailure(controlplane.RunFailureInternal)
	}
	if _, err := gateway.RecordRouteCostReconciliation(
		ctx, h.ledger, task.Plan().Scope(), input.Authorization(), outcome, reconciliation, finished,
	); err != nil {
		return generationFailure(controlplane.RunFailureInternal)
	}
	if reconciliation.Status() == gateway.RouteCostBudgetExceeded {
		return generationFailure(controlplane.RunFailurePolicy)
	}
	if dispatchResult.Status() == gateway.RouteDispatchFailed {
		return generationFailure(mapRouteFailure(dispatchResult.Failure()))
	}
	candidates, err := review.ParseCandidateBatch(
		dispatchResult.Response(), input.Snapshot(), input.EvidenceItems(),
	)
	if err != nil {
		return generationFailure(controlplane.RunFailureInternal)
	}
	outputReceipt, err := gateway.NewSuccessfulRouteOutputReceipt(
		gateway.RouteOutputCandidateBatch, input.ContextIdentity(), candidates.Identity(),
		providerRequest, input.Authorization(), outcome,
	)
	if err != nil {
		return generationFailure(controlplane.RunFailureInternal)
	}
	routeExecution, err := gateway.NewRouteExecutionRecord(
		input.Authorization(), outcome, reconciliation, outputReceipt,
	)
	if err != nil {
		return generationFailure(controlplane.RunFailureInternal)
	}
	result, err := newGenerationResult(
		inputArtifact.Identity(), contextArtifact.Identity(), input.ContextIdentity(), candidates, routeExecution,
	)
	if err != nil {
		return generationFailure(controlplane.RunFailureInternal)
	}
	payload, err := encodeGenerationResult(result)
	if err != nil {
		return generationFailure(controlplane.RunFailureResourceLimit)
	}
	provenance := []string{
		inputArtifact.Identity(), contextArtifact.Identity(), candidates.Identity(),
		input.Authorization().Identity(), outcome.Identity(), reconciliation.Identity(),
		outputReceipt.Identity(), routeExecution.Identity(),
	}
	sort.Strings(provenance)
	outputArtifact, err := artifact.New(
		task.Plan().Scope(), artifact.KindCandidateBatch, "application/json",
		contextArtifact.Classification(), artifact.OriginModel, contextArtifact.Protection(),
		provenance, payload, finished, contextArtifact.ExpiresAt(),
	)
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

func boundedDurationMilliseconds(started, finished time.Time) (uint64, bool) {
	if finished.Before(started) {
		return 0, false
	}
	duration := finished.Sub(started)
	if duration > 24*time.Hour {
		return 0, false
	}
	return uint64(duration.Milliseconds()), true
}

func mapRouteFailure(failure gateway.RouteFailureClass) controlplane.RunFailure {
	switch failure {
	case gateway.RouteFailureTransport, gateway.RouteFailureRateLimited,
		gateway.RouteFailureProviderServer, gateway.RouteFailureTimeout,
		gateway.RouteFailureConnection:
		return controlplane.RunFailureTransient
	case gateway.RouteFailureAuthentication, gateway.RouteFailureAuthorization,
		gateway.RouteFailurePolicyDenied, gateway.RouteFailureBudgetExhausted:
		return controlplane.RunFailurePolicy
	case gateway.RouteFailureCancelled:
		return controlplane.RunFailureCanceled
	case gateway.RouteFailureInvalidResponse:
		return controlplane.RunFailureInternal
	default:
		return controlplane.RunFailureInternal
	}
}

func generationStoreReadFailure(ctx context.Context, err error) controlplane.RunFailure {
	if ctx.Err() != nil {
		return controlplane.RunFailureCanceled
	}
	if errors.Is(err, artifact.ErrArtifactNotFound) || errors.Is(err, artifact.ErrArtifactExpired) {
		return controlplane.RunFailureInvalidInput
	}
	return controlplane.RunFailureInternal
}

func generationStoreWriteFailure(ctx context.Context, err error) controlplane.RunFailure {
	if ctx.Err() != nil {
		return controlplane.RunFailureCanceled
	}
	if errors.Is(err, artifact.ErrStoreCapacity) {
		return controlplane.RunFailureResourceLimit
	}
	return controlplane.RunFailureInternal
}

func generationFailure(failure controlplane.RunFailure) controlplane.TaskCompletion {
	completion, _ := controlplane.NewTaskFailure(failure)
	return completion
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func (h *GenerationHandler) String() string   { return "model generation task handler" }
func (h *GenerationHandler) GoString() string { return "model.GenerationHandler{<redacted>}" }
func (h *GenerationHandler) Format(state fmt.State, verb rune) {
	writeModelRedacted(state, verb, "model generation task handler", "model.GenerationHandler{<redacted>}")
}

var _ controlplane.TaskHandler = (*GenerationHandler)(nil)
