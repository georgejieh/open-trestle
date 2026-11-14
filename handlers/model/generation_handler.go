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
	"github.com/georgejieh/open-trestle/internal/secretscan"
)

// GenerationHandler dispatches one authorized model attempt and admits candidate output.
type GenerationHandler struct {
	identity          string
	store             artifact.Store
	catalog           gateway.RouteDispatcherCatalog
	ledger            audit.Ledger
	clock             artifact.Clock
	expected          review.ScannerBinaryDigests
	requiresSanitized bool
	// wait waits out a rate-limit retry delay; nil waits on a timer.
	wait routeWait
}

// NewGenerationHandler binds exact dispatchers, audit ledger, and protected storage.
func NewGenerationHandler(
	store artifact.Store,
	catalog gateway.RouteDispatcherCatalog,
	ledger audit.Ledger,
	clock artifact.Clock,
	expected review.ScannerBinaryDigests,
) (*GenerationHandler, error) {
	return newGenerationHandler(store, catalog, ledger, clock, expected, true)
}

func newLegacyGenerationHandler(store artifact.Store, catalog gateway.RouteDispatcherCatalog, ledger audit.Ledger, clock artifact.Clock) (*GenerationHandler, error) {
	return newGenerationHandler(store, catalog, ledger, clock, review.ScannerBinaryDigests{}, false)
}

func newGenerationHandler(store artifact.Store, catalog gateway.RouteDispatcherCatalog, ledger audit.Ledger, clock artifact.Clock, digests review.ScannerBinaryDigests, requiresSanitized bool) (*GenerationHandler, error) {
	if nilInterface(store) || catalog.Validate() != nil || nilInterface(ledger) || nilInterface(clock) {
		return nil, ErrInvalidGenerationHandler
	}
	handler := &GenerationHandler{store: store, catalog: catalog, ledger: ledger, clock: clock, expected: digests, requiresSanitized: requiresSanitized}
	handler.identity = deriveGenerationHandlerIdentity(catalog.Identity(), digests, handler.requiresSanitized)
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
		h.identity != deriveGenerationHandlerIdentity(h.catalog.Identity(), h.expected, h.requiresSanitized) {
		return ErrInvalidGenerationHandler
	}
	return nil
}

// SanitizedGenerationHandlerIdentity derives the sanitized handler identity without
// constructing a store, ledger, clock, or dispatching a provider request. It does
// not enroll a handler or validate scanner files at the configured digests.
func SanitizedGenerationHandlerIdentity(catalog gateway.RouteDispatcherCatalog, expected review.ScannerBinaryDigests) (string, error) {
	if catalog.Validate() != nil {
		return "", ErrInvalidGenerationHandler
	}
	return deriveGenerationHandlerIdentity(catalog.Identity(), expected, true), nil
}

func deriveGenerationHandlerIdentity(catalogIdentity string, expected review.ScannerBinaryDigests, requiresSanitized bool) string {
	if !validDigest(catalogIdentity) {
		return ""
	}
	schemaVersion := 3
	if requiresSanitized {
		schemaVersion = 4
	}
	encoded, err := json.Marshal(struct {
		Contract           string `json:"contract"`
		SchemaVersion      int    `json:"schema_version"`
		DispatcherCatalog  string `json:"dispatcher_catalog"`
		LauncherSHA256     string `json:"launcher_sha256,omitempty"`
		WorkerSHA256       string `json:"worker_sha256,omitempty"`
		RequiresSanitized  bool   `json:"requires_sanitized"`
		SanitizationPolicy string `json:"sanitization_policy"`
		Scanner            string `json:"scanner"`
		BuildProfile       string `json:"build_profile"`
	}{"open-trestle/model-generation-handler", schemaVersion, catalogIdentity, expected.LauncherSHA256, expected.WorkerSHA256, requiresSanitized, review.SanitizationPolicyIdentity, secretscan.ScannerName, secretscan.BuildProfile})
	if err != nil {
		return ""
	}
	if requiresSanitized {
		encoded, err = json.Marshal(struct {
			Contract string          `json:"contract"`
			Version  int             `json:"version"`
			Handler  json.RawMessage `json:"handler"`
		}{"open-trestle/repository-scoped-generation-handler", 1, encoded})
		if err != nil {
			return ""
		}
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

// Execute performs one task attempt. Control-plane retry authority is rejected;
// within the attempt a request the provider rate-limited is retried on the
// same route at most twice (settleRouteAttempts).
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
	if err != nil || input.IsSanitized() != h.requiresSanitized || input.ReviewScopeIdentity() != task.Plan().Scope().Identity() ||
		!hasProvenance(inputArtifact.Provenance(), input.ContextArtifactIdentity()) ||
		!hasProvenance(inputArtifact.Provenance(), input.Authorization().Identity()) {
		return generationFailure(controlplane.RunFailureInvalidInput)
	}
	if input.IsSanitized() && (!hasProvenance(inputArtifact.Provenance(), input.SanitizedRequestArtifactIdentity()) || !hasProvenance(inputArtifact.Provenance(), input.SanitizedEgressReceiptArtifactIdentity())) {
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
	); err != nil || !contextOutputSchemaMatches(input, contextArtifact.Payload()) {
		return generationFailure(controlplane.RunFailureInvalidInput)
	}
	var providerRequest provider.Request
	var dispatchProof SanitizedDispatchProof
	if input.IsSanitized() {
		requestArtifact, err := h.store.Get(ctx, task.Plan().Scope(), input.SanitizedRequestArtifactIdentity(), started)
		if err != nil {
			return generationFailure(generationStoreReadFailure(ctx, err))
		}
		receiptArtifact, err := h.store.Get(ctx, task.Plan().Scope(), input.SanitizedEgressReceiptArtifactIdentity(), started)
		if err != nil {
			return generationFailure(generationStoreReadFailure(ctx, err))
		}
		if review.ValidateSanitizedEgressArtifacts(contextArtifact, requestArtifact, receiptArtifact, h.expected) != nil {
			return generationFailure(controlplane.RunFailureInvalidInput)
		}
		sanitized, err := review.ParseSanitizedModelRequest(requestArtifact.Payload())
		receipt, receiptErr := review.ParseSanitizedEgressReceipt(receiptArtifact.Payload())
		sanitizedProviderRequest, requestErr := sanitized.ProviderRequest()
		providerRequest = sanitizedProviderRequest
		if err != nil || receiptErr != nil || requestErr != nil || receipt.Identity() != input.SanitizedEgressReceiptIdentity() || providerRequest.Identity() != receipt.SanitizedRequestIdentity() || providerRequest.Identity() != input.Authorization().RequestIdentity() {
			return generationFailure(controlplane.RunFailureInvalidInput)
		}
		dispatchProof, err = newGenerationDispatchProof(contextArtifact, requestArtifact, receiptArtifact, h.expected)
		if err != nil {
			return generationFailure(controlplane.RunFailureInvalidInput)
		}
		dispatchProof, err = bindSanitizedDispatchProofScope(dispatchProof, task.Plan().Scope())
		if err != nil {
			return generationFailure(controlplane.RunFailureInvalidInput)
		}
	} else {
		providerRequest, err = provider.NewRequest(provider.CapabilityReviewV1, contextArtifact.MediaType(), contextArtifact.Payload())
		if err != nil || providerRequest.Identity() != input.Authorization().RequestIdentity() || input.Authorization().RouteReference().Zone() != provider.ProviderZoneLocal {
			return generationFailure(controlplane.RunFailureInvalidInput)
		}
	}
	dispatch := func(ctx context.Context, authorization gateway.RouteAttemptAuthorization) (gateway.RouteDispatchResult, error) {
		if input.IsSanitized() {
			return dispatchAuthorizedSanitizedRouteFromCatalog(ctx, h.catalog, authorization, providerRequest, dispatchProof)
		}
		return gateway.DispatchAuthorizedRouteFromCatalog(ctx, h.catalog, authorization, providerRequest)
	}
	attempt, failed, settled := settleRouteAttempts(ctx, task, h.ledger, h.clock, h.wait, input.Authorization(), started, dispatch)
	if !settled {
		return failed
	}
	// After a rate-limited retry the last attempt holds its own authorization.
	authorization, dispatchResult, outcome, reconciliation, finished := attempt.authorization, attempt.result, attempt.outcome, attempt.reconciliation, attempt.finished
	if dispatchResult.Status() == gateway.RouteDispatchFailed {
		return routeFailureCompletion(task, dispatchResult)
	}
	// The context version selects the candidate schema and identifies
	// repository_context sources that cannot anchor a candidate.
	candidates, err := review.ParseContextCandidateBatch(
		dispatchResult.Response(), contextArtifact.Payload(), input.Snapshot(), input.EvidenceItems(),
	)
	if err != nil {
		if errors.Is(err, review.ErrInvalidCandidateDocumentShape) {
			// Failure to persist the witness remains an unproven internal failure.
			_ = h.recordDocumentShapeRejection(ctx, task, inputArtifact, contextArtifact, input, authorization, outcome, reconciliation)
		}
		return answerFailureCompletion(task, dispatchResult.Response(), err)
	}
	outputReceipt, err := gateway.NewSuccessfulRouteOutputReceipt(
		gateway.RouteOutputCandidateBatch, input.ContextIdentity(), candidates.Identity(),
		providerRequest, authorization, outcome,
	)
	if err != nil {
		return generationFailure(controlplane.RunFailureInternal)
	}
	routeExecution, err := gateway.NewRouteExecutionRecord(
		authorization, outcome, reconciliation, outputReceipt,
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
		authorization.Identity(), outcome.Identity(), reconciliation.Identity(),
		outputReceipt.Identity(), routeExecution.Identity(),
	}
	if authorization.Identity() != input.Authorization().Identity() {
		provenance = append(provenance, input.Authorization().Identity())
	}
	if input.IsSanitized() {
		provenance = append(provenance, input.SanitizedRequestArtifactIdentity(), input.SanitizedEgressReceiptArtifactIdentity())
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
		gateway.RouteFailurePolicyDenied, gateway.RouteFailureBudgetExhausted,
		gateway.RouteFailurePaymentRequired, gateway.RouteFailureModelUnavailable,
		gateway.RouteFailureModelRetired, gateway.RouteFailureRequestRejected:
		// A provider refusal of the account, credential, model or request
		// repeats on every replay; it is refused, not retried as an internal
		// failure.
		return controlplane.RunFailurePolicy
	case gateway.RouteFailureCancelled:
		return controlplane.RunFailureCanceled
	case gateway.RouteFailureInvalidResponse:
		return controlplane.RunFailureInternal
	case gateway.RouteFailureOutputExhausted:
		// The closed run failure set has no output-allowance class. The run keeps
		// the internal failure; hosts that observe the route class report it as
		// a separate detail (localreview failure_detail model_output_exhausted).
		return controlplane.RunFailureInternal
	default:
		return controlplane.RunFailureInternal
	}
}

// providerRefusalReasons names each provider refusal class, and a provider
// reply the adapter refused, as the model task's content-free failure reason.
var providerRefusalReasons = map[gateway.RouteFailureClass]controlplane.TaskFailureReason{
	gateway.RouteFailurePaymentRequired:  controlplane.TaskFailureReasonProviderPaymentRequired,
	gateway.RouteFailureModelUnavailable: controlplane.TaskFailureReasonProviderModelUnavailable,
	gateway.RouteFailureModelRetired:     controlplane.TaskFailureReasonProviderModelRetired,
	gateway.RouteFailureAuthentication:   controlplane.TaskFailureReasonProviderAuthenticationFailed,
	gateway.RouteFailureAuthorization:    controlplane.TaskFailureReasonProviderAuthorizationDenied,
	gateway.RouteFailureRateLimited:      controlplane.TaskFailureReasonProviderRateLimited,
	gateway.RouteFailureInvalidResponse:  controlplane.TaskFailureReasonProviderResponseInvalid,
}

// routeFailureCompletion fails a model task for a failed dispatch. A refusal
// the provider answered, or an answer whose reply the adapter refused,
// records its content-free reason; any other failure, or one before the
// request was sent, records only the run failure. A rate limit reaches it
// only once its same-route retries are spent or not allowed.
func routeFailureCompletion(task controlplane.TaskExecutionRequest, result gateway.RouteDispatchResult) controlplane.TaskCompletion {
	failure := mapRouteFailure(result.Failure())
	reason, refusal := providerRefusalReasons[result.Failure()]
	if !refusal || result.ReplaySafety() == gateway.RouteReplayNotDispatched {
		return generationFailure(failure)
	}
	completion, err := controlplane.NewModelTaskFailureWithReason(failure, reason, task.Plan(), task.Task())
	if err != nil {
		return generationFailure(failure)
	}
	return completion
}

// answerFailureCompletion fails a model task whose accepted reply the review
// parser refused. A reply that stopped normally and whose answer caused the
// refusal records model_output_invalid; a host input check, or a reply that
// stopped at the output limit or a content filter, records only the internal
// failure. The answer itself is never recorded.
func answerFailureCompletion(task controlplane.TaskExecutionRequest, response provider.Response, err error) controlplane.TaskCompletion {
	if !errors.Is(err, review.ErrModelOutputInvalid) || response.FinishReason() != provider.ResponseFinishStop {
		return generationFailure(controlplane.RunFailureInternal)
	}
	completion, err := controlplane.NewModelTaskFailureWithReason(controlplane.RunFailureInternal, controlplane.TaskFailureReasonModelOutputInvalid, task.Plan(), task.Task())
	if err != nil {
		return generationFailure(controlplane.RunFailureInternal)
	}
	return completion
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
