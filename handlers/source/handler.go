package source

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/scm"
	"github.com/georgejieh/open-trestle/internal/sourceoutput"
)

// Handler acquires one exact repository revision and persists protected source artifacts.
type Handler struct {
	identity, sourceRootIdentity string
	store                        artifact.Store
	adapter                      scm.SourceAdapter
	clock                        artifact.Clock
}

// NewHandler binds one exact source adapter to a protected artifact store.
func NewHandler(store artifact.Store, adapter scm.SourceAdapter, clock artifact.Clock) (*Handler, error) {
	return newHandler(store, adapter, "", clock)
}

// NewHandlerWithSourceRoot binds the handler to one retained daemon source-root authority.
func NewHandlerWithSourceRoot(store artifact.Store, adapter scm.SourceAdapter, sourceRootIdentity string, clock artifact.Clock) (*Handler, error) {
	if !validSourceDigest(sourceRootIdentity) {
		return nil, ErrInvalidHandler
	}
	return newHandler(store, adapter, sourceRootIdentity, clock)
}
func newHandler(store artifact.Store, adapter scm.SourceAdapter, sourceRootIdentity string, clock artifact.Clock) (*Handler, error) {
	if nilInterface(store) || nilInterface(adapter) || nilInterface(clock) {
		return nil, ErrInvalidHandler
	}
	if !canonicalAdapter(adapter.Identity()) {
		return nil, ErrInvalidHandler
	}
	handler := &Handler{store: store, adapter: adapter, sourceRootIdentity: sourceRootIdentity, clock: clock}
	handler.identity = deriveHandlerIdentity(adapter.Identity(), sourceRootIdentity)
	if err := handler.Validate(); err != nil {
		return nil, err
	}
	return handler, nil
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
	return controlplane.TaskAcquireSource
}

// Validate verifies dependencies, adapter identity, and handler identity.
func (h *Handler) Validate() error {
	if h == nil || nilInterface(h.store) || nilInterface(h.adapter) || nilInterface(h.clock) ||
		!canonicalAdapter(h.adapter.Identity()) || h.identity != deriveHandlerIdentity(h.adapter.Identity(), h.sourceRootIdentity) {
		return ErrInvalidHandler
	}
	return nil
}

func validSourceDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value && strings.Trim(value, "0") != ""
}

func canonicalAdapter(value evidence.SourceAdapterIdentity) bool {
	canonical, err := evidence.NewSourceAdapterIdentity(value.Kind(), value.Name(), value.Version(), value.Capabilities())
	return err == nil && sameAdapterIdentity(canonical, value) &&
		canonical.HasCapability(evidence.SourceCapabilityReadManifest) &&
		canonical.HasCapability(evidence.SourceCapabilityReadContent)
}

func deriveHandlerIdentity(adapter evidence.SourceAdapterIdentity, sourceRootIdentity string) string {
	var encoded []byte
	var err error
	if sourceRootIdentity == "" {
		encoded, err = json.Marshal(struct {
			Contract              string `json:"contract"`
			SchemaVersion         int    `json:"schema_version"`
			SourceAdapterIdentity string `json:"source_adapter_identity"`
		}{"open-trestle/source-acquisition-handler", 1, adapter.Identity()})
	} else {
		encoded, err = json.Marshal(struct {
			Contract              string `json:"contract"`
			SchemaVersion         int    `json:"schema_version"`
			SourceAdapterIdentity string `json:"source_adapter_identity"`
			SourceRootIdentity    string `json:"source_root_identity"`
		}{"open-trestle/source-acquisition-handler", 2, adapter.Identity(), sourceRootIdentity})
	}
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

// Execute reads exact task authority, acquires content, and persists one snapshot index.
func (h *Handler) Execute(ctx context.Context, request controlplane.TaskExecutionRequest) controlplane.TaskCompletion {
	if nilInterface(ctx) || h == nil || h.Validate() != nil || request.Validate() != nil ||
		request.Task().Kind() != controlplane.TaskAcquireSource ||
		request.Task().HandlerIdentity() != h.identity {
		return taskFailure(controlplane.RunFailureInvalidInput)
	}
	if ctx.Err() != nil {
		return taskFailure(controlplane.RunFailureCanceled)
	}
	now := h.clock.Now().UTC()
	if now.UnixMilli() <= 0 || now.After(request.Lease().ExpiresAt()) {
		return taskFailure(controlplane.RunFailureCanceled)
	}
	inputArtifact, err := h.store.Get(ctx, request.Plan().Scope(), request.Task().InputIdentity(), now)
	if err != nil {
		return taskFailure(storeReadFailure(ctx, err))
	}
	if inputArtifact.Kind() != artifact.KindTaskInput || inputArtifact.MediaType() != "application/json" ||
		inputArtifact.Origin() != artifact.OriginHost {
		return taskFailure(controlplane.RunFailureInvalidInput)
	}
	input, err := ParseInput(inputArtifact.Payload())
	if err != nil {
		return taskFailure(controlplane.RunFailureInvalidInput)
	}
	if !sameAdapterIdentity(input.Adapter(), h.adapter.Identity()) || input.SourceRootIdentity() != h.sourceRootIdentity {
		return taskFailure(controlplane.RunFailurePolicy)
	}
	revision := input.Revision()
	var derivation sourceoutput.RevisionDerivation
	if head, derived := input.MergeBaseHead(); derived {
		mergeBase, refusal, resolved := h.resolveMergeBase(ctx, request, input, head)
		if !resolved {
			return refusal
		}
		if derivation, err = sourceoutput.NewForgeMergeBaseDerivation(input.Revision(), head, mergeBase); err != nil {
			return taskFailure(controlplane.RunFailureInternal)
		}
		revision = mergeBase
	}
	acquisitionRequest, err := evidence.NewRepositoryAcquisitionRequest(
		input.Repository(), revision, input.Adapter(),
		evidence.AcquisitionArtifactManifestAndContent,
		evidence.AcquisitionEffectReadOnly,
	)
	if err != nil {
		return taskFailure(controlplane.RunFailureInvalidInput)
	}
	snapshot, err := scm.ExecuteRepositoryAcquisitionSnapshot(ctx, acquisitionRequest, h.adapter)
	if err != nil {
		if ctx.Err() != nil {
			return taskFailure(controlplane.RunFailureCanceled)
		}
		return taskFailure(controlplane.RunFailureInternal)
	}
	if snapshot.Execution().Outcome() != evidence.AcquisitionOutcomeAcquired {
		return taskFailure(mapAcquisitionFailure(snapshot.Execution().Receipt().Reason()))
	}
	return h.persistSnapshot(ctx, request, inputArtifact, input, revision, derivation, snapshot, now)
}

// resolveMergeBase asks the adapter for the forge's merge base of the
// requested base and the head. Every refusal is a failed completion with a
// recorded, content-free reason: no shared history, nothing to review because
// the head equals or is contained in the base, or no usable merge base.
func (h *Handler) resolveMergeBase(ctx context.Context, request controlplane.TaskExecutionRequest, input Input, head evidence.RevisionIdentity) (evidence.RevisionIdentity, controlplane.TaskCompletion, bool) {
	refuse := func(failure controlplane.RunFailure, reason controlplane.TaskFailureReason) (evidence.RevisionIdentity, controlplane.TaskCompletion, bool) {
		completion, err := controlplane.NewSourceTaskFailureWithReason(failure, reason, request.Plan(), request.Task())
		if err != nil {
			return evidence.RevisionIdentity{}, taskFailure(controlplane.RunFailureInternal), false
		}
		return evidence.RevisionIdentity{}, completion, false
	}
	if input.Revision() == head {
		return refuse(controlplane.RunFailurePolicy, controlplane.TaskFailureReasonNothingToReview)
	}
	resolver, ok := h.adapter.(scm.MergeBaseResolver)
	if !ok {
		return refuse(controlplane.RunFailurePolicy, controlplane.TaskFailureReasonMergeBaseUnavailable)
	}
	mergeBaseRequest, err := scm.NewMergeBaseRequest(input.Repository(), input.Revision(), head, input.Adapter())
	if err != nil {
		return evidence.RevisionIdentity{}, taskFailure(controlplane.RunFailureInvalidInput), false
	}
	result := resolver.ResolveMergeBase(ctx, mergeBaseRequest)
	if ctx.Err() != nil {
		return evidence.RevisionIdentity{}, taskFailure(controlplane.RunFailureCanceled), false
	}
	if scm.ValidateMergeBaseResult(mergeBaseRequest, result) != nil {
		return refuse(controlplane.RunFailureInternal, controlplane.TaskFailureReasonMergeBaseUnavailable)
	}
	switch result.Outcome {
	case scm.MergeBaseNone:
		return refuse(controlplane.RunFailurePolicy, controlplane.TaskFailureReasonNoMergeBase)
	case scm.MergeBaseUnavailable:
		return refuse(mapAcquisitionFailure(result.Reason), controlplane.TaskFailureReasonMergeBaseUnavailable)
	}
	if result.MergeBase == head {
		return refuse(controlplane.RunFailurePolicy, controlplane.TaskFailureReasonNothingToReview)
	}
	return result.MergeBase, controlplane.TaskCompletion{}, true
}

func (h *Handler) persistSnapshot(
	ctx context.Context,
	request controlplane.TaskExecutionRequest,
	inputArtifact artifact.Artifact,
	input Input,
	revision evidence.RevisionIdentity,
	derivation sourceoutput.RevisionDerivation,
	snapshot scm.RepositoryAcquisitionSnapshotExecution,
	now time.Time,
) controlplane.TaskCompletion {
	execution := snapshot.Execution()
	contents := snapshot.Contents()
	defer clearContents(contents)
	manifest := snapshot.Manifest()
	files := manifest.Files()
	references := make([]FileReference, 0, len(files))
	provenance := []string{inputArtifact.Identity(), execution.Identity()}
	for _, file := range files {
		if ctx.Err() != nil {
			return taskFailure(controlplane.RunFailureCanceled)
		}
		content, exists := contents[file.Path()]
		if !exists {
			return taskFailure(controlplane.RunFailureInternal)
		}
		payload, err := sourceoutput.EncodeFile(execution.Identity(), file, content)
		if err != nil {
			return taskFailure(controlplane.RunFailureResourceLimit)
		}
		value, err := artifact.New(
			request.Plan().Scope(), artifact.KindSourceFile, "application/json",
			inputArtifact.Classification(), artifact.OriginRepository, inputArtifact.Protection(),
			provenance, payload, now, inputArtifact.ExpiresAt(),
		)
		if err != nil {
			return taskFailure(controlplane.RunFailureResourceLimit)
		}
		if _, err := h.store.Put(ctx, value, now); err != nil {
			return taskFailure(storeWriteFailure(ctx, err))
		}
		references = append(references, sourceoutput.NewFileReference(file.Path(), file.Digest(), file.SizeBytes(), value.Identity()))
	}
	sort.Slice(references, func(first, second int) bool { return references[first].Path() < references[second].Path() })
	var index sourceoutput.Snapshot
	var err error
	if derivation.Method() != "" {
		index, err = sourceoutput.NewDerivedSnapshot(
			"", execution.RequestIdentity(), execution.ReceiptIdentity(),
			execution.Identity(), input.Repository().Identity(),
			input.SourceAdapterIdentity(), manifest.Identity(), references, derivation,
		)
	} else {
		index, err = sourceoutput.NewSnapshot(
			"", execution.RequestIdentity(), execution.ReceiptIdentity(),
			execution.Identity(), input.Repository().Identity(), revision.Identity(),
			input.SourceAdapterIdentity(), manifest.Identity(), references,
		)
	}
	if err != nil {
		return taskFailure(controlplane.RunFailureInternal)
	}
	payload, err := sourceoutput.EncodeSnapshot(index)
	if err != nil {
		return taskFailure(controlplane.RunFailureResourceLimit)
	}
	output, err := artifact.New(
		request.Plan().Scope(), artifact.KindSourceSnapshot, "application/json",
		inputArtifact.Classification(), artifact.OriginRepository, inputArtifact.Protection(),
		provenance, payload, now, inputArtifact.ExpiresAt(),
	)
	if err != nil {
		return taskFailure(controlplane.RunFailureResourceLimit)
	}
	if _, err := h.store.Put(ctx, output, now); err != nil {
		return taskFailure(storeWriteFailure(ctx, err))
	}
	completion, err := controlplane.NewTaskSuccess(output.Identity())
	if err != nil {
		return taskFailure(controlplane.RunFailureInternal)
	}
	return completion
}

func mapAcquisitionFailure(reason evidence.RepositoryAcquisitionReason) controlplane.RunFailure {
	switch reason {
	case evidence.AcquisitionReasonAuthorizationRequired,
		evidence.AcquisitionReasonPolicyBlocked,
		evidence.AcquisitionReasonCapabilityUnavailable:
		return controlplane.RunFailurePolicy
	case evidence.AcquisitionReasonAdapterUnavailable:
		return controlplane.RunFailureTransient
	case evidence.AcquisitionReasonResourceLimit:
		return controlplane.RunFailureResourceLimit
	case evidence.AcquisitionReasonAdapterFailure,
		evidence.AcquisitionReasonArtifactIncomplete:
		return controlplane.RunFailureInternal
	default:
		return controlplane.RunFailureInternal
	}
}

func storeReadFailure(ctx context.Context, err error) controlplane.RunFailure {
	if ctx.Err() != nil {
		return controlplane.RunFailureCanceled
	}
	if errors.Is(err, artifact.ErrArtifactNotFound) || errors.Is(err, artifact.ErrArtifactExpired) {
		return controlplane.RunFailureInvalidInput
	}
	return controlplane.RunFailureInternal
}

func storeWriteFailure(ctx context.Context, err error) controlplane.RunFailure {
	if ctx.Err() != nil {
		return controlplane.RunFailureCanceled
	}
	if errors.Is(err, artifact.ErrStoreCapacity) {
		return controlplane.RunFailureResourceLimit
	}
	return controlplane.RunFailureInternal
}

func taskFailure(failure controlplane.RunFailure) controlplane.TaskCompletion {
	completion, _ := controlplane.NewTaskFailure(failure)
	return completion
}

func clearContents(contents map[string][]byte) {
	for _, content := range contents {
		clear(content)
	}
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

func (h *Handler) String() string   { return "source acquisition task handler" }
func (h *Handler) GoString() string { return "source.Handler{<redacted>}" }
func (h *Handler) Format(state fmt.State, verb rune) {
	value := "source acquisition task handler"
	if verb == 'q' {
		value = strconv.Quote(value)
	} else if verb == 'v' && state.Flag('#') {
		value = "source.Handler{<redacted>}"
	}
	_, _ = state.Write([]byte(value))
}

var _ controlplane.TaskHandler = (*Handler)(nil)
