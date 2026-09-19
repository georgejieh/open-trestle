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
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/scm"
)

// Handler acquires one exact repository revision and persists protected source artifacts.
type Handler struct {
	identity string
	store    artifact.Store
	adapter  scm.SourceAdapter
	clock    artifact.Clock
}

// NewHandler binds one exact source adapter to a protected artifact store.
func NewHandler(store artifact.Store, adapter scm.SourceAdapter, clock artifact.Clock) (*Handler, error) {
	if nilInterface(store) || nilInterface(adapter) || nilInterface(clock) {
		return nil, ErrInvalidHandler
	}
	if !canonicalAdapter(adapter.Identity()) {
		return nil, ErrInvalidHandler
	}
	handler := &Handler{store: store, adapter: adapter, clock: clock}
	handler.identity = deriveHandlerIdentity(adapter.Identity())
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
		!canonicalAdapter(h.adapter.Identity()) || h.identity != deriveHandlerIdentity(h.adapter.Identity()) {
		return ErrInvalidHandler
	}
	return nil
}

func canonicalAdapter(value evidence.SourceAdapterIdentity) bool {
	canonical, err := evidence.NewSourceAdapterIdentity(value.Kind(), value.Name(), value.Version(), value.Capabilities())
	return err == nil && sameAdapterIdentity(canonical, value) &&
		canonical.HasCapability(evidence.SourceCapabilityReadManifest) &&
		canonical.HasCapability(evidence.SourceCapabilityReadContent)
}

func deriveHandlerIdentity(adapter evidence.SourceAdapterIdentity) string {
	encoded, err := json.Marshal(struct {
		Contract              string `json:"contract"`
		SchemaVersion         int    `json:"schema_version"`
		SourceAdapterIdentity string `json:"source_adapter_identity"`
	}{"open-trestle/source-acquisition-handler", 1, adapter.Identity()})
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
	if !sameAdapterIdentity(input.Adapter(), h.adapter.Identity()) {
		return taskFailure(controlplane.RunFailurePolicy)
	}
	acquisitionRequest, err := evidence.NewRepositoryAcquisitionRequest(
		input.Repository(), input.Revision(), input.Adapter(),
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
	return h.persistSnapshot(ctx, request, inputArtifact, input, snapshot, now)
}

func (h *Handler) persistSnapshot(
	ctx context.Context,
	request controlplane.TaskExecutionRequest,
	inputArtifact artifact.Artifact,
	input Input,
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
		payload, err := encodeFile(execution.Identity(), file, content)
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
		references = append(references, FileReference{
			path: file.Path(), digest: file.Digest(), sizeBytes: file.SizeBytes(),
			artifactIdentity: value.Identity(),
		})
	}
	sort.Slice(references, func(first, second int) bool { return references[first].path < references[second].path })
	index, err := newSnapshot(
		"", execution.RequestIdentity(), execution.ReceiptIdentity(),
		execution.Identity(), input.Repository().Identity(), input.Revision().Identity(),
		input.SourceAdapterIdentity(), manifest.Identity(), references,
	)
	if err != nil {
		return taskFailure(controlplane.RunFailureInternal)
	}
	payload, err := encodeSnapshot(index)
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
