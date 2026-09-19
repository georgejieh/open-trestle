package model

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	source "github.com/georgejieh/open-trestle/handlers/source"
	"github.com/georgejieh/open-trestle/internal/scm"
)

const (
	acquisitionReferenceFiles        = 128
	acquisitionReferencePayloadBytes = 32 << 20
	acquisitionReferenceHeadBytes    = 16 << 20
)

var ErrInvestigationAcquisition = errors.New("investigation acquisition references unavailable")
var ErrInvestigationAcquisitionDrain = errors.New("investigation acquisition work has not drained")

// InvestigationAcquisition is an in-process observed-reference handle, not physical custody.
type InvestigationAcquisition struct {
	owner                                                   *InvestigationAcquisitionHandler
	planIdentity, scopeIdentity, taskIdentity, headIdentity string
	head                                                    artifact.Artifact
	snapshot                                                source.Snapshot
	files                                                   []artifact.Artifact
	created, expires                                        time.Time
}

type acquisitionInvocation struct {
	planIdentity, scopeIdentity, taskIdentity, inputIdentity string
	request                                                  controlplane.TaskExecutionRequest
	files                                                    map[string]artifact.Artifact
	fileBytes                                                int
	head                                                     artifact.Artifact
	failed                                                   bool
	cancel                                                   context.CancelFunc
	done                                                     chan struct{}
	handle                                                   *InvestigationAcquisition
}
type acquisitionInvocationKey struct{}

// InvestigationAcquisitionHandler permits one plan, two source tasks and one active call.
// The underlying source handler's identity and request checks are unchanged.
type InvestigationAcquisitionHandler struct {
	mu              sync.Mutex
	handler         *source.Handler
	clock           artifact.Clock
	capture         *acquisitionCaptureStore
	planIdentity    string
	slots           map[string]*acquisitionInvocation
	active          *acquisitionInvocation
	closing, closed bool
}
type acquisitionCaptureStore struct {
	owner *InvestigationAcquisitionHandler
	store artifact.Store
}

func NewInvestigationAcquisitionHandler(store artifact.Store, adapter scm.SourceAdapter, clock artifact.Clock) (*InvestigationAcquisitionHandler, error) {
	if nilInterface(store) || nilInterface(adapter) || nilInterface(clock) {
		return nil, ErrInvestigationAcquisition
	}
	h := &InvestigationAcquisitionHandler{clock: clock, slots: make(map[string]*acquisitionInvocation)}
	capture := &acquisitionCaptureStore{owner: h, store: store}
	inner, err := source.NewHandler(capture, adapter, clock)
	if err != nil {
		return nil, ErrInvestigationAcquisition
	}
	h.handler = inner
	h.capture = capture
	return h, nil
}
func (h *InvestigationAcquisitionHandler) HandlerIdentity() string {
	if h == nil || h.handler == nil {
		return ""
	}
	return h.handler.HandlerIdentity()
}
func (h *InvestigationAcquisitionHandler) Kind() controlplane.TaskKind {
	if h == nil || h.handler == nil {
		return 0
	}
	return h.handler.Kind()
}
func (h *InvestigationAcquisitionHandler) Validate() error {
	if h == nil || h.handler == nil || h.handler.Validate() != nil || nilInterface(h.clock) || h.capture == nil || h.capture.owner != h || nilInterface(h.capture.store) {
		return ErrInvestigationAcquisition
	}
	return nil
}
func acquisitionFailure(reason controlplane.RunFailure) controlplane.TaskCompletion {
	value, _ := controlplane.NewTaskFailure(reason)
	return value
}

func (h *InvestigationAcquisitionHandler) Execute(ctx context.Context, request controlplane.TaskExecutionRequest) controlplane.TaskCompletion {
	if h == nil || h.Validate() != nil || nilInterface(ctx) || request.Validate() != nil || request.Task().Kind() != controlplane.TaskAcquireSource || request.Task().HandlerIdentity() != h.HandlerIdentity() {
		return acquisitionFailure(controlplane.RunFailureInvalidInput)
	}
	if ctx.Err() != nil {
		return acquisitionFailure(controlplane.RunFailureCanceled)
	}
	plan := request.Plan()
	task, member := plan.Task(request.Task().Key())
	if !member || task.Identity() != request.Task().Identity() {
		return acquisitionFailure(controlplane.RunFailureInvalidInput)
	}
	sourceTasks := 0
	for _, declared := range plan.Tasks() {
		if declared.Kind() == controlplane.TaskAcquireSource {
			sourceTasks++
		}
	}
	if sourceTasks == 0 || sourceTasks > 2 {
		return acquisitionFailure(controlplane.RunFailurePolicy)
	}
	at := h.clock.Now()
	if at.UnixMilli() <= 0 || at.After(request.Lease().ExpiresAt()) {
		return acquisitionFailure(controlplane.RunFailureCanceled)
	}
	h.mu.Lock()
	if ctx.Err() != nil {
		h.mu.Unlock()
		return acquisitionFailure(controlplane.RunFailureCanceled)
	}
	if h.closing || h.closed || h.active != nil || h.planIdentity != "" && h.planIdentity != plan.Identity() || len(h.slots) >= 2 {
		h.mu.Unlock()
		return acquisitionFailure(controlplane.RunFailurePolicy)
	}
	if _, exists := h.slots[task.Identity()]; exists {
		h.mu.Unlock()
		return acquisitionFailure(controlplane.RunFailurePolicy)
	}
	execution, cancel := context.WithCancel(ctx)
	invocation := &acquisitionInvocation{planIdentity: plan.Identity(), scopeIdentity: plan.Scope().Identity(), taskIdentity: task.Identity(), inputIdentity: task.InputIdentity(), request: request, files: make(map[string]artifact.Artifact), cancel: cancel, done: make(chan struct{})}
	h.planIdentity = plan.Identity()
	h.slots[task.Identity()] = invocation
	h.active = invocation
	h.mu.Unlock()
	execution = context.WithValue(execution, acquisitionInvocationKey{}, invocation)
	defer func() {
		cancel()
		h.mu.Lock()
		if invocation.handle == nil {
			invocation.files = nil
			invocation.head = artifact.Artifact{}
		}
		h.active = nil
		close(invocation.done)
		h.mu.Unlock()
	}()
	// Delegate the exact request. Only the caller-derived cancellation context differs.
	completion := h.handler.Execute(execution, request)
	if completion.Status() != controlplane.TaskCompletionSucceeded || completion.Validate() != nil {
		return completion
	}
	h.mu.Lock()
	failed := invocation.failed || h.closing || h.closed || execution.Err() != nil
	h.mu.Unlock()
	if failed {
		return acquisitionFailure(controlplane.RunFailureCanceled)
	}
	handle, err := h.matchCompleted(invocation, completion, h.clock.Now())
	if err != nil {
		return acquisitionFailure(controlplane.RunFailureInvalidInput)
	}
	h.mu.Lock()
	if h.closing || h.closed || execution.Err() != nil || invocation.failed {
		h.mu.Unlock()
		return acquisitionFailure(controlplane.RunFailureCanceled)
	}
	invocation.handle = handle
	h.mu.Unlock()
	return completion
}

func (s *acquisitionCaptureStore) invocation(ctx context.Context) *acquisitionInvocation {
	if nilInterface(ctx) || ctx.Err() != nil {
		return nil
	}
	value, _ := ctx.Value(acquisitionInvocationKey{}).(*acquisitionInvocation)
	return value
}
func (s *acquisitionCaptureStore) Get(ctx context.Context, scope audit.ReviewScope, id string, at time.Time) (artifact.Artifact, error) {
	invocation := s.invocation(ctx)
	if invocation == nil {
		return artifact.Artifact{}, ErrInvestigationAcquisition
	}
	s.owner.mu.Lock()
	valid := s.owner.active == invocation && !s.owner.closing && scope.Identity() == invocation.scopeIdentity && id == invocation.inputIdentity
	s.owner.mu.Unlock()
	if !valid {
		return artifact.Artifact{}, ErrInvestigationAcquisition
	}
	return s.store.Get(ctx, scope, id, at)
}
func (s *acquisitionCaptureStore) Put(ctx context.Context, value artifact.Artifact, at time.Time) (bool, error) {
	invocation := s.invocation(ctx)
	if invocation == nil {
		return false, ErrInvestigationAcquisition
	}
	h := s.owner
	h.mu.Lock()
	if h.active != invocation || h.closing || h.closed || invocation.failed || value.Scope().Identity() != invocation.scopeIdentity || value.Origin() != artifact.OriginRepository || value.MediaType() != "application/json" || value.Classification().String() == "" || value.Protection().String() == "" || value.PayloadSizeBytes() <= 0 {
		invocation.failed = true
		h.mu.Unlock()
		return false, ErrInvestigationAcquisition
	}
	switch value.Kind() {
	case artifact.KindSourceFile:
		if _, exists := invocation.files[value.Identity()]; exists {
			invocation.failed = true
			h.mu.Unlock()
			return false, ErrInvestigationAcquisition
		}
		if len(invocation.files) >= acquisitionReferenceFiles || value.PayloadSizeBytes() > 16<<20 || value.PayloadSizeBytes() > acquisitionReferencePayloadBytes-invocation.fileBytes {
			invocation.failed = true
			h.mu.Unlock()
			return false, artifact.ErrStoreCapacity
		}
	case artifact.KindSourceSnapshot:
		if invocation.head.Identity() != "" || value.PayloadSizeBytes() > acquisitionReferenceHeadBytes {
			invocation.failed = true
			h.mu.Unlock()
			return false, artifact.ErrStoreCapacity
		}
	default:
		invocation.failed = true
		h.mu.Unlock()
		return false, ErrInvestigationAcquisition
	}
	h.mu.Unlock()
	created, err := s.store.Put(ctx, value, at)
	h.mu.Lock()
	defer h.mu.Unlock()
	if err != nil {
		invocation.failed = true
		return created, err
	}
	if h.active != invocation || h.closing || h.closed || ctx.Err() != nil {
		invocation.failed = true
		return created, ErrInvestigationAcquisition
	}
	// A successful existing-value Put is also known; no source Get is needed.
	if value.Kind() == artifact.KindSourceFile {
		invocation.files[value.Identity()] = value
		invocation.fileBytes += value.PayloadSizeBytes()
	} else {
		invocation.head = value
	}
	return created, nil
}

func (h *InvestigationAcquisitionHandler) matchCompleted(inv *acquisitionInvocation, completion controlplane.TaskCompletion, at time.Time) (*InvestigationAcquisition, error) {
	head := inv.head
	if inv.failed || head.Identity() != completion.OutputIdentity() || head.Scope().Identity() != inv.scopeIdentity || head.Kind() != artifact.KindSourceSnapshot || head.Origin() != artifact.OriginRepository || head.PayloadSizeBytes() <= 0 || head.PayloadSizeBytes() > acquisitionReferenceHeadBytes || at.UnixMilli() <= 0 || at.Before(head.CreatedAt()) || !at.Before(head.ExpiresAt()) || !hasProvenance(head.Provenance(), inv.inputIdentity) {
		return nil, ErrInvestigationAcquisition
	}
	// Validate only the bounded head index. Source payloads remain unopened references.
	snapshot, err := source.ParseSnapshotArtifact(head)
	if err != nil || snapshot.FileCount() != len(inv.files) || len(inv.files) > acquisitionReferenceFiles || inv.fileBytes > acquisitionReferencePayloadBytes || !hasProvenance(head.Provenance(), snapshot.AcquisitionExecutionIdentity()) {
		return nil, ErrInvestigationAcquisition
	}
	created, expires := head.CreatedAt(), head.ExpiresAt()
	files := make([]artifact.Artifact, 0, len(inv.files))
	for _, ref := range snapshot.Files() {
		value, exists := inv.files[ref.ArtifactIdentity()]
		if !exists || value.Kind() != artifact.KindSourceFile || value.Scope() != head.Scope() || value.Origin() != artifact.OriginRepository || value.MediaType() != head.MediaType() || value.Classification() != head.Classification() || value.Protection() != head.Protection() || value.PayloadSizeBytes() <= 0 || value.PayloadSizeBytes() > 16<<20 || ref.SizeBytes() < 0 || ref.SizeBytes() > 10<<20 || at.Before(value.CreatedAt()) || !at.Before(value.ExpiresAt()) || !hasProvenance(value.Provenance(), inv.inputIdentity) || !hasProvenance(value.Provenance(), snapshot.AcquisitionExecutionIdentity()) {
			return nil, ErrInvestigationAcquisition
		}
		if value.CreatedAt().After(created) {
			created = value.CreatedAt()
		}
		if value.ExpiresAt().Before(expires) {
			expires = value.ExpiresAt()
		}
		files = append(files, value)
	}
	return &InvestigationAcquisition{owner: h, planIdentity: inv.planIdentity, scopeIdentity: inv.scopeIdentity, taskIdentity: inv.taskIdentity, headIdentity: head.Identity(), head: head, snapshot: snapshot, files: files, created: created, expires: expires}, nil
}

// Acquisition returns observed references, not Coordinator completion or reader custody proof.
func (h *InvestigationAcquisitionHandler) Acquisition(ctx context.Context, plan controlplane.ReviewRunPlan, headID string) (*InvestigationAcquisition, error) {
	if h == nil || nilInterface(ctx) || ctx.Err() != nil || plan.Validate() != nil || !validDigest(headID) {
		return nil, ErrInvestigationAcquisition
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closing || h.closed || h.planIdentity != plan.Identity() || ctx.Err() != nil {
		return nil, ErrInvestigationAcquisition
	}
	at := h.clock.Now()
	for _, inv := range h.slots {
		value := inv.handle
		if value != nil && value.headIdentity == headID && value.planIdentity == plan.Identity() && value.scopeIdentity == plan.Scope().Identity() && value.owner == h && at.UnixMilli() > 0 && !at.Before(value.created) && at.Before(value.expires) {
			return value, nil
		}
	}
	return nil, ErrInvestigationAcquisition
}

func (h *InvestigationAcquisitionHandler) Close(ctx context.Context) error {
	if h == nil || nilInterface(ctx) {
		return ErrInvestigationAcquisition
	}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil
	}
	h.closing = true
	active := h.active
	h.mu.Unlock()
	if active != nil {
		active.cancel()
		select {
		case <-active.done:
		case <-ctx.Done():
			return ErrInvestigationAcquisitionDrain
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.active != nil {
		return ErrInvestigationAcquisitionDrain
	}
	for _, inv := range h.slots {
		inv.files = nil
		inv.head = artifact.Artifact{}
		inv.handle = nil
	}
	h.closed = true
	return nil
}
func (a *InvestigationAcquisition) String() string { return "observed acquisition references" }
func (a *InvestigationAcquisition) GoString() string {
	return "model.InvestigationAcquisition{<redacted>}"
}
func (h *InvestigationAcquisitionHandler) String() string { return "investigation acquisition handler" }
func (h *InvestigationAcquisitionHandler) GoString() string {
	return "model.InvestigationAcquisitionHandler{<redacted>}"
}

func (a *InvestigationAcquisition) Format(s fmt.State, verb rune) {
	_, _ = s.Write([]byte("observed acquisition references"))
}
func (h *InvestigationAcquisitionHandler) Format(s fmt.State, verb rune) {
	_, _ = s.Write([]byte("investigation acquisition handler"))
}
