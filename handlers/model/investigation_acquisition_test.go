package model_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	model "github.com/georgejieh/open-trestle/handlers/model"
	source "github.com/georgejieh/open-trestle/handlers/source"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/scm"
	"strings"
	"sync"
	"testing"
	"time"
)

func acquisitionCheck(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func acquisitionDigest(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

type acquisitionClock struct {
	mu sync.Mutex
	at time.Time
}

func (c *acquisitionClock) Now() time.Time   { c.mu.Lock(); defer c.mu.Unlock(); return c.at }
func (c *acquisitionClock) set(at time.Time) { c.mu.Lock(); c.at = at; c.mu.Unlock() }

type acquisitionSource struct {
	id     evidence.SourceAdapterIdentity
	result scm.SourceAdapterResult
	calls  int
}

func (s *acquisitionSource) Identity() evidence.SourceAdapterIdentity { return s.id }
func (s *acquisitionSource) Acquire(ctx context.Context, r evidence.RepositoryAcquisitionRequest) scm.SourceAdapterResult {
	s.calls++
	return s.result
}

const acquisitionNotes = "first\nzero<&>\nlast\n"
const acquisitionInitial = "package p\nfunc Changed(x int) int { return 10 / x }\n"

type custodyAcquireStore struct {
	artifact.Store
	mu         sync.Mutex
	mode       string
	sourceIDs  map[string]bool
	sourceGets int
	head       string
	putBytes   []int
	getIDs     []string
	cancel     context.CancelFunc
}

func (s *custodyAcquireStore) Put(ctx context.Context, value artifact.Artifact, at time.Time) (bool, error) {
	s.mu.Lock()
	if value.Kind() == artifact.KindSourceFile {
		s.sourceIDs[value.Identity()] = true
		s.putBytes = append(s.putBytes, value.PayloadSizeBytes())
	}
	if value.Kind() == artifact.KindSourceSnapshot {
		s.head = value.Identity()
	}
	mode := s.mode
	cancel := s.cancel
	s.mu.Unlock()
	if mode == "file write failure" && value.Kind() == artifact.KindSourceFile {
		return false, errors.New("fixture source write failure")
	}
	created, err := s.Store.Put(ctx, value, at)
	if err == nil && mode == "cancel after file write" && value.Kind() == artifact.KindSourceFile {
		cancel()
	}
	if err == nil && mode == "head write unknown" && value.Kind() == artifact.KindSourceSnapshot {
		return false, errors.New("fixture unknown head write outcome")
	}
	return created, err
}
func (s *custodyAcquireStore) Get(ctx context.Context, scope audit.ReviewScope, id string, at time.Time) (artifact.Artifact, error) {
	s.mu.Lock()
	s.getIDs = append(s.getIDs, id)
	if s.sourceIDs[id] {
		s.sourceGets++
	}
	s.mu.Unlock()
	return s.Store.Get(ctx, scope, id, at)
}
func (s *custodyAcquireStore) sourceReads() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sourceGets
}
func (s *custodyAcquireStore) headID() string { s.mu.Lock(); defer s.mu.Unlock(); return s.head }

type custodyBlockingSource struct {
	*acquisitionSource
	entered, release chan struct{}
	once             sync.Once
}

func (s *custodyBlockingSource) Acquire(ctx context.Context, r evidence.RepositoryAcquisitionRequest) scm.SourceAdapterResult {
	s.once.Do(func() { close(s.entered) })
	select {
	case <-ctx.Done():
		return scm.SourceAdapterResult{}
	case <-s.release:
		return s.acquisitionSource.Acquire(ctx, r)
	}
}

type custodyAcquireFixture struct {
	handler     *model.InvestigationAcquisitionHandler
	store       *custodyAcquireStore
	clock       *acquisitionClock
	plan        controlplane.ReviewRunPlan
	request     controlplane.TaskExecutionRequest
	coordinator *controlplane.Coordinator
	lease       controlplane.TaskLease
	source      *acquisitionSource
	blocking    *custodyBlockingSource
}

func newCustodyAcquisitionFixture(t *testing.T, mode string) custodyAcquireFixture {
	t.Helper()
	ctx := context.Background()
	clock := &acquisitionClock{at: time.UnixMilli(1000)}
	scope, err := audit.NewReviewScope("capture-tenant", "capture-repo", "capture-run")
	acquisitionCheck(t, err)
	memoryStore, err := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 300)
	acquisitionCheck(t, err)
	store := &custodyAcquireStore{Store: memoryStore, mode: mode, sourceIDs: map[string]bool{}}
	repository, err := evidence.NewRepositoryIdentity("example.test", []string{"owner"}, "capture")
	acquisitionCheck(t, err)
	revision, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("c", 40))
	acquisitionCheck(t, err)
	adapter, err := evidence.NewSourceAdapterIdentity(evidence.SourceAdapterKindGit, "capture-fixture", "1.0.0", []evidence.SourceAdapterCapability{evidence.SourceCapabilityReadManifest, evidence.SourceCapabilityReadContent})
	acquisitionCheck(t, err)
	contents := map[string][]byte{"a.go": []byte(acquisitionInitial), "notes.txt": []byte(acquisitionNotes)}
	if mode == "reference overflow" {
		contents = map[string][]byte{}
		for i := 0; i < 129; i++ {
			contents[fmt.Sprintf("file-%03d.txt", i)] = []byte("x\n")
		}
	}
	files := []evidence.RepositoryFile{}
	for path, b := range contents {
		file, err := evidence.NewRepositoryFile(path, b)
		acquisitionCheck(t, err)
		files = append(files, file)
	}
	manifest, err := evidence.NewRepositoryManifest(files)
	acquisitionCheck(t, err)
	external := &acquisitionSource{id: adapter, result: scm.SourceAdapterResult{Outcome: evidence.AcquisitionOutcomeAcquired, Reason: evidence.AcquisitionReasonNone, Manifest: manifest, Contents: contents}}
	var adapterValue scm.SourceAdapter = external
	var blocking *custodyBlockingSource
	if mode == "blocked" {
		blocking = &custodyBlockingSource{acquisitionSource: external, entered: make(chan struct{}), release: make(chan struct{})}
		adapterValue = blocking
	}
	handler, err := model.NewInvestigationAcquisitionHandler(store, adapterValue, clock)
	acquisitionCheck(t, err)
	underlying, err := source.NewHandler(store, adapterValue, clock)
	acquisitionCheck(t, err)
	if handler.Kind() != underlying.Kind() || handler.HandlerIdentity() != underlying.HandlerIdentity() || handler.Validate() != nil {
		t.Fatal("wrapper changed underlying source request authority")
	}
	input, err := source.NewInput(repository, revision, adapter)
	acquisitionCheck(t, err)
	inputArtifact, err := source.NewInputArtifact(scope, input, artifact.ClassificationConfidential, artifact.ProtectionProcessPrivate, []string{acquisitionDigest([]byte("capture source input"))}, time.UnixMilli(100), time.UnixMilli(100000))
	acquisitionCheck(t, err)
	_, err = store.Put(ctx, inputArtifact, time.UnixMilli(100))
	acquisitionCheck(t, err)
	task, err := controlplane.NewTaskDefinition("source-head", controlplane.TaskAcquireSource, inputArtifact.Identity(), handler.HandlerIdentity(), nil, 1, 0, 30000, true)
	acquisitionCheck(t, err)
	plan, err := controlplane.NewReviewRunPlan(scope, acquisitionDigest([]byte("capture request")), acquisitionDigest([]byte("capture policy")), controlplane.ReviewRunAdvisory, []controlplane.TaskDefinition{task})
	acquisitionCheck(t, err)
	coordinator, err := controlplane.NewCoordinator(controlplane.NewMemoryRunJournal())
	acquisitionCheck(t, err)
	_, err = coordinator.Open(ctx, plan, time.UnixMilli(100))
	acquisitionCheck(t, err)
	_, err = coordinator.Advance(ctx, plan, time.UnixMilli(101))
	acquisitionCheck(t, err)
	lease, _, err := coordinator.ClaimTask(ctx, plan, task.Key(), handler.HandlerIdentity(), "capture-worker", time.UnixMilli(102))
	acquisitionCheck(t, err)
	request, err := controlplane.NewTaskExecutionRequest(plan, task, lease)
	acquisitionCheck(t, err)
	t.Cleanup(func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := handler.Close(closeCtx); err != nil {
			t.Error("capture fixture wrapper did not close")
		}
	})
	return custodyAcquireFixture{handler, store, clock, plan, request, coordinator, lease, external, blocking}
}
func TestInvestigationAcquisitionReferencesRequireActualSuccessAndExactPlanHead(t *testing.T) {
	f := newCustodyAcquisitionFixture(t, "")
	ctx := context.Background()
	if handle, err := f.handler.Acquisition(ctx, f.plan, acquisitionDigest([]byte("unproduced head"))); err == nil || handle != nil {
		t.Fatal("reference handle existed before actual Execute success")
	}
	completion := f.handler.Execute(ctx, f.request)
	if completion.Status() != controlplane.TaskCompletionSucceeded || f.source.calls != 1 {
		t.Fatal("wrapper did not delegate real source execution")
	}
	_, err := f.coordinator.CompleteTask(ctx, f.plan, f.lease, completion, f.clock.Now())
	acquisitionCheck(t, err)
	handle, err := f.handler.Acquisition(ctx, f.plan, completion.OutputIdentity())
	acquisitionCheck(t, err)
	if handle == nil || f.store.sourceReads() != 0 {
		t.Fatal("acquisition lookup reopened source files or omitted reference handle")
	}
	other, err := controlplane.NewReviewRunPlan(f.plan.Scope(), acquisitionDigest([]byte("other source plan")), f.plan.PolicyIdentity(), f.plan.Mode(), f.plan.Tasks())
	acquisitionCheck(t, err)
	for _, test := range []struct {
		plan controlplane.ReviewRunPlan
		head string
	}{{other, completion.OutputIdentity()}, {f.plan, acquisitionDigest([]byte("wrong head"))}} {
		if got, err := f.handler.Acquisition(ctx, test.plan, test.head); err == nil || got != nil {
			t.Fatal("cross-plan/head reference pool accepted")
		}
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if got, err := f.handler.Acquisition(canceled, f.plan, completion.OutputIdentity()); err == nil || got != nil {
		t.Fatal("canceled reference access succeeded")
	}
	f.clock.set(time.UnixMilli(100000))
	if got, err := f.handler.Acquisition(ctx, f.plan, completion.OutputIdentity()); err == nil || got != nil {
		t.Fatal("expired acquisition references refreshed")
	}
	if f.store.sourceReads() != 0 {
		t.Fatal("reference rejection opened source-file payloads")
	}
}
func TestInvestigationAcquisitionFailureCancelUnknownWriteAndOverflowExposeNoHandle(t *testing.T) {
	for _, mode := range []string{"file write failure", "head write unknown", "cancel after file write", "pre-canceled", "reference overflow"} {
		t.Run(mode, func(t *testing.T) {
			f := newCustodyAcquisitionFixture(t, mode)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f.store.cancel = cancel
			if mode == "pre-canceled" {
				cancel()
			}
			completion := f.handler.Execute(ctx, f.request)
			if completion.Status() == controlplane.TaskCompletionSucceeded {
				t.Fatal("failed/canceled/overflow acquisition was registered as success")
			}
			head := f.store.headID()
			if head == "" {
				head = acquisitionDigest([]byte("absent source head"))
			}
			if handle, err := f.handler.Acquisition(context.Background(), f.plan, head); err == nil || handle != nil {
				t.Fatal("partial/unknown acquisition exposed source references")
			}
			if f.store.sourceReads() != 0 {
				t.Fatal("failure cleanup reread full sources")
			}
			if mode == "pre-canceled" && f.source.calls != 0 {
				t.Fatal("pre-canceled wrapper dispatched acquisition")
			}
			if mode == "head write unknown" {
				if _, err := f.store.Store.Get(context.Background(), f.plan.Scope(), head, f.clock.Now()); err != nil {
					t.Fatal("fixture did not retain actual partial head write; no rollback claim is justified")
				}
			}
		})
	}
}
func TestInvestigationAcquisitionCloseInvalidatesReferences(t *testing.T) {
	f := newCustodyAcquisitionFixture(t, "")
	completion := f.handler.Execute(context.Background(), f.request)
	if completion.Status() != controlplane.TaskCompletionSucceeded {
		t.Fatal("source did not complete")
	}
	_, err := f.coordinator.CompleteTask(context.Background(), f.plan, f.lease, completion, f.clock.Now())
	acquisitionCheck(t, err)
	_, err = f.handler.Acquisition(context.Background(), f.plan, completion.OutputIdentity())
	acquisitionCheck(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	acquisitionCheck(t, f.handler.Close(ctx))
	if handle, err := f.handler.Acquisition(context.Background(), f.plan, completion.OutputIdentity()); err == nil || handle != nil {
		t.Fatal("closed acquisition owner returned live reference handle")
	}
}
func TestInvestigationAcquisitionCloseDrainsActualSourceCall(t *testing.T) {
	f := newCustodyAcquisitionFixture(t, "blocked")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan controlplane.TaskCompletion, 1)
	finished := make(chan struct{})
	go func() { defer close(finished); done <- f.handler.Execute(ctx, f.request) }()
	t.Cleanup(func() {
		cancel()
		close(f.blocking.release)
		select {
		case <-finished:
		case <-time.After(time.Second):
			t.Error("blocked acquisition fixture did not drain")
		}
	})
	select {
	case <-f.blocking.entered:
	case <-time.After(time.Second):
		t.Fatal("actual source adapter wait not reached")
	}
	closeCtx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	acquisitionCheck(t, f.handler.Close(closeCtx))
	select {
	case completion := <-done:
		if completion.Status() == controlplane.TaskCompletionSucceeded {
			t.Fatal("closed acquisition reported successful retained references")
		}
	case <-time.After(time.Second):
		t.Fatal("Close returned before actual source completion")
	}
}

type acquisitionSequenceSource struct {
	mu               sync.Mutex
	id               evidence.SourceAdapterIdentity
	results          map[string]scm.SourceAdapterResult
	requests         []evidence.RepositoryAcquisitionRequest
	block            string
	ignoreCancel     bool
	entered, release chan struct{}
	once             sync.Once
}

func (s *acquisitionSequenceSource) Identity() evidence.SourceAdapterIdentity { return s.id }
func (s *acquisitionSequenceSource) Acquire(ctx context.Context, r evidence.RepositoryAcquisitionRequest) scm.SourceAdapterResult {
	s.mu.Lock()
	s.requests = append(s.requests, r)
	result := s.results[r.Revision().Identity()]
	block, ignore := r.Revision().Identity() == s.block, s.ignoreCancel
	s.mu.Unlock()
	if block {
		s.once.Do(func() { close(s.entered) })
		if ignore {
			<-s.release
		} else {
			select {
			case <-s.release:
			case <-ctx.Done():
				return scm.SourceAdapterResult{}
			}
		}
	}
	return result
}
func (s *acquisitionSequenceSource) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.requests)
}

type acquisitionPair struct {
	handler     *model.InvestigationAcquisitionHandler
	store       *custodyAcquireStore
	clock       *acquisitionClock
	plan        controlplane.ReviewRunPlan
	requests    []controlplane.TaskExecutionRequest
	leases      []controlplane.TaskLease
	coordinator *controlplane.Coordinator
	source      *acquisitionSequenceSource
	expected    []evidence.RepositoryAcquisitionRequest
}

func acquisitionResult(t *testing.T, contents map[string][]byte) scm.SourceAdapterResult {
	t.Helper()
	files := []evidence.RepositoryFile{}
	for path, b := range contents {
		file, err := evidence.NewRepositoryFile(path, b)
		acquisitionCheck(t, err)
		files = append(files, file)
	}
	manifest, err := evidence.NewRepositoryManifest(files)
	acquisitionCheck(t, err)
	return scm.SourceAdapterResult{Outcome: evidence.AcquisitionOutcomeAcquired, Reason: evidence.AcquisitionReasonNone, Manifest: manifest, Contents: contents}
}
func newAcquisitionPair(t *testing.T, block, ignore bool, count int, largeFiles int) acquisitionPair {
	t.Helper()
	ctx := context.Background()
	clock := &acquisitionClock{at: time.UnixMilli(1000)}
	scope, err := audit.NewReviewScope("pair-tenant", "pair-repo", "pair-run")
	acquisitionCheck(t, err)
	memoryStore, err := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 300)
	acquisitionCheck(t, err)
	store := &custodyAcquireStore{Store: memoryStore, sourceIDs: map[string]bool{}}
	repository, err := evidence.NewRepositoryIdentity("example.test", []string{"owner"}, "pair")
	acquisitionCheck(t, err)
	id, err := evidence.NewSourceAdapterIdentity(evidence.SourceAdapterKindGit, "pair-source", "1.0.0", []evidence.SourceAdapterCapability{evidence.SourceCapabilityReadManifest, evidence.SourceCapabilityReadContent})
	acquisitionCheck(t, err)
	external := &acquisitionSequenceSource{id: id, results: map[string]scm.SourceAdapterResult{}, ignoreCancel: ignore, entered: make(chan struct{}), release: make(chan struct{})}
	handler, err := model.NewInvestigationAcquisitionHandler(store, external, clock)
	acquisitionCheck(t, err)
	tasks := []controlplane.TaskDefinition{}
	expected := []evidence.RepositoryAcquisitionRequest{}
	for n := 0; n < count; n++ {
		revision, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, fmt.Sprintf("%040x", n+1))
		acquisitionCheck(t, err)
		contents := map[string][]byte{"one.txt": []byte(fmt.Sprintf("revision %d\n", n))}
		if largeFiles > 0 {
			contents = map[string][]byte{}
			body := bytes.Repeat([]byte{'x'}, 6<<20)
			for k := 0; k < largeFiles; k++ {
				contents[fmt.Sprintf("large-%d.txt", k)] = body
			}
		}
		external.results[revision.Identity()] = acquisitionResult(t, contents)
		if block && n == 0 {
			external.block = revision.Identity()
		}
		input, err := source.NewInput(repository, revision, id)
		acquisitionCheck(t, err)
		value, err := source.NewInputArtifact(scope, input, artifact.ClassificationConfidential, artifact.ProtectionProcessPrivate, []string{acquisitionDigest([]byte("pair intent"))}, time.UnixMilli(100), time.UnixMilli(100000))
		acquisitionCheck(t, err)
		_, err = store.Put(ctx, value, time.UnixMilli(100))
		acquisitionCheck(t, err)
		key := []string{"source-base", "source-head", "unsupported-third"}[n]
		task, err := controlplane.NewTaskDefinition(key, controlplane.TaskAcquireSource, value.Identity(), handler.HandlerIdentity(), nil, 1, 0, 30000, true)
		acquisitionCheck(t, err)
		tasks = append(tasks, task)
		want, err := evidence.NewRepositoryAcquisitionRequest(repository, revision, id, evidence.AcquisitionArtifactManifestAndContent, evidence.AcquisitionEffectReadOnly)
		acquisitionCheck(t, err)
		expected = append(expected, want)
	}
	planTasks := append([]controlplane.TaskDefinition(nil), tasks...)
	if len(tasks) > 1 {
		dependencies := make([]string, 0, len(tasks))
		for _, task := range tasks {
			dependencies = append(dependencies, task.Key())
		}
		// This required join only makes the plan topology valid. It is never executed
		// or completed by this acquisition-only fixture.
		join, err := controlplane.NewTaskDefinition("change", controlplane.TaskBuildChange, acquisitionDigest([]byte("unexecuted change input")), acquisitionDigest([]byte("unexecuted change handler")), dependencies, 1, 0, 30000, true)
		acquisitionCheck(t, err)
		planTasks = append(planTasks, join)
	}
	plan, err := controlplane.NewReviewRunPlan(scope, acquisitionDigest([]byte("pair request")), acquisitionDigest([]byte("pair policy")), controlplane.ReviewRunAdvisory, planTasks)
	acquisitionCheck(t, err)
	coordinator, err := controlplane.NewCoordinator(controlplane.NewMemoryRunJournal())
	acquisitionCheck(t, err)
	_, err = coordinator.Open(ctx, plan, time.UnixMilli(100))
	acquisitionCheck(t, err)
	_, err = coordinator.Advance(ctx, plan, time.UnixMilli(101))
	acquisitionCheck(t, err)
	requests := []controlplane.TaskExecutionRequest{}
	leases := []controlplane.TaskLease{}
	for _, task := range tasks {
		lease, _, err := coordinator.ClaimTask(ctx, plan, task.Key(), handler.HandlerIdentity(), "pair-worker", time.UnixMilli(102))
		acquisitionCheck(t, err)
		request, err := controlplane.NewTaskExecutionRequest(plan, task, lease)
		acquisitionCheck(t, err)
		requests = append(requests, request)
		leases = append(leases, lease)
	}
	t.Cleanup(func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := handler.Close(closeCtx); err != nil {
			t.Error("pair wrapper did not drain")
		}
	})
	return acquisitionPair{handler, store, clock, plan, requests, leases, coordinator, external, expected}
}
func TestInvestigationAcquisitionSequentialBaseHeadAndFailedBaseIsolation(t *testing.T) {
	for _, failBase := range []bool{false, true} {
		t.Run(fmt.Sprint(failBase), func(t *testing.T) {
			f := newAcquisitionPair(t, false, false, 2, 0)
			if failBase {
				f.store.mode = "file write failure"
			}
			base := f.handler.Execute(context.Background(), f.requests[0])
			if (base.Status() == controlplane.TaskCompletionSucceeded) == failBase {
				t.Fatal("base disposition did not match actual write outcome")
			}
			if !failBase {
				_, err := f.coordinator.CompleteTask(context.Background(), f.plan, f.leases[0], base, f.clock.Now())
				acquisitionCheck(t, err)
			}
			f.store.mu.Lock()
			f.store.mode = ""
			f.store.mu.Unlock()
			head := f.handler.Execute(context.Background(), f.requests[1])
			if head.Status() != controlplane.TaskCompletionSucceeded {
				t.Fatal("distinct legitimate head blocked by base state")
			}
			_, err := f.coordinator.CompleteTask(context.Background(), f.plan, f.leases[1], head, f.clock.Now())
			acquisitionCheck(t, err)
			if failBase {
				// Both requests were genuinely leased before execution. Record the
				// actual head success before recording the required base failure.
				// This isolates wrapper pools, not engine continuation after failure.
				_, err = f.coordinator.CompleteTask(context.Background(), f.plan, f.leases[0], base, f.clock.Now())
				acquisitionCheck(t, err)
			}
			handle, err := f.handler.Acquisition(context.Background(), f.plan, head.OutputIdentity())
			acquisitionCheck(t, err)
			if handle == nil {
				t.Fatal("head references missing")
			}
			if !failBase {
				baseHandle, err := f.handler.Acquisition(context.Background(), f.plan, base.OutputIdentity())
				acquisitionCheck(t, err)
				if baseHandle == handle || base.OutputIdentity() == head.OutputIdentity() {
					t.Fatal("base/head pools merged")
				}
			}
			if f.source.count() != 2 || f.store.sourceReads() != 0 {
				t.Fatal("wrapper repeated or reread source")
			}
			for i, request := range f.source.requests {
				if request.Identity() != f.expected[i].Identity() {
					t.Fatal("delegated request changed repository/revision/adapter/effect")
				}
			}
			for i, request := range f.requests {
				if f.store.getIDs[i] != request.Task().InputIdentity() {
					t.Fatal("source Handler did not read exact original task input")
				}
			}
			if retry := f.handler.Execute(context.Background(), f.requests[0]); retry.Status() == controlplane.TaskCompletionSucceeded || f.source.count() != 2 {
				t.Fatal("admitted source attempt was replayed after success/failure")
			}
		})
	}
}
func TestInvestigationAcquisitionBusyRefusalDoesNotConsumeHeadSlot(t *testing.T) {
	f := newAcquisitionPair(t, true, false, 2, 0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan controlplane.TaskCompletion, 1)
	finished := make(chan struct{})
	go func() { defer close(finished); done <- f.handler.Execute(ctx, f.requests[0]) }()
	var release sync.Once
	t.Cleanup(func() {
		cancel()
		release.Do(func() { close(f.source.release) })
		select {
		case <-finished:
		case <-time.After(time.Second):
			t.Error("busy fixture did not drain")
		}
	})
	select {
	case <-f.source.entered:
	case <-time.After(time.Second):
		t.Fatal("base actual acquisition not reached")
	}
	if busy := f.handler.Execute(ctx, f.requests[1]); busy.Status() == controlplane.TaskCompletionSucceeded || f.source.count() != 1 {
		t.Fatal("concurrent head reached effects")
	}
	release.Do(func() { close(f.source.release) })
	select {
	case result := <-done:
		if result.Status() != controlplane.TaskCompletionSucceeded {
			t.Fatal("admitted base did not finish")
		}
	case <-time.After(time.Second):
		t.Fatal("released base did not return")
	}
	if head := f.handler.Execute(ctx, f.requests[1]); head.Status() != controlplane.TaskCompletionSucceeded || f.source.count() != 2 {
		t.Fatal("busy refusal consumed unadmitted head slot")
	}
}
func TestInvestigationAcquisitionPlanBoundAndUnadmittedCallsCannotPin(t *testing.T) {
	f := newAcquisitionPair(t, false, false, 2, 0)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if result := f.handler.Execute(ctx, f.requests[0]); result.Status() == controlplane.TaskCompletionSucceeded || f.source.count() != 0 {
		t.Fatal("pre-canceled request admitted")
	}
	if result := f.handler.Execute(context.Background(), controlplane.TaskExecutionRequest{}); result.Status() == controlplane.TaskCompletionSucceeded || f.source.count() != 0 {
		t.Fatal("zero request admitted")
	}
	if result := f.handler.Execute(context.Background(), f.requests[0]); result.Status() != controlplane.TaskCompletionSucceeded {
		t.Fatal("invalid calls consumed valid first admission")
	}
	foreign, err := controlplane.NewReviewRunPlan(f.plan.Scope(), acquisitionDigest([]byte("foreign plan")), f.plan.PolicyIdentity(), f.plan.Mode(), f.plan.Tasks())
	acquisitionCheck(t, err)
	coordinator, err := controlplane.NewCoordinator(controlplane.NewMemoryRunJournal())
	acquisitionCheck(t, err)
	_, err = coordinator.Open(context.Background(), foreign, time.UnixMilli(100))
	acquisitionCheck(t, err)
	_, err = coordinator.Advance(context.Background(), foreign, time.UnixMilli(101))
	acquisitionCheck(t, err)
	task, exists := foreign.Task("source-head")
	if !exists {
		t.Fatal("foreign source-head task missing")
	}
	lease, _, err := coordinator.ClaimTask(context.Background(), foreign, task.Key(), task.HandlerIdentity(), "foreign-worker", time.UnixMilli(102))
	acquisitionCheck(t, err)
	request, err := controlplane.NewTaskExecutionRequest(foreign, task, lease)
	acquisitionCheck(t, err)
	if result := f.handler.Execute(context.Background(), request); result.Status() == controlplane.TaskCompletionSucceeded || f.source.count() != 1 {
		t.Fatal("foreign plan replaced pinned acquisition lifetime")
	}
	large := newAcquisitionPair(t, false, false, 3, 0)
	if result := large.handler.Execute(context.Background(), large.requests[0]); result.Status() == controlplane.TaskCompletionSucceeded || large.source.count() != 0 {
		t.Fatal("three-source plan admitted before effects")
	}
}
func TestInvestigationAcquisitionReferencedPayloadBoundUsesActualEncodedLengths(t *testing.T) {
	for _, files := range []int{3, 4} {
		t.Run(fmt.Sprint(files), func(t *testing.T) {
			f := newAcquisitionPair(t, false, false, 1, files)
			result := f.handler.Execute(context.Background(), f.requests[0])
			f.store.mu.Lock()
			sizes := append([]int(nil), f.store.putBytes...)
			f.store.mu.Unlock()
			if len(sizes) == 0 {
				t.Fatal("fixture never observed actual source Handler Put payload")
			}
			var total uint64
			for _, size := range sizes {
				total += uint64(size)
			}
			if files == 3 {
				if result.Status() != controlplane.TaskCompletionSucceeded || len(sizes) != 3 || total >= 32<<20 {
					t.Fatal("useful below-bound source fixture did not fit")
				}
				if _, err := f.handler.Acquisition(context.Background(), f.plan, result.OutputIdentity()); err != nil {
					t.Fatal(err)
				}
			} else {
				if uint64(sizes[0])*4 <= 32<<20 || result.Status() == controlplane.TaskCompletionSucceeded {
					t.Fatal("encoded four-file reference overflow did not refuse")
				}
				if handle, err := f.handler.Acquisition(context.Background(), f.plan, f.store.headID()); err == nil || handle != nil {
					t.Fatal("overflow exposed an acquisition handle")
				}
			}
			if f.store.sourceReads() != 0 {
				t.Fatal("reference sizing reread source-file payloads")
			}
		})
	}
}
func TestInvestigationAcquisitionUnknownWriteCannotRetryIntoSuccess(t *testing.T) {
	f := newCustodyAcquisitionFixture(t, "head write unknown")
	first := f.handler.Execute(context.Background(), f.request)
	if first.Status() == controlplane.TaskCompletionSucceeded {
		t.Fatal("unknown head write reported success")
	}
	calls := f.source.calls
	f.store.mu.Lock()
	f.store.mode = ""
	f.store.mu.Unlock()
	if second := f.handler.Execute(context.Background(), f.request); second.Status() == controlplane.TaskCompletionSucceeded || f.source.calls != calls {
		t.Fatal("unknown admitted attempt was reauthorized by retry")
	}
}
func TestInvestigationAcquisitionCloseTimeoutRetainsUncooperativeWork(t *testing.T) {
	f := newAcquisitionPair(t, true, true, 1, 0)
	done := make(chan controlplane.TaskCompletion, 1)
	finished := make(chan struct{})
	go func() { defer close(finished); done <- f.handler.Execute(context.Background(), f.requests[0]) }()
	var release sync.Once
	t.Cleanup(func() {
		release.Do(func() { close(f.source.release) })
		select {
		case <-finished:
		case <-time.After(time.Second):
			t.Error("uncooperative fixture did not exit after release")
		}
	})
	select {
	case <-f.source.entered:
	case <-time.After(time.Second):
		t.Fatal("actual uncooperative source not reached")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := f.handler.Close(ctx); err == nil {
		t.Fatal("Close pretended active source had drained")
	}
	select {
	case <-finished:
		t.Fatal("fixture was not still active after bounded Close")
	default:
	}
	if handle, err := f.handler.Acquisition(context.Background(), f.plan, acquisitionDigest([]byte("late head"))); err == nil || handle != nil {
		t.Fatal("closing wrapper exposed reference authority")
	}
	release.Do(func() { close(f.source.release) })
	select {
	case result := <-done:
		if result.Status() == controlplane.TaskCompletionSucceeded {
			t.Fatal("late source completion escaped closing fence")
		}
	case <-time.After(time.Second):
		t.Fatal("late source failed to exit")
	}
	cleanup, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	acquisitionCheck(t, f.handler.Close(cleanup))
}
