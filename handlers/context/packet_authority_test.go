package context

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	analysishandler "github.com/georgejieh/open-trestle/handlers/analysis"
	changehandler "github.com/georgejieh/open-trestle/handlers/change"
	memoryhandler "github.com/georgejieh/open-trestle/handlers/memory"
	sourcehandler "github.com/georgejieh/open-trestle/handlers/source"
	"github.com/georgejieh/open-trestle/internal/evidence"
	memorycore "github.com/georgejieh/open-trestle/internal/memory"
	"github.com/georgejieh/open-trestle/internal/scm"
)

type blockedPacketStore struct {
	artifact.Store
	blocked  string
	changed  bool
	putCount *int
	failPut  bool
}

func (s blockedPacketStore) Get(ctx context.Context, scope audit.ReviewScope, id string, at time.Time) (artifact.Artifact, error) {
	if id == s.blocked {
		if !s.changed {
			return artifact.Artifact{}, artifact.ErrArtifactNotFound
		}
		original, err := s.Store.Get(ctx, scope, id, at)
		if err != nil {
			return artifact.Artifact{}, err
		}
		payload := bytes.Replace(original.Payload(), []byte("dW5jaGFuZ2VkCg=="), []byte("Y2hhbmdlZHh4Cg=="), 1)
		return artifact.New(scope, original.Kind(), original.MediaType(), original.Classification(), original.Origin(), original.Protection(), original.Provenance(), payload, original.CreatedAt(), original.ExpiresAt())
	}
	return s.Store.Get(ctx, scope, id, at)
}
func (s blockedPacketStore) Put(ctx context.Context, value artifact.Artifact, at time.Time) (bool, error) {
	if s.putCount != nil {
		*s.putCount++
	}
	if s.failPut && value.Kind() == artifact.KindContextPacket {
		return false, errors.New("injected packet Put failure")
	}
	return s.Store.Put(ctx, value, at)
}

type failingPacketJournal struct {
	controlplane.RunJournal
	fail           bool
	onCancelAppend func()
}

func (j *failingPacketJournal) WithEffectSection(ctx context.Context, effect func() error) error {
	return j.RunJournal.(*controlplane.FileRunJournal).WithEffectSection(ctx, effect)
}

func (j *failingPacketJournal) Append(ctx context.Context, head string, event controlplane.RunEvent) error {
	if j.onCancelAppend != nil && event.Kind() == controlplane.RunEventCanceled {
		j.onCancelAppend()
	}
	if j.fail && event.Kind() == controlplane.RunEventContextPacketPrepared {
		return errors.New("injected v4 append failure")
	}
	return j.RunJournal.Append(ctx, head, event)
}

func newPacketWriterFixture(t *testing.T, blockedFile bool, baseFile bool, legacy bool, crossedRoot bool, failAppend bool) (*PacketAuthority, controlplane.TaskExecutionRequest, *controlplane.Coordinator, artifact.Store, string, func(), *failingPacketJournal) {
	return newPacketWriterFixtureVariant(t, blockedFile, baseFile, legacy, crossedRoot, failAppend, false, false)
}

func newPacketWriterFixtureVariant(t *testing.T, blockedFile bool, baseFile bool, legacy bool, crossedRoot bool, failAppend bool, indexedChangedPath bool, emptyIndex bool) (*PacketAuthority, controlplane.TaskExecutionRequest, *controlplane.Coordinator, artifact.Store, string, func(), *failingPacketJournal) {
	return newPacketWriterFixtureWithMemoryExpiry(t, blockedFile, baseFile, legacy, crossedRoot, failAppend, indexedChangedPath, emptyIndex, time.Time{})
}

func newPacketWriterFixtureWithMemoryExpiry(t *testing.T, blockedFile bool, baseFile bool, legacy bool, crossedRoot bool, failAppend bool, indexedChangedPath bool, emptyIndex bool, memoryValidUntil time.Time) (*PacketAuthority, controlplane.TaskExecutionRequest, *controlplane.Coordinator, artifact.Store, string, func(), *failingPacketJournal) {
	if !memoryValidUntil.IsZero() && (!indexedChangedPath || emptyIndex) {
		t.Fatal("memory expiry requires the indexed changed-path record")
	}
	repository, _ := evidence.NewRepositoryIdentity("github.com", []string{"owner"}, "repo")
	gitRoot := filepath.Join(t.TempDir(), "repo")
	if err := os.Mkdir(gitRoot, 0700); err != nil {
		t.Fatal(err)
	}
	git := func(args ...string) string {
		t.Helper()
		prefix := []string{"-C", gitRoot}
		if indexedChangedPath || emptyIndex {
			prefix = append(prefix, "-c", "commit.gpgsign=false")
		}
		cmd := exec.Command("git", append(prefix, args...)...)
		if indexedChangedPath || emptyIndex {
			cmd.Env = append(os.Environ(), "GIT_AUTHOR_DATE=2001-01-01T00:00:00Z", "GIT_COMMITTER_DATE=2001-01-01T00:00:00Z")
		}
		data, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v: %s", args, err, data)
		}
		return strings.TrimSpace(string(data))
	}
	git("init", "-q")
	write := func(path, text string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(gitRoot, path), []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	testBody := "package p\nfunc TestChanged(){_=Changed()}\n"
	write("a.go", "package p\nfunc Changed() int{return 1}\n")
	write("a_test.go", testBody)
	write("z_unselected.txt", "unchanged\n")
	git("add", ".")
	git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "base")
	baseRevision, _ := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, git("rev-parse", "HEAD"))
	write("a.go", "package p\nfunc Changed() int{return 2}\n")
	write("a_test.go", testBody)
	git("add", ".")
	git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "head")
	headRevision, _ := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, git("rev-parse", "HEAD"))

	adapterIdentity, _ := evidence.NewSourceAdapterIdentity(evidence.SourceAdapterKindGit, "test-source", "1.0.0", []evidence.SourceAdapterCapability{evidence.SourceCapabilityReadManifest, evidence.SourceCapabilityReadContent})
	adapter := &contextTestSource{identity: adapterIdentity, results: map[string]scm.SourceAdapterResult{baseRevision.Identity(): makeSourceResult(t, map[string][]byte{"a.go": []byte("package p\nfunc Changed() int{return 1}\n"), "a_test.go": []byte(testBody), "z_unselected.txt": []byte("unchanged\n")}), headRevision.Identity(): makeSourceResult(t, map[string][]byte{"a.go": []byte("package p\nfunc Changed() int{return 2}\n"), "a_test.go": []byte(testBody), "z_unselected.txt": []byte("unchanged\n")})}}
	root := t.TempDir()
	store, err := artifact.NewFileStore(filepath.Join(root, "artifacts"))
	if err != nil {
		t.Fatal(err)
	}
	scope, _ := audit.NewReviewScope("tenant", "repository", "run")
	sourceRoot := strings.Repeat("8", 64)
	baseInput, _ := sourcehandler.NewBoundInput(repository, baseRevision, adapterIdentity, sourceRoot)
	headRoot := sourceRoot
	if crossedRoot {
		headRoot = strings.Repeat("9", 64)
	}
	headInput, _ := sourcehandler.NewBoundInput(repository, headRevision, adapterIdentity, headRoot)
	if legacy {
		baseInput, _ = sourcehandler.NewInput(repository, baseRevision, adapterIdentity)
		headInput, _ = sourcehandler.NewInput(repository, headRevision, adapterIdentity)
	}
	baseArtifact, _ := sourcehandler.NewInputArtifact(scope, baseInput, artifact.ClassificationConfidential, artifact.ProtectionProcessPrivate, []string{strings.Repeat("e", 64)}, time.UnixMilli(50), time.UnixMilli(120000))
	headArtifact, _ := sourcehandler.NewInputArtifact(scope, headInput, artifact.ClassificationConfidential, artifact.ProtectionProcessPrivate, []string{strings.Repeat("e", 64)}, time.UnixMilli(50), time.UnixMilli(120000))
	_, _ = store.Put(context.Background(), baseArtifact, time.UnixMilli(50))
	_, _ = store.Put(context.Background(), headArtifact, time.UnixMilli(50))
	sourceTaskHandler, _ := sourcehandler.NewHandlerWithSourceRoot(store, adapter, sourceRoot, contextTestClock{time.UnixMilli(200)})
	headSourceHandler := sourceTaskHandler
	if crossedRoot {
		headSourceHandler, _ = sourcehandler.NewHandlerWithSourceRoot(store, adapter, headRoot, contextTestClock{time.UnixMilli(200)})
	}
	if legacy {
		sourceTaskHandler, _ = sourcehandler.NewHandler(store, adapter, contextTestClock{time.UnixMilli(200)})
		headSourceHandler = sourceTaskHandler
	}
	changeTaskHandler, _ := changehandler.NewHandler(store, contextTestClock{time.UnixMilli(210)})
	analysisTaskHandler, _ := analysishandler.NewHandler(store, contextTestClock{time.UnixMilli(215)})
	index := memorycore.NewLexicalIndex()
	memoryScope, scopeErr := memorycore.NewScope("tenant", "repository", "reviewer", memorycore.RefVisibilityExact, headRevision.Identity(), []string{"."})
	if scopeErr != nil {
		t.Fatal(scopeErr)
	}
	if !emptyIndex {
		recordPath := "a.txt"
		if indexedChangedPath {
			recordPath = "a.go"
		}
		recordInput := memorycore.RecordInput{Kind: memorycore.RecordCanonicalFact, Taint: memorycore.TaintTrusted, Path: recordPath, Text: "this path has a parser invariant", EvidenceIDs: []string{strings.Repeat("9", 64)}, ProducerIdentity: strings.Repeat("7", 64), ObservedAt: time.UnixMilli(10), ValidFrom: time.UnixMilli(10)}
		if indexedChangedPath {
			recordInput.ValidUntil = memoryValidUntil
		}
		record, recordErr := memorycore.NewRecord(memoryScope, recordInput)
		if recordErr != nil {
			t.Fatal(recordErr)
		}
		if _, _, err := index.Add(context.Background(), memoryScope, record); err != nil {
			t.Fatal(err)
		}
	}
	policyIdentity := strings.Repeat("f", 64)
	memoryTaskHandler, _ := memoryhandler.NewHandler(store, contextTestClock{time.UnixMilli(220)}, index, strings.Repeat("6", 64), policyIdentity, "reviewer", []string{"."}, 10, 20)
	authorityIdentity := PacketAuthorityHandlerIdentity()
	baseTask, _ := controlplane.NewTaskDefinition("source-base", controlplane.TaskAcquireSource, baseArtifact.Identity(), sourceTaskHandler.HandlerIdentity(), nil, 1, 1000, 30000, true)
	headTask, _ := controlplane.NewTaskDefinition("source-head", controlplane.TaskAcquireSource, headArtifact.Identity(), headSourceHandler.HandlerIdentity(), nil, 1, 1000, 30000, true)
	changeTask, _ := controlplane.NewTaskDefinition("change", controlplane.TaskBuildChange, strings.Repeat("c", 64), changeTaskHandler.HandlerIdentity(), []string{"source-base", "source-head"}, 1, 1000, 30000, true)
	analysisTask, _ := controlplane.NewTaskDefinition("analysis", controlplane.TaskInspectDeterministic, strings.Repeat("3", 64), analysisTaskHandler.HandlerIdentity(), []string{"change"}, 1, 1000, 30000, true)
	memoryTask, _ := controlplane.NewTaskDefinition("memory", controlplane.TaskRetrieveContext, strings.Repeat("d", 64), memoryTaskHandler.HandlerIdentity(), []string{"change"}, 1, 1000, 30000, true)
	contextTask, _ := controlplane.NewTaskDefinition("context", controlplane.TaskAssembleContext, strings.Repeat("4", 64), authorityIdentity, []string{"analysis", "memory"}, 1, 1000, 30000, true)
	plan, err := controlplane.NewReviewRunPlan(scope, strings.Repeat("e", 64), policyIdentity, controlplane.ReviewRunAdvisory, []controlplane.TaskDefinition{baseTask, headTask, changeTask, analysisTask, memoryTask, contextTask})
	if err != nil {
		t.Fatal(err)
	}
	journal, err := controlplane.NewFileRunJournal(filepath.Join(root, "journal"))
	if err != nil {
		t.Fatal(err)
	}
	wrappedJournal := &failingPacketJournal{RunJournal: journal, fail: failAppend}
	var coordinator *controlplane.Coordinator
	if indexedChangedPath || emptyIndex {
		// NewCoordinator retains this reader. Restore the process-global reader
		// even if construction panics; never seed the rest of the producer run.
		coordinator, err = func() (*controlplane.Coordinator, error) {
			originalRandom := rand.Reader
			defer func() { rand.Reader = originalRandom }()
			rand.Reader = bytes.NewReader(bytes.Repeat([]byte{0x42}, 1024))
			return controlplane.NewCoordinator(wrappedJournal)
		}()
	} else {
		coordinator, err = controlplane.NewCoordinator(wrappedJournal)
	}
	if err != nil {
		t.Fatal(err)
	}
	_, _ = coordinator.Open(context.Background(), plan, time.UnixMilli(100))
	var contextRequest controlplane.TaskExecutionRequest
	execute := func(task controlplane.TaskDefinition, handler controlplane.TaskHandler, at time.Time) {
		state, err := coordinator.Advance(context.Background(), plan, at)
		if err != nil {
			t.Fatal(err)
		}
		lease, acquired, err := coordinator.ClaimTask(context.Background(), plan, task.Key(), task.HandlerIdentity(), "worker", at)
		if err != nil || !acquired {
			t.Fatalf("claim %s=(%v,%v)", task.Key(), acquired, err)
		}
		dependencies, err := controlplane.TaskDependencyOutputsFromState(state, task)
		if err != nil {
			t.Fatal(err)
		}
		request, err := controlplane.NewTaskExecutionRequestWithDependencies(plan, task, lease, dependencies)
		if err != nil {
			t.Fatal(err)
		}
		if task.Key() == "context" {
			contextRequest = request
		}
		completion := handler.Execute(context.Background(), request)
		if completion.Status() != controlplane.TaskCompletionSucceeded {
			t.Fatalf("%s completion=%#v failure=%s", task.Key(), completion, completion.Failure())
		}
		if _, err := coordinator.CompleteTask(context.Background(), plan, lease, completion, at.Add(time.Millisecond)); err != nil {
			t.Fatal(err)
		}
	}
	execute(baseTask, sourceTaskHandler, time.UnixMilli(101))
	execute(headTask, headSourceHandler, time.UnixMilli(103))
	execute(changeTask, changeTaskHandler, time.UnixMilli(105))
	execute(analysisTask, analysisTaskHandler, time.UnixMilli(107))
	execute(memoryTask, memoryTaskHandler, time.UnixMilli(109))
	state, err := coordinator.Advance(context.Background(), plan, time.UnixMilli(111))
	if err != nil {
		t.Fatal(err)
	}
	lease, ok, err := coordinator.ClaimTask(context.Background(), plan, "context", authorityIdentity, "worker", time.UnixMilli(111))
	if err != nil || !ok {
		t.Fatalf("context claim: %v", err)
	}
	dependencies, err := controlplane.TaskDependencyOutputsFromState(state, contextTask)
	if err != nil {
		t.Fatal(err)
	}
	contextRequest, err = controlplane.NewTaskExecutionRequestWithDependencies(plan, contextTask, lease, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	if blockedFile {
		_, current, err := coordinator.Resume(context.Background(), scope)
		if err != nil {
			t.Fatal(err)
		}
		snapshotKey := "source-head"
		if baseFile {
			snapshotKey = "source-base"
		}
		runtime, _ := current.Task(snapshotKey)
		snapshotArtifact, err := store.Get(context.Background(), scope, runtime.OutputIdentity(), time.UnixMilli(230))
		if err != nil {
			t.Fatal(err)
		}
		snapshot, err := sourcehandler.ParseSnapshotArtifact(snapshotArtifact)
		if err != nil {
			t.Fatal(err)
		}
		for _, ref := range snapshot.Files() {
			if ref.Path() == "z_unselected.txt" {
				return NewPacketAuthority(blockedPacketStore{Store: store, blocked: ref.ArtifactIdentity()}, coordinator, contextTestClock{time.UnixMilli(230)}, sourceRoot), contextRequest, coordinator, store, root, func() { _ = journal.Close(); _ = store.Close() }, wrappedJournal
			}
		}
		t.Fatal("nonselected file absent")
	}
	return NewPacketAuthority(store, coordinator, contextTestClock{time.UnixMilli(230)}, sourceRoot), contextRequest, coordinator, store, root, func() { _ = journal.Close(); _ = store.Close() }, wrappedJournal
}
func TestPacketAuthorityFileBackedPreflight(t *testing.T) {
	for _, tc := range []struct {
		name                                                                                           string
		blocked, changed, baseFile, legacy, crossedRoot, appendFailure, putFailure, succeeds, prepared bool
	}{
		{"bound", false, false, false, false, false, false, false, true, true},
		{"nonselected_head_file_missing", true, false, false, false, false, false, false, false, false},
		{"nonselected_head_file_changed", true, true, false, false, false, false, false, false, false},
		{"base_file_changed", true, true, true, false, false, false, false, false, false},
		{"legacy_source_inputs", false, false, false, true, false, false, false, false, false},
		{"crossed_v2_source_roots", false, false, false, false, true, false, false, false, false},
		{"retained_owner_root_mismatch", false, false, false, false, false, false, false, false, false},
		{"append_failure", false, false, false, false, false, true, false, false, false},
		{"packet_put_failure", false, false, false, false, false, false, true, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			authority, request, coordinator, store, root, closeFixture, _ := newPacketWriterFixture(t, tc.blocked, tc.baseFile, tc.legacy, tc.crossedRoot, tc.appendFailure)
			defer closeFixture()
			if tc.name == "retained_owner_root_mismatch" {
				authority.ownerRoot = strings.Repeat("a", 64)
			}
			if tc.changed {
				storeWrapper := authority.store.(blockedPacketStore)
				storeWrapper.changed = true
				authority.store = storeWrapper
			}
			puts := 0
			authority.store = blockedPacketStore{Store: authority.store, putCount: &puts, failPut: tc.putFailure}
			prepared, prepareErr := authority.Prepare(context.Background(), request)
			err := prepareErr
			if tc.succeeds && err != nil {
				t.Fatal(err)
			}
			if !tc.succeeds && err == nil {
				t.Fatal("unproven source accepted")
			}
			_, state, err := coordinator.Resume(context.Background(), request.Plan().Scope())
			if err != nil {
				t.Fatal(err)
			}
			runtime, _ := state.Task("context")
			checkpoint, exists := runtime.PreparedContextPacket()
			if exists != tc.prepared {
				t.Fatalf("prepared=%v err=%v", exists, err)
			}
			if !tc.prepared && puts != 0 {
				t.Fatalf("preparation failure wrote %d packets", puts)
			}
			if tc.putFailure && (puts != 1 || prepared.Identity() != checkpoint.Identity()) {
				t.Fatal("failed packet Put lost durable intent")
			}
			if tc.succeeds {
				if checkpoint.Identity() != prepared.Identity() {
					t.Fatal("changed intent")
				}
				d := checkpoint.Descriptor()
				if d.SourceRootIdentity != strings.Repeat("8", 64) || d.LeaseIdentity != request.Lease().Identity() || d.LeaseEventIdentity != request.Lease().EventIdentity() || len(d.DependencyIdentities) != 2 || len(d.Provenance) != 6 {
					t.Fatal("descriptor authority fields differ")
				}
				for _, key := range []string{"analysis", "memory"} {
					dep, _ := request.DependencyOutput(key)
					if !slices.Contains(d.DependencyIdentities, dep.OutputIdentity()) || !slices.Contains(d.Provenance, dep.OutputIdentity()) {
						t.Fatalf("missing %s dependency", key)
					}
				}
				h := &Handler{store: store, packetOnly: true}
				assembly, providerRequest, _, failure := h.assemble(context.Background(), request, time.UnixMilli(230))
				if failure != 0 || d.SnapshotIdentity != assembly.Snapshot.Identity() || d.SnapshotIdentity == assembly.HeadSnapshotArtifact.Identity() || d.ArtifactIdentity != assembly.InitialContextArtifact.Identity() || d.PayloadDigest != assembly.InitialContextArtifact.PayloadDigest() || !bytes.Equal(assembly.InitialContextArtifact.Payload(), providerRequest.Payload()) {
					t.Fatal("descriptor differs from selected physical packet")
				}
				if assembly.HeadSnapshotArtifact.ExpiresAt().Before(time.UnixMilli(d.ExpiresAtMilliseconds)) {
					t.Fatal("packet outlives source")
				}
				for _, item := range assembly.Packet.EvidenceItems() {
					if item.SourceRange().Path() == "z_unselected.txt" {
						t.Fatal("nonselected mutation fixture accidentally selected")
					}
				}

				value, getErr := store.Get(context.Background(), request.Plan().Scope(), checkpoint.Descriptor().ArtifactIdentity, time.UnixMilli(230))
				if getErr != nil || value.Identity() != checkpoint.Descriptor().ArtifactIdentity {
					t.Fatalf("packet readback: %v", getErr)
				}
				if _, err := coordinator.TerminatePreparedContextPacket(context.Background(), request.Plan(), checkpoint, request.Lease().ExpiresAt().Add(time.Millisecond)); err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(prepareErr, ErrPacketAuthority) {
				t.Fatalf("unexpected failure: %v", err)
			}
			closeFixture()
			reopenedJournal, reopenErr := controlplane.NewFileRunJournal(filepath.Join(root, "journal"))
			if reopenErr != nil {
				t.Fatal(reopenErr)
			}
			defer reopenedJournal.Close()
			reopenedStore, reopenErr := artifact.NewFileStore(filepath.Join(root, "artifacts"))
			if reopenErr != nil {
				t.Fatal(reopenErr)
			}
			defer reopenedStore.Close()
			recovered, _ := controlplane.NewCoordinator(reopenedJournal)
			_, recoveredState, reopenErr := recovered.Resume(context.Background(), request.Plan().Scope())
			if reopenErr != nil {
				t.Fatal(reopenErr)
			}
			recoveredRuntime, _ := recoveredState.Task("context")
			durable, existsAfterReopen := recoveredRuntime.PreparedContextPacket()
			if tc.succeeds {
				if existsAfterReopen || recoveredRuntime.Status() != controlplane.TaskRuntimeFailed || recoveredRuntime.OutputIdentity() != "" {
					t.Fatal("post-expiry no-output terminal lost")
				}
			} else if existsAfterReopen != tc.prepared || existsAfterReopen && durable.Identity() != checkpoint.Identity() {
				t.Fatal("v4 intent lost or forged after reopening journal")
			}
			if tc.putFailure && existsAfterReopen {
				if _, getErr := reopenedStore.Get(context.Background(), request.Plan().Scope(), durable.Descriptor().ArtifactIdentity, time.UnixMilli(231)); !errors.Is(getErr, artifact.ErrArtifactNotFound) {
					t.Fatalf("failed Put left unexpected bytes: %v", getErr)
				}
			}
		})
	}
}
