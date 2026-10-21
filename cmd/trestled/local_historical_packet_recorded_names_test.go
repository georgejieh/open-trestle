package main

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/controlplane"
	analysishandler "github.com/georgejieh/open-trestle/handlers/analysis"
	changehandler "github.com/georgejieh/open-trestle/handlers/change"
	contexthandler "github.com/georgejieh/open-trestle/handlers/context"
	memoryhandler "github.com/georgejieh/open-trestle/handlers/memory"
	sourcehandler "github.com/georgejieh/open-trestle/handlers/source"
	memorycore "github.com/georgejieh/open-trestle/internal/memory"
	"github.com/georgejieh/open-trestle/internal/sourceinput"
	"github.com/georgejieh/open-trestle/internal/sourceoutput"
	"github.com/georgejieh/open-trestle/runtimecatalog"
)

type recordedNamesBinding struct {
	kind controlplane.TaskKind
	id   string
}

func (h recordedNamesBinding) Kind() controlplane.TaskKind { return h.kind }
func (h recordedNamesBinding) HandlerIdentity() string     { return h.id }
func (h recordedNamesBinding) Execute(context.Context, controlplane.TaskExecutionRequest) controlplane.TaskCompletion {
	panic("recorded names must never execute catalog handlers")
}

type recordedNamesFixture struct {
	fact         controlplane.HistoricalContextPacketFact
	a            historicalRecordedV4Artifacts
	root         string
	catalog      runtimecatalog.PipelineCatalog
	binding      historicalRecordedSourceBinding
	journal      *controlplane.FileRunJournal
	coordinator  *controlplane.Coordinator
	prepared     controlplane.PreparedContextPacket
	ownerFixture localPacketOwnerFixture
	journalPath  string
}

// Reuse synthetic source artifacts, then record their exact first-attempt
// successes under the canonical nine-task recipe. No model or scanner runs.
func newRecordedNamesFixture(t *testing.T, alter func([]controlplane.TaskDefinition) []controlplane.TaskDefinition, attempt2 string, suffix bool) recordedNamesFixture {
	t.Helper()
	ctx := context.Background()
	f, initialPlan, _ := prepareLocalPacketOwnerFixture(t)
	baseTask, _ := initialPlan.Task("source-base")
	headTask, _ := initialPlan.Task("source-head")
	oldBase, err := f.store.Get(ctx, initialPlan.Scope(), baseTask.InputIdentity(), f.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	oldHead, err := f.store.Get(ctx, initialPlan.Scope(), headTask.InputIdentity(), f.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	baseInput, err := sourceinput.ParseInput(oldBase.Payload())
	if err != nil {
		t.Fatal(err)
	}
	headInput, err := sourceinput.ParseInput(oldHead.Payload())
	if err != nil {
		t.Fatal(err)
	}
	source, err := sourcehandler.NewHandlerWithSourceRoot(f.store, f.adapter, f.rootDigest, f.clock)
	if err != nil {
		t.Fatal(err)
	}
	change, err := changehandler.NewHandler(f.store, f.clock)
	if err != nil {
		t.Fatal(err)
	}
	analysis, err := analysishandler.NewHandler(f.store, f.clock)
	if err != nil {
		t.Fatal(err)
	}
	memory, err := memoryhandler.NewHandler(f.store, f.clock, memorycore.NewLexicalIndex(), strings.Repeat("6", 64), initialPlan.PolicyIdentity(), "reviewer", []string{"."}, 10, 20)
	if err != nil {
		t.Fatal(err)
	}
	handlers := []controlplane.TaskHandler{source, change, analysis, memory, recordedNamesBinding{controlplane.TaskAssembleContext, contexthandler.PacketAuthorityHandlerIdentity()}, recordedNamesBinding{controlplane.TaskGenerateCandidates, strings.Repeat("1", 64)}, recordedNamesBinding{controlplane.TaskVerifyCandidates, strings.Repeat("2", 64)}, recordedNamesBinding{controlplane.TaskEvaluatePublication, strings.Repeat("3", 64)}}
	catalog, err := runtimecatalog.NewPipelineCatalog(controlplane.ReviewRunLocal, handlers)
	if err != nil {
		t.Fatal(err)
	}
	preparedRequest, err := runtimecatalog.NewPreparedReviewRequest(runtimecatalog.PreparedReviewRequestOptions{Scope: initialPlan.Scope(), HostRequestIdentity: strings.Repeat("e", 64), Repository: f.repository, BaseRevision: baseInput.Revision(), HeadRevision: headInput.Revision(), SourceAdapter: f.adapter.Identity(), SourceRootIdentity: f.rootDigest, InventoryIdentity: strings.Repeat("a", 64), RuntimePolicyIdentity: strings.Repeat("b", 64), ReviewPolicyIdentity: initialPlan.PolicyIdentity(), Classification: oldBase.Classification(), Protection: oldBase.Protection(), CreatedAt: oldBase.CreatedAt(), Retention: oldBase.ExpiresAt().Sub(oldBase.CreatedAt()), Catalog: catalog, RequireBoundSource: true})
	if err != nil {
		t.Fatal(err)
	}
	preparedRun, err := runtimecatalog.PrepareReviewRun(ctx, preparedRequest)
	if err != nil {
		t.Fatal(err)
	}
	plan := preparedRun.Plan()
	if alter != nil {
		plan, err = controlplane.NewReviewRunPlan(plan.Scope(), plan.RequestIdentity(), plan.PolicyIdentity(), plan.Mode(), alter(plan.Tasks()))
		if err != nil {
			t.Fatal(err)
		}
	}
	inputs := preparedRun.Inputs()
	for _, value := range inputs {
		if _, err := f.store.Put(ctx, value, value.CreatedAt()); err != nil {
			t.Fatal(err)
		}
	}
	a := historicalRecordedV4Artifacts{BaseInput: inputs[0], HeadInput: inputs[1]}
	get := func(id string) artifact.Artifact {
		t.Helper()
		value, err := f.store.Get(ctx, plan.Scope(), id, f.clock.Now())
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	journalPath := filepath.Join(t.TempDir(), "journal")
	j, err := controlplane.NewFileRunJournal(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := j.Close(); err != nil {
			t.Error(err)
		}
	})
	c, err := controlplane.NewCoordinator(j)
	if err != nil {
		t.Fatal(err)
	}
	at := time.UnixMilli(100)
	if _, err := c.Open(ctx, plan, at); err != nil {
		t.Fatal(err)
	}
	executors := map[string]controlplane.TaskHandler{"source-base": source, "source-head": source, "change": change, "analysis": analysis, "memory": memory}
	for _, key := range []string{"source-base", "source-head", "change", "analysis", "memory"} {
		task, _ := plan.Task(key)
		at = at.Add(time.Millisecond)
		if _, err := c.Advance(ctx, plan, at); err != nil {
			t.Fatal(err)
		}
		lease, ok, err := c.ClaimTask(ctx, plan, key, task.HandlerIdentity(), "worker", at)
		if err != nil || !ok {
			t.Fatal("claim", key, err)
		}
		if key == attempt2 {
			failure, _ := controlplane.NewTaskFailure(controlplane.RunFailureTransient)
			failed, err := c.CompleteTask(ctx, plan, lease, failure, at.Add(time.Millisecond))
			if err != nil {
				t.Fatal(err)
			}
			runtime, _ := failed.Task(key)
			at = runtime.RetryAt().Add(time.Millisecond)
			if _, err := c.Advance(ctx, plan, at); err != nil {
				t.Fatal(err)
			}
			lease, ok, err = c.ClaimTask(ctx, plan, key, task.HandlerIdentity(), "worker", at)
			if err != nil || !ok {
				t.Fatal(err)
			}
		}
		_, before, err := c.Resume(ctx, plan.Scope())
		if err != nil {
			t.Fatal(err)
		}
		dependencies, err := controlplane.TaskDependencyOutputsFromState(before, task)
		if err != nil {
			t.Fatal(err)
		}
		execution, err := controlplane.NewTaskExecutionRequestWithDependencies(plan, task, lease, dependencies)
		if err != nil {
			t.Fatal(err)
		}
		success := executors[key].Execute(ctx, execution)
		if success.Status() != controlplane.TaskCompletionSucceeded {
			t.Fatal("synthetic execute", key, success.Failure())
		}
		value := get(success.OutputIdentity())
		switch key {
		case "source-base":
			a.BaseSnapshot = value
		case "source-head":
			a.HeadSnapshot = value
		case "change":
			a.Change = value
		case "analysis":
			a.Analysis = value
		case "memory":
			a.Memory = value
		}
		at = at.Add(time.Millisecond)
		if _, err := c.CompleteTask(ctx, plan, lease, success, at); err != nil {
			t.Fatal(err)
		}
	}
	task, _ := plan.Task("context")
	at = at.Add(time.Millisecond)
	state, err := c.Advance(ctx, plan, at)
	if err != nil {
		t.Fatal(err)
	}
	lease, ok, err := c.ClaimTask(ctx, plan, "context", task.HandlerIdentity(), "worker", at)
	if err != nil || !ok {
		t.Fatal(err)
	}
	deps, err := controlplane.TaskDependencyOutputsFromState(state, task)
	if err != nil {
		t.Fatal(err)
	}
	request, err := controlplane.NewTaskExecutionRequestWithDependencies(plan, task, lease, deps)
	if err != nil {
		t.Fatal(err)
	}
	clock := localPacketFixtureClock{at.Add(time.Millisecond)}
	prepared, err := contexthandler.NewPacketAuthority(f.store, c, clock, f.rootDigest).Prepare(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	a.Packet = get(prepared.Descriptor().ArtifactIdentity)
	if suffix {
		if _, err := c.CancelRun(ctx, plan, clock.Now().Add(time.Millisecond)); err != nil {
			t.Fatal(err)
		}
	}
	facts, err := j.InspectHistoricalContextPackets(ctx)
	if err != nil || len(facts) != 1 {
		t.Fatal("facts", len(facts), err)
	}
	return recordedNamesFixture{fact: facts[0], a: a, root: f.rootDigest, catalog: catalog, binding: historicalRecordedSourceBinding{f.rootDigest, f.repository.Identity(), f.adapter.Identity().Identity()}, journal: j, coordinator: c, prepared: prepared, ownerFixture: f, journalPath: journalPath}
}

func TestRecordedHistoricalV4NamesRejectsEmpty(t *testing.T) {
	if ids, err := recordedHistoricalV4Names(controlplane.HistoricalContextPacketFact{}, historicalRecordedV4Artifacts{}, historicalRecordedSourceBinding{}); err == nil || ids != nil {
		t.Fatal("empty accepted")
	}
}

func TestRecordedHistoricalV4NamesExactRecipeAndNameOnlySourceRefs(t *testing.T) {
	f := newRecordedNamesFixture(t, nil, "", false)
	ids, err := recordedHistoricalV4Names(f.fact, f.a, f.binding)
	if err != nil {
		t.Fatal(err)
	}
	expected := []string{f.a.BaseInput.Identity(), f.a.HeadInput.Identity(), f.a.BaseSnapshot.Identity(), f.a.HeadSnapshot.Identity(), f.a.Change.Identity(), f.a.Analysis.Identity(), f.a.Memory.Identity(), f.a.Packet.Identity()}
	for _, value := range []artifact.Artifact{f.a.BaseSnapshot, f.a.HeadSnapshot} {
		snapshot, err := sourceoutput.ParseSnapshotArtifact(value)
		if err != nil {
			t.Fatal(err)
		}
		for _, ref := range snapshot.Files() {
			expected = append(expected, ref.ArtifactIdentity())
		}
	}
	slices.Sort(expected)
	expected = slices.Compact(expected)
	if !slices.Equal(ids, expected) {
		t.Fatal("wrong exact name closure", len(ids), len(expected))
	}
	for _, task := range f.fact.Plan().Tasks() {
		if task.Kind() != controlplane.TaskAcquireSource && slices.Contains(ids, task.InputIdentity()) {
			t.Fatal("recipe digest admitted as artifact")
		}
	}
	ids[0] = "changed"
	again, err := recordedHistoricalV4Names(f.fact, f.a, f.binding)
	if err != nil || !slices.Equal(again, expected) {
		t.Fatal("returned names alias")
	}
	// No source-file artifacts are inputs to the pure parser. Their bytes cannot
	// affect this result, which intentionally proves names rather than contents.
}

func TestRecordedHistoricalV4NamesRefusesWrongInputsAndCatalog(t *testing.T) {
	f := newRecordedNamesFixture(t, nil, "", false)
	for _, tc := range []struct {
		name   string
		change func(*historicalRecordedV4Artifacts)
	}{
		{"swapped-snapshots", func(a *historicalRecordedV4Artifacts) {
			a.BaseSnapshot, a.HeadSnapshot = a.HeadSnapshot, a.BaseSnapshot
		}},
		{"swapped-inputs", func(a *historicalRecordedV4Artifacts) { a.BaseInput, a.HeadInput = a.HeadInput, a.BaseInput }},
		{"role-collision", func(a *historicalRecordedV4Artifacts) { a.Change = a.Analysis }},
		{"missing-memory", func(a *historicalRecordedV4Artifacts) { a.Memory = artifact.Artifact{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := f.a
			tc.change(&a)
			if ids, err := recordedHistoricalV4Names(f.fact, a, f.binding); err == nil || ids != nil {
				t.Fatal("cross-wired role accepted")
			}
		})
	}
	if _, err := recordedHistoricalV4Names(f.fact, f.a, historicalRecordedSourceBinding{strings.Repeat("a", 64), f.binding.RepositoryIdentity, f.binding.AdapterIdentity}); err == nil {
		t.Fatal("wrong root")
	}
	bindings := f.catalog.Bindings()
	handlers := []controlplane.TaskHandler{}
	for _, binding := range bindings {
		if binding.Kind == controlplane.TaskBuildChange {
			binding.HandlerIdentity = strings.Repeat("a", 64)
		}
		handlers = append(handlers, recordedNamesBinding{binding.Kind, binding.HandlerIdentity})
	}
	wrong, err := runtimecatalog.NewPipelineCatalog(controlplane.ReviewRunLocal, handlers)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateEnrolledCatalog(f.fact.Plan(), wrong); err == nil {
		t.Fatal("wrong catalog handler")
	}
}

func TestRecordedHistoricalV4NamesRefusesRetryAndSuffix(t *testing.T) {
	for _, key := range []string{"source-base", "change", "analysis", "memory"} {
		t.Run(key, func(t *testing.T) {
			f := newRecordedNamesFixture(t, nil, key, false)
			if _, err := recordedHistoricalV4Names(f.fact, f.a, f.binding); err == nil {
				t.Fatal("attempt2 accepted")
			}
		})
	}
	f := newRecordedNamesFixture(t, nil, "", true)
	if _, err := recordedHistoricalV4Names(f.fact, f.a, f.binding); err == nil {
		t.Fatal("post-v4 suffix accepted")
	}
}

func TestRecordedHistoricalV4NamesSourceRefCollisionConsistencyAndBound(t *testing.T) {
	known := strings.Repeat("a", 64)
	id := strings.Repeat("b", 64)
	digest := strings.Repeat("c", 64)
	ref := sourceoutput.NewFileReference("a.go", digest, 10, id)
	names := map[string]struct{}{known: {}}
	if err := recordedV4AddSourceNames(names, []sourceoutput.FileReference{ref}, []sourceoutput.FileReference{ref}); err != nil || len(names) != 2 {
		t.Fatal("consistent shared ref", err)
	}
	if err := recordedV4AddSourceNames(map[string]struct{}{id: {}}, []sourceoutput.FileReference{ref}); err == nil {
		t.Fatal("known role collision")
	}
	bad := sourceoutput.NewFileReference("b.go", digest, 10, id)
	if err := recordedV4AddSourceNames(map[string]struct{}{}, []sourceoutput.FileReference{ref, bad}); err == nil {
		t.Fatal("inconsistent shared ref")
	}
	names = make(map[string]struct{}, physicalPacketEntryLimit)
	for i := 0; i < physicalPacketEntryLimit-1; i++ {
		names[fmt.Sprintf("%064x", i+1)] = struct{}{}
	}
	if err := recordedV4AddSourceNames(names, []sourceoutput.FileReference{ref}); err == nil {
		t.Fatal("name ceiling increased")
	}
}

func TestRecordedHistoricalV4NamesRefusesRecipeAndCanonicalArtifactAlternatives(t *testing.T) {
	f := newRecordedNamesFixture(t, nil, "", false)
	for _, mutation := range []string{"required", "lease", "handler", "deps"} {
		t.Run(mutation, func(t *testing.T) {
			tasks := f.fact.Plan().Tasks()
			for i, task := range tasks {
				if task.Key() != "readiness" {
					continue
				}
				required := task.Required()
				lease := task.LeaseDurationMilliseconds()
				handler := task.HandlerIdentity()
				deps := task.Dependencies()
				switch mutation {
				case "required":
					required = false
				case "lease":
					lease++
				case "handler":
					handler = strings.Repeat("a", 64)
				case "deps":
					deps = []string{"verification"}
				}
				changed, err := controlplane.NewTaskDefinition(task.Key(), task.Kind(), task.InputIdentity(), handler, deps, task.MaxAttempts(), task.RetryDelayMilliseconds(), lease, required)
				if err != nil {
					t.Fatal(err)
				}
				tasks[i] = changed
			}
			plan, err := controlplane.NewReviewRunPlan(f.fact.Plan().Scope(), f.fact.Plan().RequestIdentity(), f.fact.Plan().PolicyIdentity(), controlplane.ReviewRunLocal, tasks)
			if err != nil {
				if mutation == "required" {
					return
				} // Plan validation already refuses this unsafe recipe.
				t.Fatal(err)
			}
			if mutation == "handler" {
				if validateEnrolledCatalog(plan, f.catalog) == nil {
					t.Fatal("current handler mismatch accepted")
				}
			} else if recordedV4PlanShape(plan) {
				t.Fatal("unsupported recipe accepted")
			}
		})
	}
	for _, mutation := range []string{"provenance", "payload", "classification", "origin", "schema1"} {
		t.Run(mutation, func(t *testing.T) {
			a := f.a
			value := a.BaseInput
			provenance := value.Provenance()
			payload := value.Payload()
			classification := value.Classification()
			origin := value.Origin()
			switch mutation {
			case "provenance":
				provenance = []string{strings.Repeat("a", 64)}
			case "payload":
				payload = []byte(`{"invalid":true}`)
			case "classification":
				classification = artifact.ClassificationInternal
			case "origin":
				origin = artifact.OriginRepository
			case "schema1":
				payload = []byte(strings.Replace(string(payload), `"schema_version":2`, `"schema_version":1`, 1))
			}
			changed, err := artifact.New(value.Scope(), value.Kind(), value.MediaType(), classification, origin, value.Protection(), provenance, payload, value.CreatedAt(), value.ExpiresAt())
			if err != nil {
				t.Fatal(err)
			}
			a.BaseInput = changed
			if _, err := recordedHistoricalV4Names(f.fact, a, f.binding); err == nil {
				t.Fatal("alternative unrecorded input accepted")
			}
		})
	}
}

func TestRecordedV4SplitRequiresPreparedTaskRecipe(t *testing.T) {
	f := newRecordedNamesFixture(t, nil, "", false)
	for _, task := range f.fact.Plan().Tasks() {
		if task.Kind() == controlplane.TaskAcquireSource {
			continue
		}
		tasks := f.fact.Plan().Tasks()
		for i, other := range tasks {
			if other.Key() == task.Key() {
				changed, err := controlplane.NewTaskDefinition(other.Key(), other.Kind(), strings.Repeat("f", 64), other.HandlerIdentity(), other.Dependencies(), other.MaxAttempts(), other.RetryDelayMilliseconds(), other.LeaseDurationMilliseconds(), other.Required())
				if err != nil {
					t.Fatal(err)
				}
				tasks[i] = changed
			}
		}
		plan, err := controlplane.NewReviewRunPlan(f.fact.Plan().Scope(), f.fact.Plan().RequestIdentity(), f.fact.Plan().PolicyIdentity(), f.fact.Plan().Mode(), tasks)
		if err != nil {
			t.Fatal(err)
		}
		if recordedV4PlanShape(plan) {
			t.Fatal("unprepared recipe accepted", task.Key())
		}
	}
}

func TestRecordedV4SplitBindingAndClosedExpiryTail(t *testing.T) {
	f := newRecordedNamesFixture(t, nil, "", false)
	for _, binding := range []historicalRecordedSourceBinding{{}, {RootIdentity: f.binding.RootIdentity, RepositoryIdentity: strings.Repeat("a", 64), AdapterIdentity: f.binding.AdapterIdentity}, {RootIdentity: f.binding.RootIdentity, RepositoryIdentity: f.binding.RepositoryIdentity, AdapterIdentity: strings.Repeat("a", 64)}} {
		if _, err := recordedHistoricalV4Names(f.fact, f.a, binding); err == nil {
			t.Fatal("external source binding mismatch accepted")
		}
	}
	if err := validateEnrolledCatalog(f.fact.Plan(), f.catalog); err != nil {
		t.Fatal(err)
	}
	// Terminate and advance use only the existing canonical coordinator protocol.
	at := f.fact.LeaseEvent().LeaseExpiresAt()
	if _, err := f.coordinator.TerminatePreparedContextPacket(context.Background(), f.fact.Plan(), f.prepared, at); err != nil {
		t.Fatal(err)
	}
	facts, err := f.journal.InspectHistoricalContextPackets(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if facts[0].ExpiryTail() != controlplane.ContextPacketExpiryTailExpiredV4PolicyTerminated {
		t.Fatal("missing closed policy tail")
	}
	if _, err := recordedHistoricalV4Names(facts[0], f.a, f.binding); err != nil {
		t.Fatal("closed interrupted expiry tail refused", err)
	}
	if _, err := f.coordinator.Advance(context.Background(), f.fact.Plan(), at.Add(time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	events, err := f.journal.Read(context.Background(), f.fact.Plan().Scope(), 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	// Reopen each canonical interrupted cleanup prefix in a separate synthetic
	// journal so parser support does not depend on Advance batching its suffix.
	for end := int(f.fact.PreparedEvent().Sequence()) + 1; end <= len(events); end++ {
		journal, err := controlplane.NewFileRunJournal(filepath.Join(t.TempDir(), "prefix"))
		if err != nil {
			t.Fatal(err)
		}
		if err := journal.SavePlan(context.Background(), f.fact.Plan()); err != nil {
			t.Fatal(err)
		}
		for _, event := range events[:end] {
			if err := journal.Append(context.Background(), event.PreviousIdentity(), event); err != nil {
				t.Fatal(err)
			}
		}
		observed, err := journal.InspectHistoricalContextPackets(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := recordedHistoricalV4Names(observed[0], f.a, f.binding); err != nil {
			t.Fatal("closed prefix refused", end, err)
		}
		if err := journal.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
