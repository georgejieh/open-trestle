package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	analysishandler "github.com/georgejieh/open-trestle/handlers/analysis"
	changehandler "github.com/georgejieh/open-trestle/handlers/change"
	contexthandler "github.com/georgejieh/open-trestle/handlers/context"
	memoryhandler "github.com/georgejieh/open-trestle/handlers/memory"
	sourcehandler "github.com/georgejieh/open-trestle/handlers/source"
	"github.com/georgejieh/open-trestle/internal/evidence"
	memorycore "github.com/georgejieh/open-trestle/internal/memory"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/internal/scm"
	"github.com/georgejieh/open-trestle/setup"
)

type localPacketFixtureClock struct{ at time.Time }

func (c localPacketFixtureClock) Now() time.Time { return c.at }

type localPacketFixtureReader struct{ store *artifact.FileStore }

func (r localPacketFixtureReader) Get(ctx context.Context, scope audit.ReviewScope, identity string, at time.Time) (artifact.Artifact, error) {
	return r.store.Get(ctx, scope, identity, at)
}

type localPacketOwnerFixture struct {
	store       *artifact.FileStore
	journal     *controlplane.FileRunJournal
	owner       *localPacketOwner
	resources   *daemon
	coordinator *controlplane.Coordinator
	request     controlplane.TaskExecutionRequest
	rootDigest  string
	statePath   string
	setupPath   string
	setupPlan   setup.Plan
	repository  evidence.RepositoryIdentity
	gitRoot     *os.Root
	objectStore *scm.LocalGitObjectStore
	adapter     *scm.LocalGitSourceAdapter
	clock       localPacketFixtureClock
}

func prepareLocalPacketOwnerFixture(t *testing.T) (localPacketOwnerFixture, controlplane.ReviewRunPlan, []controlplane.TaskHandler) {
	return prepareLocalPacketOwnerFixtureWithUnselected(t, false)
}

func prepareLocalPacketOwnerFixtureWithUnselected(t *testing.T, unselected bool) (localPacketOwnerFixture, controlplane.ReviewRunPlan, []controlplane.TaskHandler) {
	t.Helper()
	ctx := context.Background()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	objects := filepath.Join(root, "repository", ".git", "objects")
	if err := os.MkdirAll(objects, 0o700); err != nil {
		t.Fatal(err)
	}
	makeRevision := daemonTestRevision
	if unselected {
		extra := daemonWriteLooseObject(t, objects, "blob", []byte("unselected immutable source witness\n"))
		makeRevision = func(t *testing.T, objects string, source []byte) evidence.RevisionIdentity {
			return singleBuildRevisionWithUnselected(t, objects, source, extra)
		}
	}
	base := makeRevision(t, objects, []byte("package main\nfunc main() {}\n"))
	head := makeRevision(t, objects, []byte("package main\nimport \"fmt\"\nfunc main() { fmt.Println(\"debug\") }\n"))
	setupDirectory := filepath.Join(root, "setup")
	if err := os.Mkdir(setupDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	setupPath := filepath.Join(setupDirectory, "plan.json")
	setupPlan, err := setup.NewPlan(setup.ProfileLocalSingleNode, "tenant-a", "repo-a", "platform-owner", time.Now().UTC().Add(-time.Minute).Truncate(time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	setupFile, err := setup.OpenStateFile(setupPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := setupFile.Initialize(ctx, setupPlan); err != nil {
		_ = setupFile.Close()
		t.Fatal(err)
	}
	if err := setupFile.Close(); err != nil {
		t.Fatal(err)
	}
	repository, err := evidence.NewRepositoryIdentity("local.test", []string{"team"}, "repository")
	if err != nil {
		t.Fatal(err)
	}
	gitRoot, digest, err := openDaemonLocalGitRoot(objects, repository)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := gitRoot.Close(); err != nil {
			t.Errorf("close Git root: %v", err)
		}
	})
	objectStore, err := scm.NewLocalGitObjectStore(gitRoot, repository)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := scm.NewLocalGitSourceAdapter(objectStore)
	if err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(root, "runtime")
	resources := &daemon{}
	t.Cleanup(func() {
		if err := resources.Close(); err != nil {
			t.Errorf("close owner resources: %v", err)
		}
	})
	clock := localPacketFixtureClock{time.UnixMilli(230)}
	store, journal, owner, err := startLocalSourceOwnerGate(ctx, resources, statePath, setupPath, &setupPlan, "tenant-a", "repo-a", repository, gitRoot, objectStore, adapter, digest, clock)
	if err != nil {
		t.Fatal(err)
	}
	if store == nil || journal == nil || owner == nil {
		t.Fatal("Git-qualified boot did not return raw local resources and private owner")
	}
	if owner.store != store || owner.journal != journal || owner.sourceRootDigest != digest || owner.clock != clock {
		t.Fatal("boot-returned owner is not bound to enrolled raw resources, source digest, and trusted clock")
	}
	if err := journal.WithOwnedRoot(ctx, func(stateRoot *os.Root) error {
		record, readErr := readLocalSourceOwnerRecord(stateRoot, statePath)
		if readErr != nil {
			return readErr
		}
		gitID, gitErr := observeLocalSourceDirectory(objects, gitRoot)
		if gitErr != nil {
			return gitErr
		}
		stateID, stateErr := observeLocalSourceDirectory(statePath, stateRoot)
		if stateErr != nil {
			return stateErr
		}
		artifactRoot, openErr := os.OpenRoot(filepath.Join(statePath, "artifacts"))
		if openErr != nil {
			return openErr
		}
		artifactID, artifactErr := observeLocalSourceArtifactDirectory(stateRoot, artifactRoot, statePath)
		if artifactErr != nil {
			return errors.Join(artifactErr, artifactRoot.Close())
		}
		matchErr := matchLocalSourceOwnerRecord(record, localSourceOwnerRecord{
			StatePath: statePath, ArtifactPath: filepath.Join(statePath, "artifacts"), GitObjectsPath: objects,
			TenantID: "tenant-a", RepositoryID: "repo-a", RepositoryIdentity: repository.Identity(),
			AdapterIdentity: adapter.Identity().Identity(), Profile: string(objectStore.Profile()), SourcePathDigest: digest,
			Git: gitID, State: stateID, Artifact: artifactID,
		})
		return errors.Join(matchErr, artifactRoot.Close())
	}); err != nil {
		t.Fatalf("strict enrolled owner record: %v", err)
	}

	scope, err := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
	if err != nil {
		t.Fatal(err)
	}
	requestID := strings.Repeat("e", 64)
	policyID := strings.Repeat("f", 64)
	inputAt, expiry := time.UnixMilli(50), time.UnixMilli(120000)
	baseInput, err := sourcehandler.NewBoundInput(repository, base, adapter.Identity(), digest)
	if err != nil {
		t.Fatal(err)
	}
	headInput, err := sourcehandler.NewBoundInput(repository, head, adapter.Identity(), digest)
	if err != nil {
		t.Fatal(err)
	}
	baseArtifact, err := sourcehandler.NewInputArtifact(scope, baseInput, artifact.ClassificationConfidential, artifact.ProtectionProcessPrivate, []string{requestID}, inputAt, expiry)
	if err != nil {
		t.Fatal(err)
	}
	headArtifact, err := sourcehandler.NewInputArtifact(scope, headInput, artifact.ClassificationConfidential, artifact.ProtectionProcessPrivate, []string{requestID}, inputAt, expiry)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []artifact.Artifact{baseArtifact, headArtifact} {
		if _, err := store.Put(ctx, value, inputAt); err != nil {
			t.Fatal(err)
		}
	}
	sourceHandler, err := sourcehandler.NewHandlerWithSourceRoot(store, adapter, digest, clock)
	if err != nil {
		t.Fatal(err)
	}
	changeHandler, err := changehandler.NewHandler(store, clock)
	if err != nil {
		t.Fatal(err)
	}
	analysisHandler, err := analysishandler.NewHandler(store, clock)
	if err != nil {
		t.Fatal(err)
	}
	index := memorycore.NewLexicalIndex()
	memoryScope, err := memorycore.NewScope("tenant-a", "repo-a", "reviewer", memorycore.RefVisibilityExact, head.Identity(), []string{"."})
	if err != nil {
		t.Fatal(err)
	}
	record, err := memorycore.NewRecord(memoryScope, memorycore.RecordInput{Kind: memorycore.RecordCanonicalFact, Taint: memorycore.TaintTrusted, Path: "main.go", Text: "review this change", EvidenceIDs: []string{strings.Repeat("9", 64)}, ProducerIdentity: strings.Repeat("7", 64), ObservedAt: time.UnixMilli(10), ValidFrom: time.UnixMilli(10)})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := index.Add(ctx, memoryScope, record); err != nil {
		t.Fatal(err)
	}
	memoryHandler, err := memoryhandler.NewHandler(store, clock, index, strings.Repeat("6", 64), policyID, "reviewer", []string{"."}, 10, 20)
	if err != nil {
		t.Fatal(err)
	}
	definitions := []struct {
		key            string
		kind           controlplane.TaskKind
		input, handler string
		deps           []string
	}{
		{"source-base", controlplane.TaskAcquireSource, baseArtifact.Identity(), sourceHandler.HandlerIdentity(), nil},
		{"source-head", controlplane.TaskAcquireSource, headArtifact.Identity(), sourceHandler.HandlerIdentity(), nil},
		{"change", controlplane.TaskBuildChange, strings.Repeat("c", 64), changeHandler.HandlerIdentity(), []string{"source-base", "source-head"}},
		{"analysis", controlplane.TaskInspectDeterministic, strings.Repeat("3", 64), analysisHandler.HandlerIdentity(), []string{"change"}},
		{"memory", controlplane.TaskRetrieveContext, strings.Repeat("d", 64), memoryHandler.HandlerIdentity(), []string{"change"}},
		{"context", controlplane.TaskAssembleContext, strings.Repeat("4", 64), contexthandler.PacketAuthorityHandlerIdentity(), []string{"analysis", "memory"}},
	}
	tasks := make([]controlplane.TaskDefinition, 0, len(definitions))
	for _, definition := range definitions {
		task, taskErr := controlplane.NewTaskDefinition(definition.key, definition.kind, definition.input, definition.handler, definition.deps, 1, 1000, 30000, true)
		if taskErr != nil {
			t.Fatalf("task %s: %v", definition.key, taskErr)
		}
		tasks = append(tasks, task)
	}
	plan, err := controlplane.NewReviewRunPlan(scope, requestID, policyID, controlplane.ReviewRunAdvisory, tasks)
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := controlplane.NewCoordinator(journal)
	if err != nil {
		t.Fatal(err)
	}
	return localPacketOwnerFixture{store: store, journal: journal, owner: owner, resources: resources, coordinator: coordinator, rootDigest: digest, statePath: statePath, setupPath: setupPath, setupPlan: setupPlan, repository: repository, gitRoot: gitRoot, objectStore: objectStore, adapter: adapter, clock: clock}, plan, []controlplane.TaskHandler{sourceHandler, sourceHandler, changeHandler, analysisHandler, memoryHandler}
}

func newLocalPacketOwnerFixture(t *testing.T) localPacketOwnerFixture {
	return newLocalPacketOwnerFixtureWithUnselected(t, false)
}

func newLocalPacketOwnerFixtureWithUnselected(t *testing.T, unselected bool) localPacketOwnerFixture {
	t.Helper()
	f, plan, handlers := prepareLocalPacketOwnerFixtureWithUnselected(t, unselected)
	ctx := context.Background()
	coordinator := f.coordinator
	tasks := make([]controlplane.TaskDefinition, 0, 6)
	for _, key := range []string{"source-base", "source-head", "change", "analysis", "memory", "context"} {
		task, ok := plan.Task(key)
		if !ok {
			t.Fatalf("missing fixture task %s", key)
		}
		tasks = append(tasks, task)
	}
	if _, err := coordinator.Open(ctx, plan, time.UnixMilli(100)); err != nil {
		t.Fatal(err)
	}
	for i, handler := range handlers {
		task := tasks[i]
		at := time.UnixMilli(int64(101 + 2*i))
		state, advanceErr := coordinator.Advance(ctx, plan, at)
		if advanceErr != nil {
			t.Fatal(advanceErr)
		}
		lease, claimed, claimErr := coordinator.ClaimTask(ctx, plan, task.Key(), task.HandlerIdentity(), "worker", at)
		if claimErr != nil || !claimed {
			t.Fatalf("claim %s: acquired=%v err=%v", task.Key(), claimed, claimErr)
		}
		dependencies, depsErr := controlplane.TaskDependencyOutputsFromState(state, task)
		if depsErr != nil {
			t.Fatal(depsErr)
		}
		execution, requestErr := controlplane.NewTaskExecutionRequestWithDependencies(plan, task, lease, dependencies)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		completion := handler.Execute(ctx, execution)
		if completion.Status() != controlplane.TaskCompletionSucceeded {
			t.Fatalf("execute %s: failure=%v", task.Key(), completion.Failure())
		}
		if _, err := coordinator.CompleteTask(ctx, plan, lease, completion, at.Add(time.Millisecond)); err != nil {
			t.Fatal(err)
		}
	}
	state, err := coordinator.Advance(ctx, plan, time.UnixMilli(111))
	if err != nil {
		t.Fatal(err)
	}
	lease, claimed, err := coordinator.ClaimTask(ctx, plan, "context", tasks[5].HandlerIdentity(), "worker", time.UnixMilli(111))
	if err != nil || !claimed {
		t.Fatalf("claim context: acquired=%v err=%v", claimed, err)
	}
	dependencies, err := controlplane.TaskDependencyOutputsFromState(state, tasks[5])
	if err != nil {
		t.Fatal(err)
	}
	request, err := controlplane.NewTaskExecutionRequestWithDependencies(plan, tasks[5], lease, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	f.request = request
	return f
}

// assertLocalPacketOracle checks the wire against persisted upstream artifacts, not a
// second packet assembly. The two Git revisions fix the expected source bytes.
func assertLocalPacketOracle(t *testing.T, fixture localPacketOwnerFixture, state controlplane.ReviewRunState, value artifact.Artifact, descriptor controlplane.ContextPacketDescriptor) {
	t.Helper()
	ctx, scope, at := context.Background(), fixture.request.Plan().Scope(), fixture.clock.Now()
	get := func(key string) artifact.Artifact {
		t.Helper()
		task, ok := state.Task(key)
		if !ok || task.Status() != controlplane.TaskRuntimeSucceeded {
			t.Fatalf("missing upstream %s", key)
		}
		got, err := fixture.store.Get(ctx, scope, task.OutputIdentity(), at)
		if err != nil {
			t.Fatalf("read upstream %s: %v", key, err)
		}
		return got
	}
	baseValue, headValue, changeValue, analysisValue, memoryValue := get("source-base"), get("source-head"), get("change"), get("analysis"), get("memory")
	base, err := sourcehandler.ParseSnapshotArtifact(baseValue)
	if err != nil {
		t.Fatal(err)
	}
	head, err := sourcehandler.ParseSnapshotArtifact(headValue)
	if err != nil {
		t.Fatal(err)
	}
	change, err := changehandler.ParseResultArtifact(changeValue, baseValue, headValue)
	if err != nil {
		t.Fatal(err)
	}
	analysis, err := analysishandler.ParseResultArtifact(analysisValue, changeValue, baseValue, headValue)
	if err != nil {
		t.Fatal(err)
	}
	memoryResult, err := memoryhandler.ParseResultArtifact(memoryValue, changeValue, baseValue, headValue)
	if err != nil {
		t.Fatal(err)
	}
	if base.FileCount() != 1 || head.FileCount() != 1 || len(change.Entries()) != 1 || len(analysis.Items()) == 0 || len(analysis.Gaps()) != 0 || len(analysis.SemanticImpact().Gaps()) != 0 || len(memoryResult.Queries()) != 1 || len(memoryResult.Omissions()) != 0 {
		t.Fatal("unexpected upstream fixture shape")
	}
	baseBytes := []byte("package main\nfunc main() {}\n")
	headBytes := []byte("package main\nimport \"fmt\"\nfunc main() { fmt.Println(\"debug\") }\n")
	for _, pair := range []struct {
		snapshot sourcehandler.Snapshot
		content  []byte
	}{{base, baseBytes}, {head, headBytes}} {
		ref := pair.snapshot.Files()[0]
		stored, readErr := fixture.store.Get(ctx, scope, ref.ArtifactIdentity(), at)
		if readErr != nil {
			t.Fatal(readErr)
		}
		file, parseErr := sourcehandler.ParseFileArtifact(stored, pair.snapshot, ref)
		if parseErr != nil || ref.Path() != "main.go" || !bytes.Equal(file.Content(), pair.content) {
			t.Fatalf("Git revision content mismatch: %v", parseErr)
		}
	}
	file, err := evidence.NewRepositoryFile("main.go", headBytes)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := evidence.NewRepositoryManifest([]evidence.RepositoryFile{file})
	if err != nil || manifest.Identity() != head.ManifestIdentity() {
		t.Fatalf("head manifest mismatch: %v", err)
	}
	// One expected source per changed hunk and per new semantic reference range.
	type sourceWire struct {
		SourceID       string   `json:"source_id"`
		Stage          string   `json:"stage"`
		Taint          string   `json:"taint"`
		EvidenceDigest string   `json:"evidence_digest"`
		Path           string   `json:"path"`
		StartLine      int      `json:"start_line"`
		EndLine        int      `json:"end_line"`
		RiskFlags      []string `json:"risk_flags"`
		Content        string   `json:"content"`
	}
	sources := []sourceWire{}
	ranges := []evidence.SourceRange{}
	seen := map[evidence.SourceRange]bool{}
	add := func(start, end int, id, digest, stage string) {
		t.Helper()
		r, e := evidence.NewSourceRange("main.go", start, end)
		if e != nil {
			t.Fatal(e)
		}
		if seen[r] {
			t.Fatalf("duplicate upstream source range %v", r)
		}
		seen[r] = true
		lines := bytes.SplitAfter(headBytes, []byte("\n"))
		var selected []byte
		for i := start - 1; i < end; i++ {
			if i < 0 || i >= len(lines) {
				t.Fatal("source range outside head")
			}
			selected = append(selected, lines[i]...)
		}
		d := sha256.Sum256(selected)
		if digest != hex.EncodeToString(d[:]) {
			t.Fatal("upstream source digest mismatches known Git revision")
		}
		sources = append(sources, sourceWire{id, stage, "repository_controlled", digest, "main.go", start, end, []string{}, string(selected)})
		ranges = append(ranges, r)
	}
	for _, item := range analysis.Items() {
		if item.Path() != "main.go" || item.FileIdentity() != file.Identity() {
			t.Fatal("changed hunk not bound to known head file")
		}
		add(item.StartLine(), item.EndLine(), item.EvidenceID(), item.Digest(), "changed_hunk")
	}
	for _, ref := range analysis.SemanticImpact().References() {
		if ref.Path() != "main.go" {
			t.Fatal("unexpected semantic path")
		}
		r, e := evidence.NewSourceRange(ref.Path(), ref.Line(), ref.Line())
		if e != nil {
			t.Fatal(e)
		}
		if seen[r] {
			continue
		} // A duplicate semantic reference is an accounted omission below.
		lines := bytes.SplitAfter(headBytes, []byte("\n"))
		if ref.Line() < 1 || ref.Line() > 3 {
			t.Fatal("semantic line outside Git revision")
		}
		binding, e := evidence.BindSourceSlice(file, headBytes, r, lines[ref.Line()-1])
		if e != nil {
			t.Fatal(e)
		}
		add(ref.Line(), ref.Line(), binding.Identity(), binding.SliceDigest(), "direct_reference")
	}
	if len(sources) != 2 || len(analysis.Items()) != 1 || len(analysis.SemanticImpact().References()) != 1 || sources[0].Stage != "changed_hunk" || sources[0].StartLine != 2 || sources[0].EndLine != 3 || sources[1].Stage != "direct_reference" || sources[1].StartLine != 1 || sources[1].EndLine != 1 {
		t.Fatalf("known Git revisions produced unexpected source selection: %+v", sources)
	}
	sort.Slice(sources, func(i, j int) bool {
		if sources[i].Stage != sources[j].Stage {
			return sources[i].Stage == "changed_hunk"
		}
		return sources[i].SourceID < sources[j].SourceID
	})
	ranges = ranges[:0]
	for _, source := range sources {
		r, e := evidence.NewSourceRange(source.Path, source.StartLine, source.EndLine)
		if e != nil {
			t.Fatal(e)
		}
		ranges = append(ranges, r)
	}
	snapshot, err := review.NewAcquiredReviewPipelineSnapshot(scope.ReviewRunID(), manifest, ranges)
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		Contract                string          `json:"contract"`
		SchemaVersion           int             `json:"schema_version"`
		ReviewScopeIdentity     string          `json:"review_scope_identity"`
		MemoryScopeIdentity     string          `json:"memory_scope_identity"`
		SnapshotIdentity        string          `json:"snapshot_identity"`
		Task                    string          `json:"task"`
		OutputSchemaIdentity    string          `json:"output_schema_identity"`
		InstructionsIdentity    string          `json:"instructions_identity"`
		OutputSchema            json.RawMessage `json:"output_schema"`
		SourceSelectionIdentity string          `json:"source_selection_identity"`
		SourceCoverage          struct {
			Analyzed            int `json:"analyzed"`
			PreselectionOmitted int `json:"preselection_omitted"`
			Available           int `json:"available"`
			Selected            int `json:"selected"`
			Omitted             int `json:"omitted"`
			SelectedBytes       int `json:"selected_bytes"`
		} `json:"source_coverage"`
		SourceAuthority string `json:"source_authority"`
		MemoryAuthority string `json:"memory_authority"`
		ToolCalls       string `json:"tool_calls"`
		Limits          struct {
			MaxSourceBytes int `json:"max_source_bytes"`
			MaxMemoryItems int `json:"max_memory_items"`
		} `json:"limits"`
		Sources          []sourceWire      `json:"sources"`
		SourceOmissions  []json.RawMessage `json:"source_omissions"`
		Memory           json.RawMessage   `json:"memory"`
		AdditionalMemory []json.RawMessage `json:"additional_memory"`
		StatedIntent     json.RawMessage   `json:"stated_intent"`
		PatternHygiene   json.RawMessage   `json:"pattern_hygiene"`
	}
	decoder := json.NewDecoder(bytes.NewReader(value.Payload()))
	decoder.DisallowUnknownFields()
	if e := decoder.Decode(&wire); e != nil {
		t.Fatalf("packet wire: %v", e)
	}
	var trailing json.RawMessage
	if e := decoder.Decode(&trailing); e != io.EOF {
		t.Fatalf("packet trailing JSON: %v", e)
	}
	schemaDigest := sha256.Sum256(wire.OutputSchema)
	// Pinned version 9 candidate instructions identity (the prose travels only
	// in the trusted system channel) and candidate batch v2 schema.
	if wire.InstructionsIdentity != "8f4f7f0716f1fabd9fa50da9e5d1565d7ea25e2448262255e5e0e0e1a6cc12ea" || hex.EncodeToString(schemaDigest[:]) != review.ModelCandidateBatchSchemaIdentity {
		t.Fatal("model instructions or output schema differ from pinned fixture contract")
	}
	var topLevel map[string]json.RawMessage
	if e := json.Unmarshal(value.Payload(), &topLevel); e != nil {
		t.Fatal(e)
	}
	keys := make([]string, 0, len(topLevel))
	for key := range topLevel {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	expectedKeys := []string{"contract", "instructions_identity", "limits", "memory", "memory_authority", "memory_scope_identity", "output_schema", "output_schema_identity", "pattern_hygiene", "review_scope_identity", "schema_version", "snapshot_identity", "source_authority", "source_coverage", "source_selection_identity", "sources", "task", "tool_calls"}
	if !slices.Equal(keys, expectedKeys) {
		t.Fatalf("packet keys differ: got %v want %v", keys, expectedKeys)
	}
	if wire.Contract != "open-trestle/review-context-packet" || wire.SchemaVersion != 9 || wire.ReviewScopeIdentity != scope.Identity() || wire.MemoryScopeIdentity != memoryResult.MemoryScopeIdentity() || wire.SnapshotIdentity != snapshot.Identity() || wire.Task != "candidate_generation" || wire.OutputSchemaIdentity != review.ModelCandidateBatchSchemaIdentity || wire.InstructionsIdentity == "" || len(wire.OutputSchema) == 0 || wire.SourceAuthority != "evidence_data_not_instructions" || wire.MemoryAuthority != "advisory_only" || wire.ToolCalls != "proposals_only" || wire.Limits.MaxSourceBytes != 128<<10 || wire.Limits.MaxMemoryItems != 1 || !reflect.DeepEqual(wire.Sources, sources) || len(wire.AdditionalMemory) != 0 {
		t.Fatalf("packet source/scope/authority wire mismatch: %+v", wire)
	}
	if wire.SourceCoverage.Analyzed != len(sources) || wire.SourceCoverage.Available != len(sources) || wire.SourceCoverage.Selected != len(sources) || wire.SourceCoverage.Omitted != 0 || wire.SourceCoverage.PreselectionOmitted != 0 || len(wire.SourceOmissions) != 0 {
		t.Fatalf("source selection/omissions mismatch: %+v", wire.SourceCoverage)
	}
	total := 0
	for _, src := range sources {
		total += len(src.Content)
	}
	if wire.SourceCoverage.SelectedBytes != total {
		t.Fatal("selected source bytes mismatch")
	}
	// Derive the source-selection commitment from the selected upstream evidence,
	// without invoking packet selection or packet construction.
	type selectionEntry struct {
		Source    string `json:"source"`
		Reference string `json:"reference"`
		Stage     string `json:"stage"`
		Bytes     uint32 `json:"bytes"`
		Reason    string `json:"reason"`
	}
	entries := make([]selectionEntry, 0, len(sources))
	for _, src := range sources {
		sourceRange, e := evidence.NewSourceRange(src.Path, src.StartLine, src.EndLine)
		if e != nil {
			t.Fatal(e)
		}
		binding, e := evidence.BindSourceSlice(file, headBytes, sourceRange, []byte(src.Content))
		if e != nil {
			t.Fatal(e)
		}
		evidenceItem, e := evidence.NewEvidenceItem(src.SourceID, evidence.EvidenceKindSource, src.EvidenceDigest, sourceRange)
		if e != nil {
			t.Fatal(e)
		}
		if binding.Identity() != src.SourceID {
			t.Fatal("source evidence binding differs from upstream reference")
		}
		stage := review.ContextStageChangedHunk
		if src.Stage == "direct_reference" {
			stage = review.ContextStageDirectReference
		}
		bound, e := review.NewBoundContextSource(stage, memorycore.TaintRepositoryControlled, evidenceItem, []byte(src.Content), binding)
		if e != nil {
			t.Fatal(e)
		}
		entries = append(entries, selectionEntry{bound.Identity(), src.SourceID, src.Stage, uint32(len(src.Content)), "selected"})
	}
	selectionPreimage := struct {
		Contract       string           `json:"contract"`
		Version        int              `json:"version"`
		MaxSourceBytes uint32           `json:"max_source_bytes"`
		MaxSources     int              `json:"max_sources"`
		SelectedBytes  uint32           `json:"selected_bytes"`
		Entries        []selectionEntry `json:"entries"`
	}{"open-trestle/review-context-source-selection", 1, 128 << 10, 32, uint32(total), entries}
	selectionJSON, e := json.Marshal(selectionPreimage)
	if e != nil {
		t.Fatal(e)
	}
	selectionDigest := sha256.Sum256(selectionJSON)
	if wire.SourceSelectionIdentity != hex.EncodeToString(selectionDigest[:]) {
		t.Fatal("source selection identity differs from upstream evidence")
	}

	memoryScope, e := memoryResult.MemoryScope()
	if e != nil {
		t.Fatal(e)
	}
	retrieval, e := memoryResult.Queries()[0].Retrieval(memoryScope, memoryResult.AsOf())
	if e != nil {
		t.Fatal(e)
	}
	items := retrieval.Items()
	if len(items) != 1 || items[0].Record().Text() != "review this change" || items[0].Record().Kind() != memorycore.RecordCanonicalFact || items[0].Record().Taint() != memorycore.TaintTrusted {
		t.Fatal("seeded memory not retrieved")
	}
	rec := items[0].Record()
	if rec.Path() != "main.go" || rec.ProducerIdentity() != strings.Repeat("7", 64) || !slices.Equal(rec.EvidenceIDs(), []string{strings.Repeat("9", 64)}) || rec.ObservedAtUnixMilliseconds() != 10 || rec.ValidFromUnixMilliseconds() != 10 || rec.ValidUntilUnixMilliseconds() != 0 || rec.StaleAfterUnixMilliseconds() != 0 || len(rec.Symbols()) != 0 || len(rec.DerivedFromIDs()) != 0 || len(rec.CounterEvidenceIDs()) != 0 {
		t.Fatal("retrieval differs from seeded canonical memory fact")
	}
	expectedMemory := struct {
		RetrievalIdentity string `json:"retrieval_identity"`
		QueryIdentity     string `json:"query_identity"`
		IndexRevision     uint64 `json:"index_revision"`
		Items             []any  `json:"items"`
	}{retrieval.Identity(), retrieval.Query().Identity(), retrieval.IndexRevision(), []any{struct {
		MemoryID           string   `json:"memory_id"`
		Kind               string   `json:"kind"`
		Taint              string   `json:"taint"`
		Path               string   `json:"path"`
		Symbols            []string `json:"symbols"`
		Text               string   `json:"text"`
		EvidenceIDs        []string `json:"evidence_ids"`
		DerivedFromIDs     []string `json:"derived_from_ids"`
		CounterEvidenceIDs []string `json:"counter_evidence_ids"`
		ProducerIdentity   string   `json:"producer_identity"`
		ObservedAt         int64    `json:"observed_at"`
		ValidFrom          int64    `json:"valid_from"`
		ValidUntil         int64    `json:"valid_until"`
		StaleAfter         int64    `json:"stale_after"`
		FreshnessIdentity  string   `json:"freshness_identity"`
		Confidence         uint16   `json:"confidence_basis_points"`
		Rank               uint8    `json:"rank"`
		PathScore          uint8    `json:"path_score"`
		SymbolScore        uint8    `json:"symbol_score"`
		TextScore          uint8    `json:"text_score"`
	}{rec.Identity(), rec.Kind().String(), rec.Taint().String(), rec.Path(), rec.Symbols(), rec.Text(), rec.EvidenceIDs(), rec.DerivedFromIDs(), rec.CounterEvidenceIDs(), rec.ProducerIdentity(), rec.ObservedAtUnixMilliseconds(), rec.ValidFromUnixMilliseconds(), rec.ValidUntilUnixMilliseconds(), rec.StaleAfterUnixMilliseconds(), rec.FreshnessIdentity(), rec.ConfidenceBasisPoints(), items[0].Rank(), items[0].PathScore(), items[0].SymbolScore(), items[0].TextScore()}}}
	encodedMemory, e := json.Marshal(expectedMemory)
	if e != nil {
		t.Fatal(e)
	}
	var gotMemory, wantMemory any
	if e = json.Unmarshal(wire.Memory, &gotMemory); e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(encodedMemory, &wantMemory); e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(gotMemory, wantMemory) {
		t.Fatalf("memory wire differs from persisted retrieval: got %s want %s", wire.Memory, encodedMemory)
	}
	provenance := []string{analysisValue.Identity(), memoryValue.Identity(), changeValue.Identity(), headValue.Identity(), analysis.Identity(), memoryResult.Identity()}
	sort.Strings(provenance)
	dependencies := []string{analysisValue.Identity(), memoryValue.Identity()}
	sort.Strings(dependencies)
	payloadDigest := sha256.Sum256(value.Payload())
	expectedArtifact, e := artifact.New(scope, artifact.KindContextPacket, "application/json", artifact.ClassificationConfidential, artifact.OriginHost, artifact.ProtectionProcessPrivate, provenance, value.Payload(), at, time.UnixMilli(120000))
	if e != nil {
		t.Fatal(e)
	}
	if expectedArtifact.Identity() != value.Identity() {
		t.Fatal("candidate artifact identity differs from independently constructed envelope")
	}
	expectedDescriptor := controlplane.ContextPacketDescriptor{ArtifactIdentity: expectedArtifact.Identity(), LeaseIdentity: fixture.request.Lease().Identity(), LeaseEventIdentity: fixture.request.Lease().EventIdentity(), PayloadDigest: hex.EncodeToString(payloadDigest[:]), Classification: "confidential", Protection: "process_private", Provenance: provenance, SourceRootIdentity: fixture.rootDigest, SnapshotIdentity: snapshot.Identity(), DependencyIdentities: dependencies, CreatedAtMilliseconds: at.UnixMilli(), ExpiresAtMilliseconds: time.UnixMilli(120000).UnixMilli()}
	if !reflect.DeepEqual(descriptor, expectedDescriptor) || !slices.Equal(value.Provenance(), provenance) {
		t.Fatalf("descriptor/provenance differs from independent upstream chain: got %+v want %+v", descriptor, expectedDescriptor)
	}
}

func TestLocalPacketOwnerFixtureBuildsRealEnrolledCandidate(t *testing.T) {
	fixture := newLocalPacketOwnerFixture(t)
	ctx := context.Background()
	scope := fixture.request.Plan().Scope()
	_, state, err := fixture.coordinator.Resume(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	runtime, exists := state.Task("context")
	if !exists || runtime.Status() != controlplane.TaskRuntimeLeased || runtime.LeaseExpiresAt() != fixture.request.Lease().ExpiresAt() {
		t.Fatal("context request does not describe the actual leased task")
	}
	before, err := fixture.journal.Read(ctx, scope, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	at := fixture.clock.Now()
	candidate, err := contexthandler.BuildPacketCandidate(ctx, localPacketFixtureReader{fixture.store}, fixture.request, state, fixture.clock, fixture.rootDigest, at, at)
	if err != nil {
		t.Fatal(err)
	}
	value, descriptor := candidate.Artifact(), candidate.Descriptor()
	assertLocalPacketOracle(t, fixture, state, value, descriptor)
	if value.Validate() != nil || value.Kind() != artifact.KindContextPacket || value.MediaType() != "application/json" || value.Classification() != artifact.ClassificationConfidential || value.Origin() != artifact.OriginHost || value.Protection() != artifact.ProtectionProcessPrivate || !bytes.Contains(value.Payload(), []byte("fmt.Println")) ||
		descriptor.ArtifactIdentity != value.Identity() || descriptor.PayloadDigest != value.PayloadDigest() || descriptor.Classification != value.Classification().String() || descriptor.Protection != value.Protection().String() || descriptor.SourceRootIdentity != fixture.rootDigest || descriptor.SnapshotIdentity == "" ||
		descriptor.LeaseIdentity != fixture.request.Lease().Identity() || descriptor.LeaseEventIdentity != fixture.request.Lease().EventIdentity() ||
		descriptor.CreatedAtMilliseconds != value.CreatedAt().UnixMilli() || descriptor.ExpiresAtMilliseconds != value.ExpiresAt().UnixMilli() ||
		len(descriptor.Provenance) != 6 || len(descriptor.DependencyIdentities) != 2 || !reflect.DeepEqual(descriptor.Provenance, value.Provenance()) ||
		!value.ExpiresAt().After(fixture.request.Lease().ExpiresAt()) {
		t.Fatal("candidate does not match the full source-bound packet envelope and lease")
	}
	for _, output := range fixture.request.DependencyOutputs() {
		if !output.Available() || !slices.Contains(descriptor.DependencyIdentities, output.OutputIdentity()) {
			t.Fatalf("missing exact dependency %s", output.TaskKey())
		}
	}
	after, err := fixture.journal.Read(ctx, scope, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatal("candidate changed the journal")
	}
	for i := range before {
		if before[i].Identity() != after[i].Identity() || after[i].Kind() == controlplane.RunEventContextPacketPrepared {
			t.Fatal("candidate changed history or appended v4")
		}
	}
	_, afterState, err := fixture.coordinator.Resume(ctx, scope)
	if err != nil || afterState.HeadIdentity() != state.HeadIdentity() {
		t.Fatalf("candidate changed state head: %v", err)
	}
	afterRuntime, ok := afterState.Task("context")
	if !ok {
		t.Fatal("context task disappeared")
	}
	if _, prepared := afterRuntime.PreparedContextPacket(); prepared {
		t.Fatal("candidate prepared v4")
	}
	if _, err := fixture.store.Get(ctx, scope, value.Identity(), at); !errors.Is(err, artifact.ErrArtifactNotFound) {
		t.Fatalf("candidate wrote packet bytes: %v", err)
	}
	encoded, err := artifact.Encode(value)
	if err != nil {
		t.Fatalf("encode candidate envelope: %v", err)
	}
	decoded, err := artifact.Parse(encoded)
	if err != nil || decoded.Identity() != value.Identity() || !bytes.Equal(decoded.Payload(), value.Payload()) {
		t.Fatalf("candidate packet envelope failed round trip: %v", err)
	}
}
