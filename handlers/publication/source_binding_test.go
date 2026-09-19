package publication

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
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
	modelhandler "github.com/georgejieh/open-trestle/handlers/model"
	sourcehandler "github.com/georgejieh/open-trestle/handlers/source"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/gateway"
	memorycore "github.com/georgejieh/open-trestle/internal/memory"
	"github.com/georgejieh/open-trestle/internal/policy"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/internal/scm"
)

type bindingSourceAdapter struct {
	identity evidence.SourceAdapterIdentity
	results  map[string]scm.SourceAdapterResult
}

func (a bindingSourceAdapter) Identity() evidence.SourceAdapterIdentity { return a.identity }
func (a bindingSourceAdapter) Acquire(_ context.Context, request evidence.RepositoryAcquisitionRequest) scm.SourceAdapterResult {
	return a.results[request.Revision().Identity()]
}

type bindingRouteRegistry struct {
	record   provider.RouteRegistryRecord
	manifest []byte
}

func (r bindingRouteRegistry) LookupRouteRegistryRecord(context.Context, string) (provider.RouteRegistryRecord, error) {
	return r.record, nil
}
func (r bindingRouteRegistry) OpenRouteEvidenceManifest(context.Context, string) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(r.manifest)), nil
}

func bindingPolicyAuthorizer(t *testing.T) *contexthandler.PolicyAuthorizer {
	t.Helper()
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	reference, err := provider.NewRouteReference(provider.ProviderZoneLocal, "test-provider", "test-adapter", "test-connection", "test-model", "1")
	check(err)
	capabilities, err := provider.NewModelCapabilities(128000, 16000, []provider.ModelFeature{provider.ModelFeatureStructuredOutput})
	check(err)
	declaration, err := provider.NewRouteCapabilityDeclaration(reference, capabilities)
	check(err)
	pricing, err := provider.NewRoutePricing(0, 0)
	check(err)
	candidate, err := provider.NewRouteCandidateDeclaration(declaration, provider.ContentLoggingDisabled, pricing, provider.RouteQualityTier1)
	check(err)
	manifest := []byte("publication source binding route evidence")
	digest := sha256.Sum256(manifest)
	record, err := provider.NewRouteRegistryRecord(1, candidate, provider.RouteRegistryApproved, hex.EncodeToString(digest[:]))
	check(err)
	registry := bindingRouteRegistry{record: record, manifest: manifest}
	resolved, err := gateway.ResolveRouteRegistryRecord(context.Background(), record.Identity(), registry, registry)
	check(err)
	state, err := provider.NewRouteOperationalState(record.Identity(), 1, provider.RouteHealthHealthy, provider.RouteQuotaAvailable)
	check(err)
	observed, err := gateway.NewObservedRouteCandidate(resolved, state)
	check(err)
	performance, err := provider.NewUnknownRoutePerformanceObservation(record.Identity(), 1)
	check(err)
	requirements, err := provider.NewModelRequirements(1000, 100, []provider.ModelFeature{provider.ModelFeatureStructuredOutput})
	check(err)
	zones, err := policy.NewAllowedProviderZones(provider.ProviderZoneLocal)
	check(err)
	constraints, err := policy.NewProviderDataConstraints(policy.DataClassificationConfidential, zones, false)
	check(err)
	budget, err := provider.NewModelCostBudget(100, 100, 0)
	check(err)
	ranking, err := gateway.NewRouteRankingPolicy(nil)
	check(err)
	authorizer, err := contexthandler.NewPolicyAuthorizer(strings.Repeat("f", 64), requirements, constraints, budget, 1, []gateway.ObservedRouteCandidate{observed}, ranking, 1, []provider.RoutePerformanceObservation{performance}, audit.NewMemoryLedger())
	check(err)
	return authorizer
}

type sourceBindingFixture struct {
	store                                                                          artifact.Store
	scope                                                                          audit.ReviewScope
	target                                                                         review.PublicationTarget
	inputArtifact, contextArtifact, analysisArtifact, changeArtifact, headArtifact artifact.Artifact
	input                                                                          modelhandler.GenerationInput
	analysis                                                                       analysishandler.Result
	change                                                                         changehandler.Result
	head                                                                           sourcehandler.Snapshot
	memory                                                                         memoryhandler.Result
	contents                                                                       map[string][]byte
	authorizer                                                                     *contexthandler.PolicyAuthorizer
}

func newSourceBindingFixture(t *testing.T, withReference bool) sourceBindingFixture {
	t.Helper()
	ctx := context.Background()
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	repository, err := evidence.NewRepositoryIdentity("github.com", []string{"owner"}, "repo")
	check(err)
	baseRevision, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("1", 40))
	check(err)
	headRevision, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("2", 40))
	check(err)
	adapterIdentity, err := evidence.NewSourceAdapterIdentity(evidence.SourceAdapterKindGit, "test-source", "1.0.0", []evidence.SourceAdapterCapability{evidence.SourceCapabilityReadManifest, evidence.SourceCapabilityReadContent})
	check(err)
	testContent := "package p\nfunc TestOther(){}\n"
	if withReference {
		testContent = "package p\nfunc TestChanged(){_=Changed()}\n"
	}
	result := func(changed string) scm.SourceAdapterResult {
		contents := map[string][]byte{"a.go": []byte(changed), "a_test.go": []byte(testContent)}
		files := make([]evidence.RepositoryFile, 0, len(contents))
		for _, path := range []string{"a.go", "a_test.go"} {
			file, err := evidence.NewRepositoryFile(path, contents[path])
			check(err)
			files = append(files, file)
		}
		manifest, err := evidence.NewRepositoryManifest(files)
		check(err)
		return scm.SourceAdapterResult{Outcome: evidence.AcquisitionOutcomeAcquired, Reason: evidence.AcquisitionReasonNone, Manifest: manifest, Contents: contents}
	}
	adapter := bindingSourceAdapter{identity: adapterIdentity, results: map[string]scm.SourceAdapterResult{
		baseRevision.Identity(): result("package p\nfunc Changed() int{return 1}\n"),
		headRevision.Identity(): result("package p\nfunc Changed() int{return 2}\n"),
	}}
	store, err := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 100)
	check(err)
	scope, err := audit.NewReviewScope("tenant", "repository", "run")
	check(err)
	inputArtifact := func(revision evidence.RevisionIdentity, provenance string) artifact.Artifact {
		input, err := sourcehandler.NewInput(repository, revision, adapterIdentity)
		check(err)
		value, err := sourcehandler.NewInputArtifact(scope, input, artifact.ClassificationConfidential, artifact.ProtectionProcessPrivate, []string{provenance}, time.UnixMilli(50), time.UnixMilli(10000))
		check(err)
		_, err = store.Put(ctx, value, time.UnixMilli(50))
		check(err)
		return value
	}
	baseInput := inputArtifact(baseRevision, strings.Repeat("a", 64))
	headInput := inputArtifact(headRevision, strings.Repeat("b", 64))
	source, err := sourcehandler.NewHandler(store, adapter, fixedClock{time.UnixMilli(200)})
	check(err)
	change, err := changehandler.NewHandler(store, fixedClock{time.UnixMilli(210)})
	check(err)
	analysis, err := analysishandler.NewHandler(store, fixedClock{time.UnixMilli(215)})
	check(err)
	memory, err := memoryhandler.NewHandler(store, fixedClock{time.UnixMilli(220)}, memorycore.NewLexicalIndex(), strings.Repeat("6", 64), strings.Repeat("f", 64), "reviewer", []string{"."}, 10, 20)
	check(err)
	authorizer := bindingPolicyAuthorizer(t)
	assembly, err := contexthandler.NewHandler(store, fixedClock{time.UnixMilli(230)}, authorizer)
	check(err)
	definition := func(key string, handler controlplane.TaskHandler, input string, dependencies []string) controlplane.TaskDefinition {
		task, err := controlplane.NewTaskDefinition(key, handler.Kind(), input, handler.HandlerIdentity(), dependencies, 1, 1000, 30000, true)
		check(err)
		return task
	}
	baseTask := definition("source-base", source, baseInput.Identity(), nil)
	headTask := definition("source-head", source, headInput.Identity(), nil)
	changeTask := definition("change", change, strings.Repeat("c", 64), []string{"source-base", "source-head"})
	analysisTask := definition("analysis", analysis, strings.Repeat("3", 64), []string{"change"})
	memoryTask := definition("memory", memory, strings.Repeat("d", 64), []string{"change"})
	contextTask := definition("context", assembly, strings.Repeat("4", 64), []string{"analysis", "memory"})
	plan, err := controlplane.NewReviewRunPlan(scope, strings.Repeat("e", 64), strings.Repeat("f", 64), controlplane.ReviewRunAdvisory, []controlplane.TaskDefinition{baseTask, headTask, changeTask, analysisTask, memoryTask, contextTask})
	check(err)
	coordinator, err := controlplane.NewCoordinator(controlplane.NewMemoryRunJournal())
	check(err)
	_, err = coordinator.Open(ctx, plan, time.UnixMilli(100))
	check(err)
	execute := func(task controlplane.TaskDefinition, handler controlplane.TaskHandler, millis int64) artifact.Artifact {
		at := time.UnixMilli(millis)
		state, err := coordinator.Advance(ctx, plan, at)
		check(err)
		lease, acquired, err := coordinator.ClaimTask(ctx, plan, task.Key(), task.HandlerIdentity(), "worker", at)
		check(err)
		if !acquired {
			t.Fatalf("claim %s not acquired", task.Key())
		}
		dependencies, err := controlplane.TaskDependencyOutputsFromState(state, task)
		check(err)
		request, err := controlplane.NewTaskExecutionRequestWithDependencies(plan, task, lease, dependencies)
		check(err)
		completion := handler.Execute(ctx, request)
		if completion.Status() != controlplane.TaskCompletionSucceeded {
			t.Fatalf("producer %s failed: %s", task.Key(), completion.Failure())
		}
		state, err = coordinator.CompleteTask(ctx, plan, lease, completion, at.Add(time.Millisecond))
		check(err)
		taskState, ok := state.Task(task.Key())
		if !ok {
			t.Fatalf("producer %s state missing", task.Key())
		}
		output, err := store.Get(ctx, scope, taskState.OutputIdentity(), time.UnixMilli(240))
		check(err)
		return output
	}
	baseArtifact := execute(baseTask, source, 101)
	headArtifact := execute(headTask, source, 103)
	changeArtifact := execute(changeTask, change, 105)
	analysisArtifact := execute(analysisTask, analysis, 107)
	memoryArtifact := execute(memoryTask, memory, 109)
	input := execute(contextTask, assembly, 111)
	parsedInput, err := modelhandler.ParseGenerationInput(input.Payload())
	check(err)
	packet, err := store.Get(ctx, scope, parsedInput.ContextArtifactIdentity(), time.UnixMilli(240))
	check(err)
	parsedAnalysis, err := analysishandler.ParseResultArtifact(analysisArtifact, changeArtifact, baseArtifact, headArtifact)
	check(err)
	parsedChange, err := changehandler.ParseResultArtifact(changeArtifact, baseArtifact, headArtifact)
	check(err)
	parsedHead, err := sourcehandler.ParseSnapshotArtifact(headArtifact)
	check(err)
	parsedMemory, err := memoryhandler.ParseResultArtifact(memoryArtifact, changeArtifact, baseArtifact, headArtifact)
	check(err)
	contents := make(map[string][]byte)
	for _, reference := range parsedHead.Files() {
		value, err := store.Get(ctx, scope, reference.ArtifactIdentity(), time.UnixMilli(240))
		check(err)
		file, err := sourcehandler.ParseFileArtifact(value, parsedHead, reference)
		check(err)
		contents[reference.Path()] = file.Content()
	}
	target, err := review.NewPublicationTarget("github-review", repository, "42", headRevision)
	check(err)
	return sourceBindingFixture{store: store, scope: scope, target: target, inputArtifact: input, contextArtifact: packet, analysisArtifact: analysisArtifact, changeArtifact: changeArtifact, headArtifact: headArtifact, input: parsedInput, analysis: parsedAnalysis, change: parsedChange, head: parsedHead, memory: parsedMemory, contents: contents, authorizer: authorizer}
}

func assertSelectedBindingSources(t *testing.T, f sourceBindingFixture, withReference bool) {
	t.Helper()
	if err := review.ValidateContextPacketRequest(f.contextArtifact.Payload(), f.input.ContextIdentity(), f.scope.Identity(), f.input.MemoryScopeIdentity(), f.input.MemoryIdentity(), f.input.Snapshot(), f.input.EvidenceItems()); err != nil {
		t.Fatalf("producer packet rejected before publication: %v", err)
	}
	var packet struct {
		Sources []struct {
			SourceID  string `json:"source_id"`
			Stage     string `json:"stage"`
			Path      string `json:"path"`
			StartLine int    `json:"start_line"`
			EndLine   int    `json:"end_line"`
		} `json:"sources"`
	}
	if err := json.Unmarshal(f.contextArtifact.Payload(), &packet); err != nil {
		t.Fatal(err)
	}
	want := 1
	if withReference {
		want = 2
	}
	if len(packet.Sources) != want || len(f.input.EvidenceItems()) != want || len(f.analysis.Items()) != 1 {
		t.Fatalf("selected=%d input=%d changed=%d", len(packet.Sources), len(f.input.EvidenceItems()), len(f.analysis.Items()))
	}
	changed, semantic := false, false
	for _, source := range packet.Sources {
		switch source.Path {
		case "a.go":
			changed = source.Stage == "changed_hunk" && source.SourceID == f.analysis.Items()[0].EvidenceID()
		case "a_test.go":
			semantic = source.Stage == "direct_reference" && source.StartLine == 2 && source.EndLine == 2 && source.SourceID != f.analysis.Items()[0].EvidenceID()
		}
	}
	if !changed || semantic != withReference {
		t.Fatal("changed hunk or unchanged direct reference not selected exactly")
	}
	foundReference := false
	for _, reference := range f.analysis.SemanticImpact().References() {
		if reference.Path() == "a_test.go" && reference.Line() == 2 {
			foundReference = true
		}
	}
	if foundReference != withReference {
		t.Fatal("authoritative semantic profile does not match fixture")
	}
}

func assertExactProtectedBinding(t *testing.T, f sourceBindingFixture) {
	t.Helper()
	bindings := make([]string, 0, len(f.input.EvidenceItems()))
	for _, item := range f.input.EvidenceItems() {
		content := f.contents[item.SourceRange().Path()]
		lines := bytes.SplitAfter(content, []byte("\n"))
		slice := bytes.Join(lines[item.SourceRange().StartLine()-1:item.SourceRange().EndLine()], nil)
		file, err := evidence.NewRepositoryFile(item.SourceRange().Path(), content)
		if err != nil {
			t.Fatal(err)
		}
		binding, err := evidence.BindSourceSlice(file, content, item.SourceRange(), slice)
		if err != nil || binding.SliceDigest() != item.Digest() {
			t.Fatalf("physical source reconstruction failed: %v", err)
		}
		bindings = append(bindings, binding.Identity())
	}
	want, err := review.NewProtectedSourceBinding(f.scope, f.change.Repository(), f.change.HeadRevision(), f.headArtifact.Identity(), f.head.Identity(), f.head.ManifestIdentity(), f.changeArtifact.Identity(), f.change.Identity(), f.analysisArtifact.Identity(), f.contextArtifact.Identity(), f.input.ContextIdentity(), f.input.Snapshot().Identity(), bindings)
	if err != nil {
		t.Fatal(err)
	}
	// The generation result is unused by this consumer; model dispatch is outside this seam.
	handler := &Handler{store: f.store}
	got, err := handler.buildSourceBinding(context.Background(), f.scope, f.target, artifact.Artifact{}, f.inputArtifact, f.contextArtifact, time.UnixMilli(250))
	if err != nil {
		t.Fatalf("publication rejected selected protected sources: %v", err)
	}
	if got.Validate() != nil || got.Identity() != want.Identity() {
		t.Fatal("publication binding omitted or changed selected physical evidence")
	}
}

func TestBuildSourceBindingAcceptsChangedHunk(t *testing.T) {
	fixture := newSourceBindingFixture(t, false)
	assertSelectedBindingSources(t, fixture, false)
	assertExactProtectedBinding(t, fixture)
}

func TestBuildSourceBindingAcceptsUnchangedSemanticReference(t *testing.T) {
	fixture := newSourceBindingFixture(t, true)
	assertSelectedBindingSources(t, fixture, true)
	assertExactProtectedBinding(t, fixture)
}

func sourceBindingContextVariant(t *testing.T, f sourceBindingFixture, mutation string) sourceBindingFixture {
	t.Helper()
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	sources := make([]review.ContextSource, 0, len(f.input.EvidenceItems()))
	ranges := make([]evidence.SourceRange, 0, len(f.input.EvidenceItems()))
	for _, original := range f.input.EvidenceItems() {
		rangeValue := original.SourceRange()
		content := bytes.Clone(f.contents[rangeValue.Path()])
		id := original.ID()
		stage := review.ContextStageChangedHunk
		if rangeValue.Path() == "a.go" {
			switch mutation {
			case "changed_range":
				changedRange, err := evidence.NewSourceRange("a.go", 1, 1)
				check(err)
				rangeValue = changedRange
				content = []byte("func Changed() int{return 2}\n")
			case "changed_path":
				changedRange, err := evidence.NewSourceRange("a_test.go", 2, 2)
				check(err)
				rangeValue = changedRange
			}
		}
		if original.SourceRange().Path() == "a_test.go" {
			stage = review.ContextStageDirectReference
			switch mutation {
			case "range":
				changedRange, err := evidence.NewSourceRange("a_test.go", 1, 1)
				check(err)
				rangeValue = changedRange
			case "digest":
				content = []byte("package p\nfunc TestChanged(){ _=Changed()}\n")
			case "reference":
				id = strings.Repeat("9", 64)
			}
		}
		file, err := evidence.NewRepositoryFile(rangeValue.Path(), content)
		check(err)
		lines := bytes.SplitAfter(content, []byte("\n"))
		slice := bytes.Join(lines[rangeValue.StartLine()-1:rangeValue.EndLine()], nil)
		binding, err := evidence.BindSourceSlice(file, content, rangeValue, slice)
		check(err)
		if stage == review.ContextStageDirectReference && mutation == "range" {
			id = binding.Identity()
		}
		item, err := evidence.NewEvidenceItem(id, evidence.EvidenceKindSource, binding.SliceDigest(), rangeValue)
		check(err)
		source, err := review.NewBoundContextSource(stage, memorycore.TaintRepositoryControlled, item, slice, binding)
		check(err)
		sources = append(sources, source)
		ranges = append(ranges, rangeValue)
	}
	files := make([]evidence.RepositoryFile, 0, len(f.contents))
	for _, path := range []string{"a.go", "a_test.go"} {
		file, err := evidence.NewRepositoryFile(path, f.contents[path])
		check(err)
		files = append(files, file)
	}
	manifest, err := evidence.NewRepositoryManifest(files)
	check(err)
	snapshot, err := review.NewAcquiredReviewPipelineSnapshot(f.scope.ReviewRunID(), manifest, ranges)
	check(err)
	memoryScope, err := f.memory.MemoryScope()
	check(err)
	retrievals := make([]memorycore.LexicalRetrieval, 0, len(f.memory.Queries()))
	for _, query := range f.memory.Queries() {
		retrieval, err := query.Retrieval(memoryScope, f.memory.AsOf())
		check(err)
		retrievals = append(retrievals, retrieval)
	}
	limits, err := review.NewContextLimits(128<<10, 0)
	check(err)
	packet, err := review.NewContextPacketWithRetrievals(f.scope, memoryScope, snapshot, review.ContextTaskCandidateGeneration, sources, retrievals, limits)
	check(err)
	request, err := packet.ProviderRequest()
	check(err)
	contextArtifact, err := artifact.New(f.scope, artifact.KindContextPacket, "application/json", f.contextArtifact.Classification(), artifact.OriginHost, f.contextArtifact.Protection(), f.contextArtifact.Provenance(), request.Payload(), time.UnixMilli(240), f.contextArtifact.ExpiresAt())
	check(err)
	authorization, err := f.authorizer.Authorize(context.Background(), f.scope, request, strings.Repeat("f", 64), time.UnixMilli(240))
	check(err)
	input, err := modelhandler.NewGenerationInput(contextArtifact, packet, snapshot, authorization)
	check(err)
	inputArtifact, err := modelhandler.NewGenerationInputArtifact(input, contextArtifact, []string{f.analysisArtifact.Identity()}, time.UnixMilli(240))
	check(err)
	parsed, err := modelhandler.ParseGenerationInput(inputArtifact.Payload())
	check(err)
	check(review.ValidateContextPacketRequest(contextArtifact.Payload(), parsed.ContextIdentity(), f.scope.Identity(), parsed.MemoryScopeIdentity(), parsed.MemoryIdentity(), parsed.Snapshot(), parsed.EvidenceItems()))
	for _, value := range []artifact.Artifact{contextArtifact, inputArtifact} {
		_, err = f.store.Put(context.Background(), value, time.UnixMilli(240))
		check(err)
	}
	f.input, f.inputArtifact, f.contextArtifact = parsed, inputArtifact, contextArtifact
	return f
}

func TestBuildSourceBindingAcceptsRebuiltSemanticContext(t *testing.T) {
	fixture := newSourceBindingFixture(t, true)
	fixture = sourceBindingContextVariant(t, fixture, "none")
	assertSelectedBindingSources(t, fixture, true)
	assertExactProtectedBinding(t, fixture)
}

func TestBuildSourceBindingRejectsMismatchedSemanticAuthority(t *testing.T) {
	for _, mutation := range []string{"range", "digest", "reference", "head"} {
		t.Run(mutation, func(t *testing.T) {
			fixture := newSourceBindingFixture(t, true)
			assertSelectedBindingSources(t, fixture, true)
			if mutation == "head" {
				head, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("3", 40))
				if err != nil {
					t.Fatal(err)
				}
				fixture.target, err = review.NewPublicationTarget("github-review", fixture.change.Repository(), "42", head)
				if err != nil {
					t.Fatal(err)
				}
			} else {
				fixture = sourceBindingContextVariant(t, fixture, mutation)
			}
			handler := &Handler{store: fixture.store}
			binding, err := handler.buildSourceBinding(context.Background(), fixture.scope, fixture.target, artifact.Artifact{}, fixture.inputArtifact, fixture.contextArtifact, time.UnixMilli(250))
			if err == nil || binding.Identity() != "" {
				t.Fatal("publication accepted selected source outside protected semantic authority")
			}
		})
	}
}

func TestBuildSourceBindingRejectsChangedEvidenceRangeMismatch(t *testing.T) {
	for _, mutation := range []string{"changed_range", "changed_path"} {
		t.Run(mutation, func(t *testing.T) {
			fixture := newSourceBindingFixture(t, false)
			assertSelectedBindingSources(t, fixture, false)
			original := fixture.input.EvidenceItems()[0]
			fixture = sourceBindingContextVariant(t, fixture, mutation)
			changed := fixture.input.EvidenceItems()[0]
			if changed.ID() != original.ID() || changed.Digest() != original.Digest() || changed.SourceRange() == original.SourceRange() {
				t.Fatal("fixture must preserve changed evidence ID and digest while changing its range")
			}
			handler := &Handler{store: fixture.store}
			binding, err := handler.buildSourceBinding(context.Background(), fixture.scope, fixture.target, artifact.Artifact{}, fixture.inputArtifact, fixture.contextArtifact, time.UnixMilli(250))
			if err == nil || binding.Identity() != "" {
				t.Fatal("publication accepted changed evidence by digest without exact range")
			}
		})
	}
}

type missingBindingSourceStore struct {
	artifact.Store
	missing   string
	requested bool
}

func (s *missingBindingSourceStore) Get(ctx context.Context, scope audit.ReviewScope, id string, at time.Time) (artifact.Artifact, error) {
	if id == s.missing {
		s.requested = true
		return artifact.Artifact{}, artifact.ErrArtifactNotFound
	}
	return s.Store.Get(ctx, scope, id, at)
}

func TestBuildSourceBindingRequiresProtectedSemanticFile(t *testing.T) {
	fixture := newSourceBindingFixture(t, true)
	assertSelectedBindingSources(t, fixture, true)
	store := &missingBindingSourceStore{Store: fixture.store}
	for _, reference := range fixture.head.Files() {
		if reference.Path() == "a_test.go" {
			store.missing = reference.ArtifactIdentity()
		}
	}
	if store.missing == "" {
		t.Fatal("semantic source artifact missing from fixture")
	}
	handler := &Handler{store: store}
	binding, err := handler.buildSourceBinding(context.Background(), fixture.scope, fixture.target, artifact.Artifact{}, fixture.inputArtifact, fixture.contextArtifact, time.UnixMilli(250))
	if err == nil || binding.Identity() != "" || !store.requested {
		t.Fatal("publication did not fail closed on the missing protected semantic file")
	}
}
