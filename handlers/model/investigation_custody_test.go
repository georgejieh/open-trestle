package model_test

import (
	"context"
	"encoding/json"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/controlplane"
	model "github.com/georgejieh/open-trestle/handlers/model"
	source "github.com/georgejieh/open-trestle/handlers/source"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/memory"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/internal/scm"
)

type custodyClock struct {
	mu sync.Mutex
	at time.Time
}

func (c *custodyClock) Now() time.Time   { c.mu.Lock(); defer c.mu.Unlock(); return c.at }
func (c *custodyClock) set(at time.Time) { c.mu.Lock(); c.at = at; c.mu.Unlock() }
func custodyClose(t *testing.T, c *model.Investigation) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := c.Close(ctx); err != nil {
		t.Error("controller did not close within caller bound")
	}
}
func custodyController(t *testing.T, ctx context.Context, o model.InvestigationOptions) *model.Investigation {
	t.Helper()
	c, err := model.NewInvestigation(ctx, o)
	upperCheck(t, err)
	t.Cleanup(func() { custodyClose(t, c) })
	return c
}

type custodyBundle struct {
	input, result, turn artifact.Artifact
	handle              *model.InvestigationGenerationCustody
	contextIdentity     string
}

func custodyGenerate(t *testing.T, ctx context.Context, c *model.Investigation, o model.InvestigationOptions, store *upperStore) custodyBundle {
	t.Helper()
	_, err := c.Step(ctx)
	upperCheck(t, err)
	_, err = c.Step(ctx)
	upperCheck(t, err)
	before := store.fileGets()
	generation, err := c.Generate(ctx)
	upperCheck(t, err)
	if store.fileGets() != before {
		t.Fatal("final generation/artifact construction reopened admitted full source")
	}
	handle := generation.Custody()
	if handle == nil {
		t.Fatal("successful generation did not retain live custody")
	}
	var refs struct {
		Turn string `json:"generation_turn_artifact_identity"`
	}
	upperCheck(t, json.Unmarshal(generation.ResultArtifact().Payload(), &refs))
	if refs.Turn == "" {
		t.Fatal("final result lacks its retained actual turn reference")
	}
	turn, err := store.Get(ctx, o.Scope, refs.Turn, o.Clock.Now())
	upperCheck(t, err)
	return custodyBundle{generation.InputArtifact(), generation.ResultArtifact(), turn, handle, generation.ContextIdentity()}
}
func custodyReadback(t *testing.T, b custodyBundle, at time.Time) {
	t.Helper()
	input, err := model.ParseAdmittedInvestigationGenerationInputArtifact(b.input, b.handle, at)
	upperCheck(t, err)
	result, err := model.ParseAdmittedInvestigationGenerationResultArtifact(b.result, b.input, b.turn, b.handle, at)
	upperCheck(t, err)
	if input.ContextIdentity() != b.contextIdentity || result.ContextIdentity() != b.contextIdentity || result.RouteExecution().Authorization().Identity() != input.Authorization().Identity() || result.Turn().Authorization().Identity() != input.Authorization().Identity() || len(result.Candidates().Findings()) != 1 {
		t.Fatal("admitted artifact readback lost held model/source/turn bindings")
	}
}
func TestInvestigationCustodyFeedsFinalArtifactsAndVerificationWithoutSourceReload(t *testing.T) {
	o, store, a, b, _, _ := upperFixture(t, "")
	ctx := context.Background()
	c := custodyController(t, ctx, o)
	bundle := custodyGenerate(t, ctx, c, o, store)
	before := store.fileGets()
	custodyReadback(t, bundle, o.Clock.Now())
	verified, err := c.Verify(ctx)
	upperCheck(t, err)
	custodyReadback(t, bundle, o.Clock.Now())
	if store.fileGets() != before || a.count() != 3 || b.count() != 1 || verified.IndependentReceipt().VerifiedCount() != 1 {
		t.Fatal("artifact/verification readback repeated full source or lost actual independent path")
	}
	kind := reflect.TypeOf(*bundle.handle)
	for i := 0; i < kind.NumField(); i++ {
		if kind.Field(i).PkgPath == "" {
			t.Fatal("custody exposes successful-source fields")
		}
	}
	for _, name := range []string{"Admit", "SetSource", "SetSuccessfulSource", "Restore", "Decode", "Import", "Settle"} {
		if _, ok := reflect.TypeOf(bundle.handle).MethodByName(name); ok {
			t.Fatal("live custody can be created or altered from caller claims")
		}
	}
}
func TestInvestigationCustodyRejectsMissingAndDifferentActualController(t *testing.T) {
	o, store, _, _, _, _ := upperFixture(t, "")
	c := custodyController(t, context.Background(), o)
	bundle := custodyGenerate(t, context.Background(), c, o, store)
	other, otherStore, _, _, _, _ := upperFixture(t, "")
	other.SessionIdentity = upperDigest([]byte("other actual controller session"))
	otherController := custodyController(t, context.Background(), other)
	otherBundle := custodyGenerate(t, context.Background(), otherController, other, otherStore)
	for _, handle := range []*model.InvestigationGenerationCustody{nil, {}, otherBundle.handle} {
		if _, err := model.ParseAdmittedInvestigationGenerationInputArtifact(bundle.input, handle, o.Clock.Now()); err == nil {
			t.Fatal("nil/zero/other controller custody accepted input")
		}
		if _, err := model.ParseAdmittedInvestigationGenerationResultArtifact(bundle.result, bundle.input, bundle.turn, handle, o.Clock.Now()); err == nil {
			t.Fatal("nil/zero/other controller custody accepted result")
		}
	}
	if _, err := model.ParseAdmittedInvestigationGenerationResultArtifact(otherBundle.result, otherBundle.input, otherBundle.turn, bundle.handle, o.Clock.Now()); err == nil {
		t.Fatal("complete separate bundle replaced original live custody pins")
	}
	custodyReadback(t, otherBundle, other.Clock.Now())
}
func custodyRewrite(t *testing.T, a artifact.Artifact, key string, value any) artifact.Artifact {
	t.Helper()
	var wire map[string]json.RawMessage
	upperCheck(t, json.Unmarshal(a.Payload(), &wire))
	wire[key] = upperJSON(t, value)
	delete(wire, "identity")
	wire["identity"] = upperJSON(t, upperDigest(upperJSON(t, wire)))
	changed, err := artifact.New(a.Scope(), a.Kind(), a.MediaType(), a.Classification(), a.Origin(), a.Protection(), a.Provenance(), upperJSON(t, wire), a.CreatedAt(), a.ExpiresAt())
	upperCheck(t, err)
	return changed
}
func TestInvestigationCustodyRejectsStageAndRehashedArtifactPins(t *testing.T) {
	o, store, _, _, _, _ := upperFixture(t, "")
	c := custodyController(t, context.Background(), o)
	held := custodyGenerate(t, context.Background(), c, o, store)
	for _, which := range []string{"wrong stage", "head", "source", "turn", "result", "complete input-result substitution"} {
		t.Run(which, func(t *testing.T) {
			input, result, turn := held.input, held.result, held.turn
			switch which {
			case "wrong stage":
				result = held.input
			case "head":
				input = custodyRewrite(t, input, "head_snapshot_artifact_identity", upperDigest([]byte("foreign protected head")))
			case "source":
				input = custodyRewrite(t, input, "evidence", []any{})
			case "turn":
				turn = custodyRewrite(t, turn, "owner_identity", upperDigest([]byte("foreign owner")))
			case "result":
				result = custodyRewrite(t, result, "candidate_batch_identity", upperDigest([]byte("foreign candidate batch")))
			case "complete input-result substitution":
				input = custodyRewrite(t, input, "head_snapshot_identity", upperDigest([]byte("different self-consistent claim")))
				result = custodyRewrite(t, result, "input_artifact_identity", input.Identity())
			}
			if _, err := model.ParseAdmittedInvestigationGenerationResultArtifact(result, input, turn, held.handle, o.Clock.Now()); err == nil {
				t.Fatal("rehashed artifacts or wrong stage replaced held expected pins")
			}
		})
	}
}
func TestInvestigationCustodyCloseCancelAndExpiryIgnoreStaleCallerTime(t *testing.T) {
	for _, mode := range []string{"close", "cancel", "expire"} {
		t.Run(mode, func(t *testing.T) {
			o, store, _, _, _, _ := upperFixture(t, "")
			clock := &custodyClock{at: o.Clock.Now()}
			o.Clock = clock
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			c := custodyController(t, ctx, o)
			bundle := custodyGenerate(t, ctx, c, o, store)
			old := clock.Now()
			custodyReadback(t, bundle, old)
			switch mode {
			case "close":
				custodyClose(t, c)
			case "cancel":
				cancel()
			case "expire":
				clock.set(time.UnixMilli(100000))
			}
			if _, err := model.ParseAdmittedInvestigationGenerationInputArtifact(bundle.input, bundle.handle, old); err == nil {
				t.Fatal("stale caller time refreshed invalid live input custody")
			}
			if _, err := model.ParseAdmittedInvestigationGenerationResultArtifact(bundle.result, bundle.input, bundle.turn, bundle.handle, old); err == nil {
				t.Fatal("closed/canceled/expired live custody remained usable")
			}
		})
	}
}

type custodyFailVerifier struct{ *upperModel }

func (m custodyFailVerifier) DispatchRoute(ctx context.Context, r gateway.RouteDispatchRequest) gateway.RouteDispatchResult {
	var p upperPacket
	upperCheck(m.t, json.Unmarshal(r.Request().Payload(), &p))
	m.mu.Lock()
	m.calls = append(m.calls, r)
	m.packets = append(m.packets, p)
	m.mu.Unlock()
	result, err := gateway.NewFailedRouteDispatchResult(gateway.RouteFailureTimeout, gateway.RouteReplayOutcomeUnknown, provider.NewUnknownRouteTokenUsage(), 0)
	upperCheck(m.t, err)
	return result
}
func TestInvestigationFailedProgressionInvalidatesHeldGenerationCustody(t *testing.T) {
	o, store, a, b, _, _ := upperFixture(t, "")
	catalog, err := gateway.NewRouteDispatcherCatalog([]gateway.RouteDispatcher{a, custodyFailVerifier{b}})
	upperCheck(t, err)
	o.Catalog = catalog
	c := custodyController(t, context.Background(), o)
	bundle := custodyGenerate(t, context.Background(), c, o, store)
	custodyReadback(t, bundle, o.Clock.Now())
	if _, err := c.Verify(context.Background()); err == nil || b.count() != 1 {
		t.Fatal("actual failed verifier did not stop progression")
	}
	if _, err := model.ParseAdmittedInvestigationGenerationResultArtifact(bundle.result, bundle.input, bundle.turn, bundle.handle, o.Clock.Now()); err == nil {
		t.Fatal("failed progression left successful live custody usable")
	}
}
func TestInvestigationCloseCancelsAndDrainsActualSourceWait(t *testing.T) {
	o, store, a, b, _, _ := upperFixture(t, "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := custodyController(t, ctx, o)
	_, err := c.Step(ctx)
	upperCheck(t, err)
	store.arm()
	done := make(chan error, 1)
	finished := make(chan struct{})
	go func() { defer close(finished); _, err := c.Step(ctx); done <- err }()
	t.Cleanup(func() {
		cancel()
		store.unblock()
		select {
		case <-finished:
		case <-time.After(time.Second):
			t.Error("source-wait fixture did not drain")
		}
	})
	select {
	case <-store.entered:
	case <-time.After(time.Second):
		t.Fatal("actual source wait not reached")
	}
	closeCtx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := c.Close(closeCtx); err != nil {
		t.Fatal("Close failed to cancel/drain cooperative source work")
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("closed source step returned success")
		}
	case <-time.After(time.Second):
		t.Fatal("Close returned without actual step completion")
	}
	if a.count() != 2 || b.count() != 0 {
		t.Fatal("Close repeated model work or reached verifier")
	}
}

// Reacquire through the real source handler; do not synthesize a completed source stage.
func custodyBackingFixture(t *testing.T, tail int, twoInitialRanges bool) (model.InvestigationOptions, *upperStore, int, int) {
	t.Helper()
	o, _, _, _, _, _ := upperFixture(t, "")
	ctx := context.Background()
	clock := upperClock{}
	store, err := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 100)
	upperCheck(t, err)
	spy := &upperStore{Store: store, sourceIDs: map[string]bool{}, ledger: o.Ledger, scope: o.Scope, t: t}
	repository, err := evidence.NewRepositoryIdentity("example.test", []string{"owner"}, "repo")
	upperCheck(t, err)
	revision, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("b", 40))
	upperCheck(t, err)
	adapter, err := evidence.NewSourceAdapterIdentity(evidence.SourceAdapterKindGit, "custody-backing-fixture", "1.0.0", []evidence.SourceAdapterCapability{evidence.SourceCapabilityReadManifest, evidence.SourceCapabilityReadContent})
	upperCheck(t, err)
	contents := map[string][]byte{"a.go": []byte(upperInitial), "notes.txt": []byte(upperNotes + strings.Repeat("x", tail))}
	files := []evidence.RepositoryFile{}
	for path, b := range contents {
		f, err := evidence.NewRepositoryFile(path, b)
		upperCheck(t, err)
		files = append(files, f)
	}
	manifest, err := evidence.NewRepositoryManifest(files)
	upperCheck(t, err)
	external := &upperSource{id: adapter, result: scm.SourceAdapterResult{Outcome: evidence.AcquisitionOutcomeAcquired, Reason: evidence.AcquisitionReasonNone, Manifest: manifest, Contents: contents}}
	handler, err := model.NewInvestigationAcquisitionHandler(spy, external, clock)
	upperCheck(t, err)
	in, err := source.NewInput(repository, revision, adapter)
	upperCheck(t, err)
	input, err := source.NewInputArtifact(o.Scope, in, artifact.ClassificationConfidential, artifact.ProtectionProcessPrivate, []string{upperDigest([]byte("custody source intent"))}, time.UnixMilli(100), time.UnixMilli(100000))
	upperCheck(t, err)
	_, err = store.Put(ctx, input, time.UnixMilli(100))
	upperCheck(t, err)
	task, err := controlplane.NewTaskDefinition("source", controlplane.TaskAcquireSource, input.Identity(), handler.HandlerIdentity(), nil, 1, 0, 30000, true)
	upperCheck(t, err)
	plan, err := controlplane.NewReviewRunPlan(o.Scope, upperDigest([]byte("custody source request")), upperDigest([]byte("review-policy")), controlplane.ReviewRunAdvisory, []controlplane.TaskDefinition{task})
	upperCheck(t, err)
	coordinator, err := controlplane.NewCoordinator(controlplane.NewMemoryRunJournal())
	upperCheck(t, err)
	_, err = coordinator.Open(ctx, plan, time.UnixMilli(100))
	upperCheck(t, err)
	_, err = coordinator.Advance(ctx, plan, time.UnixMilli(101))
	upperCheck(t, err)
	lease, _, err := coordinator.ClaimTask(ctx, plan, "source", handler.HandlerIdentity(), "fixture-worker", time.UnixMilli(102))
	upperCheck(t, err)
	execution, err := controlplane.NewTaskExecutionRequest(plan, task, lease)
	upperCheck(t, err)
	completion := handler.Execute(ctx, execution)
	if completion.Status() != controlplane.TaskCompletionSucceeded || external.calls != 1 {
		t.Fatal("real backing source acquisition failed")
	}
	_, err = coordinator.CompleteTask(ctx, plan, lease, completion, clock.Now())
	upperCheck(t, err)
	headArtifact, err := store.Get(ctx, o.Scope, completion.OutputIdentity(), clock.Now())
	upperCheck(t, err)
	head, err := source.ParseSnapshotArtifact(headArtifact)
	upperCheck(t, err)
	acquisition, err := handler.Acquisition(ctx, plan, headArtifact.Identity())
	upperCheck(t, err)
	t.Cleanup(func() {
		closeCtx, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		if err := handler.Close(closeCtx); err != nil {
			t.Error("acquisition wrapper did not close")
		}
	})
	reader, err := source.NewSnapshotReader(ctx, store, clock, o.Scope, headArtifact.Identity(), head.Identity(), source.SnapshotReadLimits{MaxFiles: 16, MaxLines: 20, MaxScannedBytes: 16 << 20, MaxResultBytes: 8192, MaxMatches: 8})
	upperCheck(t, err)
	listing, err := reader.List(ctx)
	upperCheck(t, err)
	sources := []review.ContextSource{}
	ranges := []evidence.SourceRange{}
	for _, ref := range listing.Files() {
		spy.sourceIDs[ref.ArtifactIdentity()] = true
		if ref.Path() == "notes.txt" {
			spy.blockID = ref.ArtifactIdentity()
			continue
		}
		starts := []int{2}
		if twoInitialRanges {
			starts = []int{1, 2}
		}
		for _, line := range starts {
			slice, err := reader.Read(ctx, ref.Ref(), line, line)
			upperCheck(t, err)
			binding := slice.Binding()
			item, err := evidence.NewEvidenceItem(binding.Identity(), evidence.EvidenceKindSource, binding.SliceDigest(), binding.SourceRange())
			upperCheck(t, err)
			bound, err := review.NewBoundContextSource(review.ContextStageChangedHunk, memory.TaintRepositoryControlled, item, slice.Content(), binding)
			upperCheck(t, err)
			sources = append(sources, bound)
			ranges = append(ranges, binding.SourceRange())
		}
	}
	snapshot, err := review.NewAcquiredReviewPipelineSnapshot(o.Scope.ReviewRunID(), manifest, ranges)
	upperCheck(t, err)
	memScope, err := memory.NewScope(o.Scope.TenantID(), o.Scope.RepositoryID(), "reviewer", memory.RefVisibilityExact, upperDigest([]byte("review-policy")), []string{"."})
	upperCheck(t, err)
	query, err := memory.NewLexicalQuery(memScope, "a.go", nil, nil, clock.Now(), 1)
	upperCheck(t, err)
	retrieval, err := memory.NewLexicalIndex().Search(ctx, memScope, query)
	upperCheck(t, err)
	limits, err := review.NewContextLimits(65536, 0)
	upperCheck(t, err)
	packet, err := review.NewContextPacket(o.Scope, memScope, snapshot, review.ContextTaskCandidateGeneration, sources, retrieval, limits)
	upperCheck(t, err)
	policyBytes, err := review.EncodeInvestigationPolicy(o.Policy)
	upperCheck(t, err)
	var wire map[string]any
	upperCheck(t, json.Unmarshal(policyBytes, &wire))
	wire["max_scanned_bytes"] = 16 << 20
	wire["timeout_milliseconds"] = 60000
	o.Deadline = time.UnixMilli(61000)
	o.Policy, err = review.ParseInvestigationPolicy(upperJSON(t, wire))
	upperCheck(t, err)
	o.Store = spy
	o.Acquisition = acquisition
	o.HeadSnapshotArtifactIdentity = headArtifact.Identity()
	o.MemoryScope = memScope
	o.InitialContext = packet
	o.InitialSnapshot = snapshot
	spy.gets = nil
	var retained int
	retained = headArtifact.PayloadSizeBytes()
	for _, ref := range head.Files() {
		value, err := store.Get(ctx, o.Scope, ref.ArtifactIdentity(), clock.Now())
		upperCheck(t, err)
		retained += 2 * value.PayloadSizeBytes()
	}
	if retained > 16<<20 || head.FileCount() > 128 || len(contents["notes.txt"]) > 10<<20 {
		t.Fatal("backing fixture exceeded retained/reader bounds")
	}
	return o, spy, len(contents["a.go"]), len(contents["notes.txt"])
}
func custodyAllocatedBytes(t *testing.T, b custodyBundle, at time.Time) uint64 {
	t.Helper()
	custodyReadback(t, b, at)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	const repeats = 8
	for n := 0; n < repeats; n++ {
		custodyReadback(t, b, at)
	}
	runtime.ReadMemStats(&after)
	return (after.TotalAlloc - before.TotalAlloc) / repeats
}
func TestInvestigationCachedReadbackAllocationDoesNotScaleWithBackingFile(t *testing.T) {
	var costs []uint64
	for _, tail := range []int{0, 1 << 20} {
		o, store, aBytes, nBytes := custodyBackingFixture(t, tail, false)
		c := custodyController(t, context.Background(), o)
		first, err := c.Step(context.Background())
		upperCheck(t, err)
		second, err := c.Step(context.Background())
		upperCheck(t, err)
		if first.ScannedBytes() != uint64(aBytes) || second.ScannedBytes() != uint64(aBytes+nBytes) {
			t.Fatal("actual backing-file reads were undercharged")
		}
		before := store.fileGets()
		generation, err := c.Generate(context.Background())
		upperCheck(t, err)
		var refs struct {
			Turn string `json:"generation_turn_artifact_identity"`
		}
		upperCheck(t, json.Unmarshal(generation.ResultArtifact().Payload(), &refs))
		turn, err := store.Get(context.Background(), o.Scope, refs.Turn, o.Clock.Now())
		upperCheck(t, err)
		bundle := custodyBundle{generation.InputArtifact(), generation.ResultArtifact(), turn, generation.Custody(), generation.ContextIdentity()}
		costs = append(costs, custodyAllocatedBytes(t, bundle, o.Clock.Now()))
		if store.fileGets() != before {
			t.Fatal("cached artifact path reopened full backing source")
		}
		custodyClose(t, c)
	}
	if costs[1] > 2*costs[0]+(64<<10) {
		t.Fatalf("cached readback allocation scaled with full source: small=%d large=%d", costs[0], costs[1])
	}
}

type custodyMatchingSearchModel struct{ *upperModel }

func (m custodyMatchingSearchModel) DispatchRoute(ctx context.Context, r gateway.RouteDispatchRequest) gateway.RouteDispatchResult {
	result := m.upperModel.DispatchRoute(ctx, r)
	var p upperPacket
	upperCheck(m.t, json.Unmarshal(r.Request().Payload(), &p))
	if p.Task != "candidate_generation" || p.Investigation.Turn != 3 {
		return result
	}
	var body map[string]any
	upperCheck(m.t, json.Unmarshal(result.Response().Parts()[0].Payload(), &body))
	body["tool_calls"].([]any)[0].(map[string]any)["literal"] = "zero"
	part, err := provider.NewResponsePart(provider.ResponsePartStructuredData, "application/json", upperJSON(m.t, body))
	upperCheck(m.t, err)
	response, err := provider.NewResponse(provider.CapabilityReviewV1, provider.ResponseFinishStop, []provider.ResponsePart{part}, result.Usage())
	upperCheck(m.t, err)
	changed, err := gateway.NewSuccessfulRouteDispatchResult(response)
	upperCheck(m.t, err)
	return changed
}
func TestInvestigationContextDedupDoesNotRefundActualSearch(t *testing.T) {
	o, _, a, b, _, _ := upperFixture(t, "no-match scan")
	policyBytes, err := review.EncodeInvestigationPolicy(o.Policy)
	upperCheck(t, err)
	var wire map[string]any
	upperCheck(t, json.Unmarshal(policyBytes, &wire))
	wire["max_scanned_bytes"] = 65536
	o.Policy, err = review.ParseInvestigationPolicy(upperJSON(t, wire))
	upperCheck(t, err)
	o.Catalog, err = gateway.NewRouteDispatcherCatalog([]gateway.RouteDispatcher{custodyMatchingSearchModel{a}, b})
	upperCheck(t, err)
	c := custodyController(t, context.Background(), o)
	_, err = c.Step(context.Background())
	upperCheck(t, err)
	read, err := c.Step(context.Background())
	upperCheck(t, err)
	search, err := c.Step(context.Background())
	upperCheck(t, err)
	if search.ScannedBytes() != read.ScannedBytes()+uint64(len(upperNotes)) {
		t.Fatal("identical returned binding refunded an actual full-file search")
	}
	var p upperPacket
	upperCheck(t, json.Unmarshal(search.NextRequest().Payload(), &p))
	if len(p.Sources) != 2 {
		t.Fatal("identical physical binding was duplicated in context")
	}
}
func TestInvestigationInitialRangesChargeEveryActualFullFileRead(t *testing.T) {
	o, store, aBytes, _ := custodyBackingFixture(t, 0, true)
	before := store.fileGets()
	c := custodyController(t, context.Background(), o)
	step, err := c.Step(context.Background())
	upperCheck(t, err)
	if step.ScannedBytes() != uint64(2*aBytes) || store.fileGets()-before != 2 {
		t.Fatal("multiple initial ranges invented uncharged one-load/many-range admission")
	}
}

func TestInvestigationDistinctRepeatedReadChargesFullFileAgain(t *testing.T) {
	o, _, _, _, _, _ := upperFixture(t, "scan")
	encoded, err := review.EncodeInvestigationPolicy(o.Policy)
	upperCheck(t, err)
	var policy map[string]any
	upperCheck(t, json.Unmarshal(encoded, &policy))
	policy["max_scanned_bytes"] = 65536
	o.Policy, err = review.ParseInvestigationPolicy(upperJSON(t, policy))
	upperCheck(t, err)
	c := custodyController(t, context.Background(), o)
	_, err = c.Step(context.Background())
	upperCheck(t, err)
	first, err := c.Step(context.Background())
	upperCheck(t, err)
	second, err := c.Step(context.Background())
	upperCheck(t, err)
	if second.ScannedBytes() != first.ScannedBytes()+uint64(len(upperNotes)) {
		t.Fatal("different read range did not charge complete file input again")
	}
}

func TestInvestigationControllerUsesAcquiredReferencesWithoutPretendingReaderWork(t *testing.T) {
	o, store, a, b, _, _ := upperFixture(t, "")
	before := store.fileGets()
	c := custodyController(t, context.Background(), o)
	first, err := c.Step(context.Background())
	upperCheck(t, err)
	if first.ScannedBytes() != uint64(len(upperInitial)) || store.fileGets()-before != 1 {
		t.Fatal("listing prefetched unselected source or acquisition references replaced physical initial read")
	}
	second, err := c.Step(context.Background())
	upperCheck(t, err)
	if second.ScannedBytes() != uint64(len(upperInitial)+len(upperNotes)) || store.fileGets()-before != 2 || a.count() != 2 || b.count() != 0 {
		t.Fatal("actual target Get was duplicated or omitted after pre-reader operation admission")
	}
}
func TestInvestigationControllerRefusesMissingOrCrossedAcquisitionHandle(t *testing.T) {
	o, _, a, b, _, _ := upperFixture(t, "")
	other, _, _, _, _, _ := upperFixture(t, "other source")
	for _, handle := range []*model.InvestigationAcquisition{nil, {}, other.Acquisition} {
		copy := o
		copy.Acquisition = handle
		controller, err := model.NewInvestigation(context.Background(), copy)
		if err == nil || controller != nil || a.count() != 0 || b.count() != 0 {
			t.Fatal("caller claims or crossed acquired references became controller source authority")
		}
	}
}
