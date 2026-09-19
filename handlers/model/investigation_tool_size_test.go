package model

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	source "github.com/georgejieh/open-trestle/handlers/source"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/memory"
	"github.com/georgejieh/open-trestle/internal/policy"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/internal/scm"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

func toolSizeFixture(t *testing.T, label string, fileCount int, notes string, resultCap, returnedCap uint64, matches int) *toolRecordFixture {
	t.Helper()
	f := &toolRecordFixture{t: t, clock: &toolRecordClock{time.UnixMilli(1000)}}
	f.ctx = context.WithValue(context.Background(), toolRecordContextKey{}, "caller-"+label)
	var err error
	f.scope, err = audit.NewReviewScope("tool-tenant", "tool-repo", "tool-"+label)
	toolRecordCheck(t, err)
	store, err := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 100)
	toolRecordCheck(t, err)
	f.ledger = audit.NewMemoryLedger()
	f.store = &toolRecordStore{Store: store, held: map[string]artifact.Artifact{}, ledger: f.ledger, scope: f.scope, t: t, contextValue: f.ctx.Value(toolRecordContextKey{})}
	repository, err := evidence.NewRepositoryIdentity("example.test", []string{"owner"}, "repo")
	toolRecordCheck(t, err)
	revision, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("a", 40))
	toolRecordCheck(t, err)
	adapter, err := evidence.NewSourceAdapterIdentity(evidence.SourceAdapterKindGit, "tool-record-fixture", "1.0.0", []evidence.SourceAdapterCapability{evidence.SourceCapabilityReadManifest, evidence.SourceCapabilityReadContent})
	toolRecordCheck(t, err)
	contents := map[string][]byte{"a.go": []byte(toolRecordChanged), "notes.txt": []byte(notes)}
	for i := 2; i < fileCount; i++ {
		contents[fmt.Sprintf("z%02d.txt", i)] = []byte("unused\n")
	}
	paths := make([]string, 0, len(contents))
	for path := range contents {
		paths = append(paths, path)
	}
	slices.Sort(paths)
	files := []evidence.RepositoryFile{}
	for _, path := range paths {
		file, err := evidence.NewRepositoryFile(path, contents[path])
		toolRecordCheck(t, err)
		files = append(files, file)
	}
	f.manifest, err = evidence.NewRepositoryManifest(files)
	toolRecordCheck(t, err)
	external := &toolRecordExternalSource{id: adapter, result: scm.SourceAdapterResult{Outcome: evidence.AcquisitionOutcomeAcquired, Reason: evidence.AcquisitionReasonNone, Manifest: f.manifest, Contents: contents}}
	handler, err := source.NewHandler(f.store, external, f.clock)
	toolRecordCheck(t, err)
	input, err := source.NewInput(repository, revision, adapter)
	toolRecordCheck(t, err)
	inputArtifact, err := source.NewInputArtifact(f.scope, input, artifact.ClassificationConfidential, artifact.ProtectionProcessPrivate, []string{toolRecordHash([]byte("host-input"))}, time.UnixMilli(100), time.UnixMilli(6000))
	toolRecordCheck(t, err)
	_, err = f.store.Put(f.ctx, inputArtifact, time.UnixMilli(100))
	toolRecordCheck(t, err)
	task, err := controlplane.NewTaskDefinition("source", controlplane.TaskAcquireSource, inputArtifact.Identity(), handler.HandlerIdentity(), nil, 1, 0, 30000, true)
	toolRecordCheck(t, err)
	plan, err := controlplane.NewReviewRunPlan(f.scope, toolRecordHash([]byte("request")), toolRecordHash([]byte("review-policy")), controlplane.ReviewRunAdvisory, []controlplane.TaskDefinition{task})
	toolRecordCheck(t, err)
	coordinator, err := controlplane.NewCoordinator(controlplane.NewMemoryRunJournal())
	toolRecordCheck(t, err)
	_, err = coordinator.Open(f.ctx, plan, time.UnixMilli(100))
	toolRecordCheck(t, err)
	_, err = coordinator.Advance(f.ctx, plan, time.UnixMilli(101))
	toolRecordCheck(t, err)
	lease, acquired, err := coordinator.ClaimTask(f.ctx, plan, "source", handler.HandlerIdentity(), "fixture-worker", time.UnixMilli(102))
	toolRecordCheck(t, err)
	if !acquired {
		t.Fatal("source task was not actually claimed")
	}
	execution, err := controlplane.NewTaskExecutionRequest(plan, task, lease)
	toolRecordCheck(t, err)
	completion := handler.Execute(f.ctx, execution)
	if completion.Status() != controlplane.TaskCompletionSucceeded || external.calls != 1 {
		t.Fatal("actual source handler did not acquire protected files")
	}
	_, err = coordinator.CompleteTask(f.ctx, plan, lease, completion, f.clock.Now())
	toolRecordCheck(t, err)
	f.head, err = f.store.Get(f.ctx, f.scope, completion.OutputIdentity(), f.clock.Now())
	toolRecordCheck(t, err)
	f.snapshot, err = source.ParseSnapshotArtifact(f.head)
	toolRecordCheck(t, err)
	for _, file := range f.snapshot.Files() {
		f.allSourceIDs = append(f.allSourceIDs, file.ArtifactIdentity())
	}
	f.allSourceIDs = toolRecordIDs(f.allSourceIDs...)
	f.limits = source.SnapshotReadLimits{MaxFiles: fileCount, MaxLines: 20, MaxResultBytes: int(resultCap), MaxMatches: matches, MaxScannedBytes: 65536}
	f.reader, err = source.NewSnapshotReader(f.ctx, f.store, f.clock, f.scope, f.head.Identity(), f.snapshot.Identity(), f.limits)
	toolRecordCheck(t, err)
	bootstrap, err := f.reader.List(f.ctx)
	toolRecordCheck(t, err)
	f.files = bootstrap.Files()
	var initial source.SnapshotSlice
	for _, file := range f.files {
		if file.Path() == "a.go" {
			initial, err = f.reader.Read(f.ctx, file.Ref(), 2, 2)
			toolRecordCheck(t, err)
		}
	}
	item, err := evidence.NewEvidenceItem(initial.Binding().Identity(), evidence.EvidenceKindSource, initial.Binding().SliceDigest(), initial.Binding().SourceRange())
	toolRecordCheck(t, err)
	bound, err := review.NewBoundContextSource(review.ContextStageChangedHunk, memory.TaintRepositoryControlled, item, initial.Content(), initial.Binding())
	toolRecordCheck(t, err)
	f.initialSources = []review.ContextSource{bound}
	f.selected, err = review.NewAcquiredReviewPipelineSnapshot(f.scope.ReviewRunID(), f.manifest, []evidence.SourceRange{initial.Binding().SourceRange()})
	toolRecordCheck(t, err)
	f.memoryScope, err = memory.NewScope(f.scope.TenantID(), f.scope.RepositoryID(), "actor", memory.RefVisibilityExact, toolRecordHash([]byte("review-policy")), []string{"."})
	toolRecordCheck(t, err)
	query, err := memory.NewLexicalQuery(f.memoryScope, "a.go", nil, nil, f.clock.Now(), 1)
	toolRecordCheck(t, err)
	f.retrieval, err = memory.NewLexicalIndex().Search(f.ctx, f.memoryScope, query)
	toolRecordCheck(t, err)
	contextLimits, err := review.NewContextLimits(65536, 0)
	toolRecordCheck(t, err)
	f.initial, err = review.NewContextPacket(f.scope, f.memoryScope, f.selected, review.ContextTaskCandidateGeneration, f.initialSources, f.retrieval, contextLimits)
	toolRecordCheck(t, err)
	policyBytes, err := os.ReadFile("../../internal/review/testdata/investigation-policy-v1.json")
	toolRecordCheck(t, err)
	var policyWire map[string]any
	toolRecordCheck(t, json.Unmarshal(policyBytes, &policyWire))
	policyWire["max_files"], policyWire["max_result_bytes"], policyWire["max_returned_bytes"], policyWire["max_matches"] = fileCount, resultCap, returnedCap, matches
	policyBytes = toolRecordJSON(t, policyWire)
	f.policy, err = review.ParseInvestigationPolicy(policyBytes)
	toolRecordCheck(t, err)
	routes := []map[string]any{}
	for _, name := range []string{"a", "b"} {
		routes = append(routes, map[string]any{"zone": "local", "provider_id": "provider-" + name, "adapter_id": "adapter-" + name, "connection_id": "connection-" + name, "model_id": "model-" + name, "model_version": "1", "max_context_tokens": 128000, "max_output_tokens": 4096, "features": []string{"structured_output"}, "content_logging": "disabled", "pricing_known": true, "input_micro_usd_per_million_tokens": 1000000, "output_micro_usd_per_million_tokens": 1000000, "quality": "tier_3", "registry_revision": 1, "registry_status": "approved", "evidence_manifest_base64": base64.StdEncoding.EncodeToString([]byte("approved route fixture")), "operational_revision": 1, "health": "healthy", "quota": "available", "performance_revision": 1, "latency_known": true, "p95_latency_milliseconds": 10, "latency_sample_count": 20})
	}
	inventory, err := runtimeconfig.DecodeRouteInventory(f.ctx, bytes.NewReader(toolRecordJSON(t, map[string]any{"schema_version": 1, "routes": routes})))
	toolRecordCheck(t, err)
	var generation, verification gateway.ObservedRouteCandidate
	for _, route := range inventory.Candidates() {
		if route.ResolvedRecord().RouteRegistryRecord().RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference().AdapterID() == "adapter-a" {
			generation = route
		} else {
			verification = route
		}
	}
	f.model = &toolRecordExternalModel{adapter: "adapter-a", t: t, ledger: f.ledger, scope: f.scope}
	verifier := &toolRecordExternalModel{adapter: "adapter-b", t: t, ledger: f.ledger, scope: f.scope}
	catalog, err := gateway.NewRouteDispatcherCatalog([]gateway.RouteDispatcher{f.model, verifier})
	toolRecordCheck(t, err)
	requirements, err := provider.NewModelRequirements(1, 4096, []provider.ModelFeature{provider.ModelFeatureStructuredOutput})
	toolRecordCheck(t, err)
	zones, err := policy.NewAllowedProviderZones(provider.ProviderZoneLocal)
	toolRecordCheck(t, err)
	constraints, err := policy.NewProviderDataConstraints(policy.DataClassificationConfidential, zones, false)
	toolRecordCheck(t, err)
	budget, err := provider.NewModelCostBudget(1, 4096, 100000)
	toolRecordCheck(t, err)
	ranking, err := gateway.NewRouteRankingPolicy(nil)
	toolRecordCheck(t, err)
	independence, err := gateway.NewRouteIndependencePolicy(gateway.RouteIndependenceDistinctProvider)
	toolRecordCheck(t, err)
	claim := func(route gateway.ObservedRouteCandidate) review.InvestigationRouteContextClaim {
		return review.InvestigationRouteContextClaim{Record: route.ResolvedRecord().RouteRegistryRecord(), ManifestSizeBytes: route.ResolvedRecord().EvidenceManifestSizeBytes(), Operational: route.OperationalState()}
	}
	options := review.InvestigationContextBindingOptions{Scope: f.scope, HostSessionIdentity: toolRecordHash([]byte("host-" + label)), Policy: f.policy, HeadSnapshotArtifactIdentity: f.head.Identity(), HeadSnapshotIdentity: f.snapshot.Identity(), HeadManifestIdentity: f.manifest.Identity(), HeadRevisionIdentity: f.snapshot.RevisionIdentity(), InitialContext: f.initial, InitialSnapshot: f.selected, Deadline: time.UnixMilli(6000), Routing: review.InvestigationContextRouting{RegistryRevision: inventory.RegistryRevision(), PerformanceRevision: inventory.PerformanceRevision(), Generation: claim(generation), Verification: []review.InvestigationRouteContextClaim{claim(verification)}, Performance: inventory.PerformanceObservations(), Requirements: requirements, Constraints: constraints, Budget: budget, VerificationRanking: ranking, Independence: independence, CatalogIdentity: catalog.Identity()}}
	f.binding, err = review.NewInvestigationContextBinding(options)
	toolRecordCheck(t, err)
	makePlan := func(route gateway.ObservedRouteCandidate) gateway.InvestigationRoutePlan {
		observations := []provider.RoutePerformanceObservation{}
		for _, observation := range inventory.PerformanceObservations() {
			if observation.RecordIdentity() == route.ResolvedRecord().RouteRegistryRecord().Identity() {
				observations = append(observations, observation)
			}
		}
		pin, err := gateway.NewPinnedRouteRankingPolicy(route.ResolvedRecord().RouteRegistryRecord().RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference(), nil)
		toolRecordCheck(t, err)
		plan, err := gateway.NewInvestigationRoutePlan(inventory.RegistryRevision(), []gateway.ObservedRouteCandidate{route}, pin, inventory.PerformanceRevision(), observations)
		toolRecordCheck(t, err)
		return plan
	}
	f.owner, err = gateway.NewInvestigationRouteOwner(gateway.InvestigationRouteOwnerOptions{Scope: f.scope, SessionIdentity: f.binding.Identity(), PolicyIdentity: f.policy.Identity(), Deadline: options.Deadline, MaxTurns: uint8(f.policy.MaxModelTurns()), Budget: budget, Requirements: requirements, Constraints: constraints, Generation: makePlan(generation), Verification: makePlan(verification), Catalog: catalog, Ledger: f.ledger, Clock: f.clock})
	toolRecordCheck(t, err)
	f.state = review.InvestigationContextState{Turn: 1, ScannedBytes: initial.ScannedBytes()}
	f.setContext(f.initial, f.selected)
	f.store.gets = nil
	return f
}

func toolSizeMeasure(t *testing.T, f *toolRecordFixture, op InvestigationToolOperation) (uint64, uint64, uint64) {
	t.Helper()
	beforeGets, beforeCalls, beforeState := len(f.store.gets), len(f.model.calls), f.owner.State()
	beforeEvents, err := f.ledger.Read(f.ctx, f.scope, 0, 100)
	toolRecordCheck(t, err)
	payload, envelope, provenance, err := EstimateInvestigationToolResultArtifactBytes(op)
	toolRecordCheck(t, err)
	afterEvents, err := f.ledger.Read(f.ctx, f.scope, 0, 100)
	toolRecordCheck(t, err)
	if beforeGets != len(f.store.gets) || beforeCalls != len(f.model.calls) || beforeState != f.owner.State() || !slices.EqualFunc(beforeEvents, afterEvents, func(a, b audit.Event) bool { return a.Identity() == b.Identity() }) {
		t.Fatal("pure size estimate performed a source, model, ledger or owner effect")
	}
	return payload, envelope, provenance
}

func toolSizeAssertWire(t *testing.T, op InvestigationToolOperation, value artifact.Artifact, rawBound, envelopeBound, count uint64) {
	t.Helper()
	payload := value.Payload()
	encoded, err := artifact.Encode(value)
	toolRecordCheck(t, err)
	if uint64(len(payload)) > rawBound || uint64(len(encoded)) > envelopeBound {
		t.Fatalf("actual payload/envelope %d/%d exceeds bounds %d/%d", len(payload), len(encoded), rawBound, envelopeBound)
	}
	var fields map[string]json.RawMessage
	toolRecordCheck(t, json.Unmarshal(payload, &fields))
	if len(fields) != 36 {
		t.Fatal("complete tool result field schema changed")
	}
	actualPayload := 2 + len(fields) - 1
	for key, value := range fields {
		actualPayload += len(toolRecordJSON(t, key)) + 1 + len(value)
	}
	if actualPayload != len(payload) {
		t.Fatal("independent full payload framing arithmetic changed")
	}
	var envelope map[string]json.RawMessage
	toolRecordCheck(t, json.Unmarshal(encoded, &envelope))
	if len(envelope) != 16 {
		t.Fatal("artifact envelope field schema changed")
	}
	metadata := 2 + len(envelope) - 1
	for key, value := range envelope {
		metadata += len(toolRecordJSON(t, key)) + 1
		if key == "payload" {
			metadata += 2
		} else {
			metadata += len(value)
		}
	}
	if metadata+base64.StdEncoding.EncodedLen(len(payload)) != len(encoded) {
		t.Fatal("independent artifact metadata/base64 framing arithmetic changed")
	}
	ids := []string{op.expected.HeadArtifactIdentity, op.Identity(), op.expected.TurnIdentity, op.expected.ResponseIdentity, op.expected.ContextArtifactIdentity, op.expected.TurnArtifactIdentity}
	for _, file := range op.selected() {
		ids = append(ids, file.Artifact)
	}
	ids = toolRecordIDs(ids...)
	if count != uint64(len(ids)) || !slices.Equal(value.Provenance(), ids) {
		t.Fatal("provenance is not the exact unique selected/reference union")
	}
	if op.Tool() == "snapshot.list" && (rawBound != uint64(len(payload)) || envelopeBound != uint64(len(encoded))) {
		t.Fatalf("fully known listing framing was not exact: actual %d/%d bound %d/%d", len(payload), len(encoded), rawBound, envelopeBound)
	}
}

func TestInvestigationToolSizeActualResultsAndPureEffects(t *testing.T) {
	for _, mode := range []string{"list", "read", "hit", "miss"} {
		t.Run(mode, func(t *testing.T) {
			f := toolSizeFixture(t, "size-"+mode, 2, "first\n<\\\"&>é\u2028\nlast\n", 8192, 262144, 1)
			tool, literal, refs := "snapshot.list", "", []string(nil)
			if mode != "list" {
				refs = []string{f.file("notes.txt").Ref()}
				tool = "snapshot.read"
			}
			if mode == "hit" || mode == "miss" {
				tool = "snapshot.search"
				literal = "é"
				if mode == "miss" {
					literal = "absent"
				}
			}
			bundle, expected, turn, proposal := f.dispatch(tool, "size-a", literal, refs)
			op := toolRecordOperation(t, bundle, expected, proposal, f.clock.Now())
			p, e, c := toolSizeMeasure(t, f, op)
			if p > 8192 || e > 262144 || c > 32 {
				t.Fatal("small known-file operation has no useful conservative bound")
			}
			capture, err := f.capture(f.ctx, op, turn)
			toolRecordCheck(t, err)
			value, parsed, _ := f.result(op, bundle, expected, proposal, capture)
			toolSizeAssertWire(t, op, value, p, e, c)
			if mode == "miss" && len(parsed.Sources()) != 0 || mode == "hit" && len(parsed.Sources()) != 1 {
				t.Fatal("actual search witnesses changed")
			}
			if mode != "list" && parsed.ScannedBytes() != uint64(f.file("notes.txt").SizeBytes()) {
				t.Fatal("size test lost whole-file read/search charge")
			}
			if p2, e2, c2 := toolSizeMeasure(t, f, op); p2 != p || e2 != e || c2 != c {
				t.Fatal("estimate depended on a later actual invocation")
			}
		})
	}
}

func TestInvestigationToolSizeOwnPolicyBoundariesAndOversize(t *testing.T) {
	base := toolSizeFixture(t, "size-boundary", 2, toolRecordNotes, 8192, 262144, 1)
	bundle, expected, _, proposal := base.dispatch("snapshot.read", "size-a", "", []string{base.file("notes.txt").Ref()})
	op := toolRecordOperation(t, bundle, expected, proposal, base.clock.Now())
	p, e, _ := toolSizeMeasure(t, base, op)
	for _, test := range []struct {
		name          string
		raw, returned uint64
	}{
		{"exact", p, e}, {"raw-below", p - 1, e}, {"envelope-below", p, e - 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := toolSizeFixture(t, "size-boundary", 2, toolRecordNotes, test.raw, test.returned, 1)
			b, x, _, proposal := f.dispatch("snapshot.read", "size-a", "", []string{f.file("notes.txt").Ref()})
			op := toolRecordOperation(t, b, x, proposal, f.clock.Now())
			gotP, gotE, gotC := toolSizeMeasure(t, f, op)
			if gotP != p || gotE != e || gotC != 7 {
				t.Fatal("known small-file bound changed after recalculating coherent policy limits")
			}
			if (gotP > f.policy.MaxResultBytes()) != (test.name == "raw-below") || (gotE > f.policy.MaxReturnedBytes()) != (test.name == "envelope-below") {
				t.Fatal("valid conservative oversize was hidden as an estimator error or admission")
			}
		})
	}
}

func TestInvestigationToolSizeKnownBytesNumericWidthsAndAggregateProjection(t *testing.T) {
	for _, n := range []int{1, 9, 10, 99, 100, 999, 1000, 32768} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			f := toolSizeFixture(t, "size-width", 2, "first\n"+strings.Repeat("x", n)+"\n", 65536, 262144, 1)
			b, x, turn, proposal := f.dispatch("snapshot.read", "size-a", "", []string{f.file("notes.txt").Ref()})
			op := toolRecordOperation(t, b, x, proposal, f.clock.Now())
			p, e, c := toolSizeMeasure(t, f, op)
			capture, err := f.capture(f.ctx, op, turn)
			toolRecordCheck(t, err)
			value, _, _ := f.result(op, b, x, proposal, capture)
			toolSizeAssertWire(t, op, value, p, e, c)
			if n == 32768 && p <= 65536 {
				t.Fatal("complete wrapper plus maximum successful projection was not separately bounded")
			}
		})
	}
	f := toolSizeFixture(t, "size-aggregate", 2, toolRecordNotes, 65536, 262144, 64)
	b, x, _, proposal := f.dispatch("snapshot.search", "size-a", "absent", []string{f.file("notes.txt").Ref()})
	op := toolRecordOperation(t, b, x, proposal, f.clock.Now())
	p, _, _ := toolSizeMeasure(t, f, op)
	if p > 65536 {
		t.Fatal("tiny known file was treated as 64 independent 64 KiB snippet budgets")
	}
}

func TestInvestigationToolSizeExactProvenance32And33(t *testing.T) {
	for _, n := range []int{26, 27} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			f := toolSizeFixture(t, "size-provenance", n, toolRecordNotes, 65536, 262144, 1)
			b, x, turn, proposal := f.dispatch("snapshot.list", "size-a", "", nil)
			op := toolRecordOperation(t, b, x, proposal, f.clock.Now())
			p, e, c := toolSizeMeasure(t, f, op)
			if c != uint64(n+6) || p > 65536 || e > 262144 {
				t.Fatal("provenance-only boundary was not isolated")
			}
			capture, err := f.capture(f.ctx, op, turn)
			toolRecordCheck(t, err)
			if n == 26 {
				value, _, _ := f.result(op, b, x, proposal, capture)
				toolSizeAssertWire(t, op, value, p, e, c)
				return
			}
			x.OperationIdentity, x.InvocationIdentity = op.Identity(), capture.invocation.Identity()
			if value, err := NewInvestigationListToolResultArtifact(op, b, capture.invocation, x, f.clock.Now()); err == nil || value.Identity() != "" {
				t.Fatal("33-member provenance became a persistable result")
			}
		})
	}
}

func TestInvestigationToolSizeRejectsInvalidAndSchemaDrift(t *testing.T) {
	if _, _, _, err := EstimateInvestigationToolResultArtifactBytes(InvestigationToolOperation{}); err == nil {
		t.Fatal("zero operation estimated")
	}
	f := toolSizeFixture(t, "size-invalid", 2, toolRecordNotes, 8192, 262144, 1)
	b, x, _, proposal := f.dispatch("snapshot.read", "size-a", "", []string{f.file("notes.txt").Ref()})
	op := toolRecordOperation(t, b, x, proposal, f.clock.Now())
	invalid := op
	invalid.identity = "invalid"
	if _, _, _, err := EstimateInvestigationToolResultArtifactBytes(invalid); err == nil {
		t.Fatal("invalid retained identity estimated")
	}
	types := []reflect.Type{reflect.TypeOf(toolResultWire{}), reflect.TypeOf(toolRecordFile{}), reflect.TypeOf(toolRecordSource{}), reflect.TypeOf(toolReaderFileWire{}), reflect.TypeOf(toolReaderSliceWire{})}
	if !investigationToolSizeSchema(types...) {
		t.Fatal("accepted wire schema refused")
	}
	for i, typ := range types {
		fields := make([]reflect.StructField, typ.NumField())
		for j := range fields {
			fields[j] = typ.Field(j)
		}
		for _, mode := range []string{"extra", "kind", "tag", "nil"} {
			altered := append([]reflect.Type(nil), types...)
			copyFields := append([]reflect.StructField(nil), fields...)
			switch mode {
			case "extra":
				copyFields = append(copyFields, reflect.StructField{Name: "Extra", Type: reflect.TypeOf(""), Tag: `json:"extra"`})
			case "kind":
				copyFields[0].Type = reflect.TypeOf(map[string]string{})
			case "tag":
				copyFields[0].Tag = `json:"moved"`
			case "nil":
				altered[i] = nil
			}
			if mode != "nil" {
				altered[i] = reflect.StructOf(copyFields)
			}
			if investigationToolSizeSchema(altered...) {
				t.Fatalf("schema drift %d/%s did not fail closed", i, mode)
			}
		}
	}
}

func TestInvestigationToolSizeDoesNotCopyKnownSourcePayload(t *testing.T) {
	measure := func(n int) int64 {
		f := toolSizeFixture(t, "size-alloc", 2, "first\n"+strings.Repeat("x", n)+"\n", 65536, 262144, 1)
		b, x, _, proposal := f.dispatch("snapshot.read", "size-a", "", []string{f.file("notes.txt").Ref()})
		op := toolRecordOperation(t, b, x, proposal, f.clock.Now())
		result := testing.Benchmark(func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				p, e, c, err := EstimateInvestigationToolResultArtifactBytes(op)
				if err != nil || p == 0 || e <= p || c != 7 {
					b.Fatal("size estimate failed")
				}
			}
		})
		if result.N == 0 || result.AllocedBytesPerOp() > 64<<10 {
			t.Fatal("metadata-only estimate exceeded bounded allocation tripwire")
		}
		return result.AllocedBytesPerOp()
	}
	small, large := measure(16), measure(32768)
	if large > small+4096 {
		t.Fatalf("estimate allocation scaled with file payload: %d -> %d bytes/op", small, large)
	}
}

func TestInvestigationToolSizeCheckedArithmetic(t *testing.T) {
	for _, operation := range []string{"add", "multiply"} {
		counter := investigationToolSizeCount{}
		if operation == "add" {
			_ = counter.add(^uint64(0), 1)
		} else {
			_ = counter.multiply(^uint64(0), 2)
		}
		if counter.err == nil {
			t.Fatal("size arithmetic overflow was not rejected")
		}
	}
}
