package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/diagnostics"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestProgressPendingIsReadOnly(t *testing.T) {
	server, plan := apiServer(t)
	if _, err := server.coordinator.Open(context.Background(), plan, time.UnixMilli(100)); err != nil {
		t.Fatal(err)
	}
	before, _ := server.coordinator.Receipt(context.Background(), plan.Scope())
	response := httptest.NewRecorder()
	server.ServeHTTP(response, authenticatedRequest(http.MethodGet, "https://trestle.test/api/v1/tenants/tenant-a/repositories/repo-a/runs/run-a/progress", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var envelope struct {
		Contract string          `json:"contract"`
		Run      json.RawMessage `json:"run"`
		Progress map[string]struct {
			State string `json:"state"`
			Files *int   `json:"files"`
		} `json:"progress"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Contract != "open-trestle/run-progress-response" || len(envelope.Progress) != 4 {
		t.Fatalf("response=%s", response.Body.String())
	}
	for name, axis := range envelope.Progress {
		if axis.State != "not_run" || axis.Files != nil {
			t.Fatalf("axis=%s value=%+v", name, axis)
		}
	}
	after, _ := server.coordinator.Receipt(context.Background(), plan.Scope())
	if before.Identity() != after.Identity() {
		t.Fatal("GET changed canonical state")
	}
}

type progressFrozenArtifact struct {
	Tenant         string                  `json:"scope_tenant"`
	Repository     string                  `json:"scope_repository"`
	Run            string                  `json:"scope_run"`
	Kind           artifact.Kind           `json:"kind"`
	MediaType      string                  `json:"media_type"`
	Classification artifact.Classification `json:"classification"`
	Origin         artifact.Origin         `json:"origin"`
	Protection     artifact.Protection     `json:"protection"`
	Provenance     []string                `json:"provenance"`
	Payload        []byte                  `json:"payload_base64"`
	Created        int64                   `json:"created_milliseconds"`
	Expires        int64                   `json:"expires_milliseconds"`
}

func progressFixture(t testing.TB, scenario string, completed string) (*Server, controlplane.ReviewRunPlan, *progressCountingReader) {
	t.Helper()
	encoded, err := os.ReadFile("../../handlers/analysis/testdata/old-code-analysis-" + scenario + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err = json.Unmarshal(encoded, &raw); err != nil {
		t.Fatal(err)
	}
	frozen := make(map[string]progressFrozenArtifact)
	for _, key := range []string{"base", "head", "change", "evidence"} {
		var value progressFrozenArtifact
		if err = json.Unmarshal(raw[key], &value); err != nil {
			t.Fatal(err)
		}
		frozen[key] = value
	}
	store, _ := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 10)
	ids := make(map[string]string)
	var scope audit.ReviewScope
	for _, key := range []string{"base", "head", "change", "evidence"} {
		f := frozen[key]
		scope, _ = audit.NewReviewScope(f.Tenant, f.Repository, f.Run)
		value, err := artifact.New(scope, f.Kind, f.MediaType, f.Classification, f.Origin, f.Protection, f.Provenance, f.Payload, time.UnixMilli(f.Created), time.UnixMilli(f.Expires))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = store.Put(context.Background(), value, time.UnixMilli(500)); err != nil {
			t.Fatal(err)
		}
		ids[key] = value.Identity()
	}
	specs := []struct {
		key  string
		kind controlplane.TaskKind
		deps []string
	}{{"source-base", controlplane.TaskAcquireSource, nil}, {"source-head", controlplane.TaskAcquireSource, nil}, {"change", controlplane.TaskBuildChange, []string{"source-base", "source-head"}}, {"analysis", controlplane.TaskInspectDeterministic, []string{"change"}}, {"context", controlplane.TaskAssembleContext, []string{"analysis"}}, {"candidates", controlplane.TaskGenerateCandidates, []string{"context"}}, {"verification", controlplane.TaskVerifyCandidates, []string{"candidates"}}}
	var tasks []controlplane.TaskDefinition
	for _, spec := range specs {
		task, err := controlplane.NewTaskDefinition(spec.key, spec.kind, strings.Repeat("a", 64), strings.Repeat("d", 64), spec.deps, 1, 1000, 30000, true)
		if err != nil {
			t.Fatal(err)
		}
		tasks = append(tasks, task)
	}
	plan, err := controlplane.NewReviewRunPlan(scope, strings.Repeat("b", 64), strings.Repeat("c", 64), controlplane.ReviewRunAdvisory, tasks)
	if err != nil {
		t.Fatal(err)
	}
	coordinator, _ := controlplane.NewCoordinator(controlplane.NewMemoryRunJournal())
	_, err = coordinator.Open(context.Background(), plan, time.UnixMilli(100))
	if err != nil {
		t.Fatal(err)
	}
	at := int64(101)
	for _, key := range []string{"source-base", "source-head", "change", "analysis"} {
		task, _ := plan.Task(key)
		if _, err = coordinator.Advance(context.Background(), plan, time.UnixMilli(at)); err != nil {
			t.Fatal(err)
		}
		at++
		lease, claimed, err := coordinator.ClaimTask(context.Background(), plan, key, task.HandlerIdentity(), "worker", time.UnixMilli(at))
		if err != nil || !claimed {
			t.Fatalf("claim=%v err=%v", claimed, err)
		}
		at++
		outputKey := map[string]string{"source-base": "base", "source-head": "head", "change": "change", "analysis": "evidence"}[key]
		success, _ := controlplane.NewTaskSuccess(ids[outputKey])
		if _, err = coordinator.CompleteTask(context.Background(), plan, lease, success, time.UnixMilli(at)); err != nil {
			t.Fatal(err)
		}
		at++
		if key == completed {
			break
		}
	}
	principal, _ := NewPrincipal("operator", "tenant", []string{"repository"}, []Capability{CapabilityRunRead})
	authenticator, _ := NewStaticTokenAuthenticator([]StaticToken{{Token: testAPIToken, Principal: principal}})
	server, err := NewServer(coordinator, authenticator, fixedClock{time.UnixMilli(500)})
	if err != nil {
		t.Fatal(err)
	}
	reader := &progressCountingReader{reader: store}
	server, err = server.WithProgressArtifacts(reader)
	if err != nil {
		t.Fatal(err)
	}
	return server, plan, reader
}

type progressCountingReader struct {
	reader      artifact.Reader
	mu          sync.Mutex
	reads       int
	hook        func()
	replacement *artifact.Artifact
}

func (r *progressCountingReader) Get(ctx context.Context, scope audit.ReviewScope, id string, at time.Time) (artifact.Artifact, error) {
	r.mu.Lock()
	r.reads++
	hook := r.hook
	r.hook = nil
	replacement := r.replacement
	r.mu.Unlock()
	if hook != nil {
		hook()
	}
	if replacement != nil {
		return *replacement, nil
	}
	return r.reader.Get(ctx, scope, id, at)
}
func progressResponse(t *testing.T, server *Server, runIDs ...string) (runProgress, *httptest.ResponseRecorder) {
	t.Helper()
	runID := "run"
	if len(runIDs) > 0 {
		runID = runIDs[0]
	}
	response := httptest.NewRecorder()
	server.ServeHTTP(response, authenticatedRequest(http.MethodGet, "https://trestle.test/api/v1/tenants/tenant/repositories/repository/runs/"+runID+"/progress", nil))
	var envelope struct {
		Progress runProgress `json:"progress"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	return envelope.Progress, response
}
func TestProgressCanonicalEvidenceCounts(t *testing.T) {
	for _, tc := range []struct {
		scenario     string
		observations int
	}{{"produced-v4-failed-one-observation", 1}, {"synthetic-v4-zero-match", 0}, {"synthetic-v4-removed-file-gap", 0}} {
		t.Run(tc.scenario, func(t *testing.T) {
			server, plan, reader := progressFixture(t, tc.scenario, "analysis")
			before, _ := server.coordinator.Receipt(context.Background(), plan.Scope())
			p, response := progressResponse(t, server, plan.Scope().ReviewRunID())
			if response.Code != 200 || p.Change.State != "available" || p.Deterministic.State != "available" || p.Deterministic.Observations == nil || *p.Deterministic.Observations != tc.observations || p.Deterministic.CheckedRanges == nil || reader.reads != 4 {
				t.Fatalf("status=%d progress=%+v reads=%d body=%s", response.Code, p, reader.reads, response.Body.String())
			}
			after, _ := server.coordinator.Receipt(context.Background(), plan.Scope())
			if before.Identity() != after.Identity() {
				t.Fatal("GET wrote run state")
			}
			if p.Context.State != "not_run" || p.Verification.Candidates != nil {
				t.Fatal("invented model counts")
			}
		})
	}
}
func TestProgressChangeBeforeAnalysis(t *testing.T) {
	server, _, reader := progressFixture(t, "synthetic-v4-zero-match", "change")
	p, response := progressResponse(t, server)
	if response.Code != 200 || p.Change.State != "available" || p.Deterministic.State != "not_run" || p.Deterministic.Observations != nil || reader.reads != 3 {
		t.Fatalf("response=%s reads=%d", response.Body.String(), reader.reads)
	}
}
func TestProgressAbsentEvidenceDoesNotBecomeZero(t *testing.T) {
	server, _, _ := progressFixture(t, "synthetic-v4-zero-match", "analysis")
	store, _ := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 10)
	server, _ = server.WithProgressArtifacts(store)
	p, response := progressResponse(t, server)
	if response.Code != 200 || p.Change.State != "unavailable" || p.Change.Files != nil || p.Deterministic.Observations != nil {
		t.Fatalf("response=%s", response.Body.String())
	}
}
func TestProgressRejectsReceiptHeadAdvance(t *testing.T) {
	server, plan, reader := progressFixture(t, "synthetic-v4-zero-match", "analysis")
	reader.hook = func() {
		if _, err := server.coordinator.CancelRun(context.Background(), plan, time.UnixMilli(501)); err != nil {
			t.Fatal(err)
		}
	}
	_, response := progressResponse(t, server)
	if response.Code != 409 || decodeAPIError(t, response.Body.Bytes()).Code != "progress_changed" {
		t.Fatalf("response=%s", response.Body.String())
	}
}
func TestProgressConcurrentReads(t *testing.T) {
	server, _, reader := progressFixture(t, "synthetic-v4-zero-match", "analysis")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, response := progressResponse(t, server)
			if response.Code != 200 {
				t.Errorf("status=%d", response.Code)
			}
		}()
	}
	wg.Wait()
	if reader.reads != 32 {
		t.Fatalf("reads=%d", reader.reads)
	}
}
func TestProgressWrongScopeArtifactUnavailable(t *testing.T) {
	server, _, reader := progressFixture(t, "synthetic-v4-zero-match", "analysis")
	scope, _ := audit.NewReviewScope("other", "repository", "run")
	value, _ := artifact.New(scope, artifact.KindChangeModel, "application/json", artifact.ClassificationInternal, artifact.OriginDeterministicTool, artifact.ProtectionProcessPrivate, nil, []byte("{}"), time.UnixMilli(100), time.UnixMilli(1000))
	reader.replacement = &value
	p, response := progressResponse(t, server)
	if response.Code != 200 || p.Change.State != "unavailable" || p.Change.Files != nil {
		t.Fatalf("response=%s", response.Body.String())
	}
}
func TestProgressAuthorizationAndMethod(t *testing.T) {
	server, plan := apiServer(t)
	server.coordinator.Open(context.Background(), plan, time.UnixMilli(100))
	base := "https://trestle.test/api/v1/tenants/tenant-a/repositories/repo-a/runs/run-a/progress"
	for _, tc := range []struct {
		request *http.Request
		status  int
	}{{httptest.NewRequest(http.MethodGet, base, nil), 401}, {authenticatedRequest(http.MethodGet, strings.Replace(base, "tenant-a", "tenant-b", 1), nil), 403}, {authenticatedRequest(http.MethodGet, strings.Replace(base, "repo-a", "repo-b", 1), nil), 403}, {authenticatedRequest(http.MethodPost, base, nil), 405}, {authenticatedRequest(http.MethodGet, base, []byte("{}")), 400}, {authenticatedRequest(http.MethodGet, base+"?id=x", nil), 400}} {
		response := httptest.NewRecorder()
		server.ServeHTTP(response, tc.request)
		if response.Code != tc.status {
			t.Fatalf("status=%d want=%d body=%s", response.Code, tc.status, response.Body.String())
		}
	}
}
func TestProgressOptionRejectsNil(t *testing.T) {
	server, _ := apiServer(t)
	var reader *artifact.MemoryStore
	if _, err := server.WithProgressArtifacts(reader); err == nil {
		t.Fatal("typed nil accepted")
	}
	if _, err := server.WithProgressArtifacts(nil); err == nil {
		t.Fatal("nil accepted")
	}
}

func BenchmarkRunProgressCanonicalEvidence(b *testing.B) {
	for _, scenario := range []string{"produced-v4-failed-one-observation", "synthetic-v4-zero-match", "synthetic-v4-removed-file-gap"} {
		b.Run(scenario, func(b *testing.B) {
			server, plan, reader := progressFixture(b, scenario, "analysis")
			receipt, err := server.coordinator.Receipt(context.Background(), plan.Scope())
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				p := server.readRunProgress(context.Background(), receipt, time.UnixMilli(500))
				if p.Deterministic.State != "available" {
					b.Fatal("unavailable canonical evidence")
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(reader.reads)/float64(b.N), "artifact_gets/op")
		})
	}
}

func TestProgressRequiresRunRead(t *testing.T) {
	server, plan := apiServer(t)
	server.coordinator.Open(context.Background(), plan, time.UnixMilli(100))
	principal, _ := NewPrincipal("writer", "tenant-a", []string{"repo-a"}, []Capability{CapabilityRunWrite})
	server.authenticator, _ = NewStaticTokenAuthenticator([]StaticToken{{Token: testAPIToken, Principal: principal}})
	response := httptest.NewRecorder()
	server.ServeHTTP(response, authenticatedRequest(http.MethodGet, "https://trestle.test/api/v1/tenants/tenant-a/repositories/repo-a/runs/run-a/progress", nil))
	if response.Code != 403 {
		t.Fatalf("status=%d", response.Code)
	}
}
func TestProgressUnavailableAnalysisPreservesChange(t *testing.T) {
	server, plan, reader := progressFixture(t, "synthetic-v4-zero-match", "analysis")
	receipt, _ := server.coordinator.Receipt(context.Background(), plan.Scope())
	task, _ := receipt.Task("analysis")
	reader.reader = progressMissingReader{reader: reader.reader, missing: task.OutputIdentity()}
	p, response := progressResponse(t, server)
	if response.Code != 200 || p.Change.State != "available" || p.Deterministic.State != "unavailable" || p.Deterministic.Observations != nil {
		t.Fatalf("response=%s", response.Body.String())
	}
}

type progressMissingReader struct {
	reader  artifact.Reader
	missing string
}

func (r progressMissingReader) Get(ctx context.Context, scope audit.ReviewScope, id string, at time.Time) (artifact.Artifact, error) {
	if id == r.missing {
		return artifact.Artifact{}, artifact.ErrArtifactNotFound
	}
	return r.reader.Get(ctx, scope, id, at)
}
func TestProgressLoadBound(t *testing.T) {
	_, plan, reader := progressFixture(t, "synthetic-v4-zero-match", "analysis")
	reads := progressReads{reader: reader, scope: plan.Scope(), at: time.UnixMilli(500), values: make(map[string]artifact.Artifact)}
	for i := 0; i < maxProgressArtifacts+2; i++ {
		reads.get(context.Background(), strings.Repeat(string('a'+rune(i)), 64))
	}
	if reader.reads != maxProgressArtifacts {
		t.Fatalf("loads=%d", reader.reads)
	}
}

type progressForbiddenDiagnosticReader struct{}

func (progressForbiddenDiagnosticReader) GetDiagnosticSet(context.Context, audit.ReviewScope) (diagnostics.Set, error) {
	panic("progress must not read canonical diagnostics")
}
func TestProgressReceiptUnchangedAndNoDiagnosticReads(t *testing.T) {
	server, plan, _ := progressFixture(t, "synthetic-v4-zero-match", "analysis")
	server.diagnosticReader = progressForbiddenDiagnosticReader{}
	receipt, _ := server.coordinator.Receipt(context.Background(), plan.Scope())
	encoded, _ := controlplane.EncodeReviewRunReceipt(receipt)
	_, response := progressResponse(t, server)
	var envelope struct {
		Run json.RawMessage `json:"run"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, envelope.Run) {
		t.Fatal("progress altered canonical receipt")
	}
}
func TestProgressExpiredEvidenceUnknown(t *testing.T) {
	server, _, _ := progressFixture(t, "synthetic-v4-zero-match", "analysis")
	server.clock = fixedClock{time.UnixMilli(10000)}
	p, response := progressResponse(t, server)
	if response.Code != 200 || p.Change.State != "unavailable" || p.Change.Files != nil {
		t.Fatalf("body=%s", response.Body.String())
	}
}

func BenchmarkRunProgressHTTPRepeated(b *testing.B) {
	server, plan, reader := progressFixture(b, "produced-v4-failed-one-observation", "analysis")
	endpoint := "https://trestle.test/api/v1/tenants/tenant/repositories/repository/runs/" + plan.Scope().ReviewRunID() + "/progress"
	before, err := server.coordinator.Receipt(context.Background(), plan.Scope())
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		response := httptest.NewRecorder()
		server.ServeHTTP(response, authenticatedRequest(http.MethodGet, endpoint, nil))
		if response.Code != http.StatusOK {
			b.Fatalf("progress response=%d", response.Code)
		}
	}
	b.StopTimer()
	after, err := server.coordinator.Receipt(context.Background(), plan.Scope())
	if err != nil || before.Identity() != after.Identity() {
		b.Fatal("progress read changed receipt", err)
	}
	b.ReportMetric(float64(reader.reads)/float64(b.N), "artifact_gets/op")
}
