package localreview

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	changehandler "github.com/georgejieh/open-trestle/handlers/change"
	memoryhandler "github.com/georgejieh/open-trestle/handlers/memory"
	modelhandler "github.com/georgejieh/open-trestle/handlers/model"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/memory"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/runtimecatalog"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

func rmNewClock() *rmClock { return &rmClock{at: time.Now().UTC().Truncate(time.Millisecond)} }
func rmOpted(t *testing.T, f *rmModelFixture, c *rmClock, paths []string) (SessionOptions, rmEnvelopeWire, string) {
	t.Helper()
	o := rmOptions(t, f, c)
	_, head := rmRevisions(t, f)
	w := rmEnvelopeFor(t, o, head, paths, c.Now().Add(time.Minute))
	path := rmWrite(t, w)
	input := rmLoad(t, path, w, o)
	o.RetainedMemoryInput = &input
	return o, w, path
}
func rmNineTasks(t *testing.T, p runtimecatalog.PreparedReviewRun) {
	t.Helper()
	want := []struct {
		key  string
		kind controlplane.TaskKind
		deps []string
	}{
		{"source-base", controlplane.TaskAcquireSource, nil}, {"source-head", controlplane.TaskAcquireSource, nil},
		{"change", controlplane.TaskBuildChange, []string{"source-base", "source-head"}},
		{"analysis", controlplane.TaskInspectDeterministic, []string{"change"}},
		{"memory", controlplane.TaskRetrieveContext, []string{"change"}},
		{"context", controlplane.TaskAssembleContext, []string{"analysis", "memory"}},
		{"candidates", controlplane.TaskGenerateCandidates, []string{"context"}},
		{"verification", controlplane.TaskVerifyCandidates, []string{"candidates"}},
		{"readiness", controlplane.TaskEvaluatePublication, []string{"analysis", "change", "verification"}},
	}
	if p.Validate() != nil || p.Plan().Mode() != controlplane.ReviewRunLocal || p.Plan().TaskCount() != 9 {
		t.Fatal("not the actual nine-task local plan")
	}
	for _, w := range want {
		d, ok := p.Plan().Task(w.key)
		a, e := controlplane.DefaultTaskAttemptPolicy(w.kind)
		if !ok || e != nil || d.Kind() != w.kind || !d.Required() || !slices.Equal(d.Dependencies(), w.deps) || d.MaxAttempts() != a.MaximumAttempts() || d.RetryDelayMilliseconds() != a.RetryDelayMilliseconds() || d.LeaseDurationMilliseconds() != a.LeaseDurationMilliseconds() {
			t.Fatal("task/default policy changed")
		}
	}
}
func rmArtifact(t *testing.T, s *Session, p runtimecatalog.PreparedReviewRun, id string, at time.Time) artifact.Artifact {
	t.Helper()
	v, e := s.store.Get(context.Background(), p.Plan().Scope(), id, at)
	if e != nil || v.Validate() != nil || v.Scope().Identity() != p.Plan().Scope().Identity() || v.Protection() != artifact.ProtectionProcessPrivate || v.Classification() != artifact.ClassificationConfidential {
		t.Fatal("missing native scoped protected artifact")
	}
	return v
}
func rmTaskArtifact(t *testing.T, s *Session, p runtimecatalog.PreparedReviewRun, key string, at time.Time) artifact.Artifact {
	t.Helper()
	_, state, e := s.coordinator.Resume(context.Background(), p.Plan().Scope())
	task, ok := state.Task(key)
	if e != nil || !ok || task.Status() != controlplane.TaskRuntimeSucceeded {
		t.Fatal("native task did not succeed: " + key)
	}
	return rmArtifact(t, s, p, task.OutputIdentity(), at)
}
func rmReadMemory(t *testing.T, s *Session, p runtimecatalog.PreparedReviewRun, at time.Time) (memoryhandler.Result, artifact.Artifact) {
	t.Helper()
	a := rmTaskArtifact(t, s, p, "memory", at)
	change := rmTaskArtifact(t, s, p, "change", at)
	baseID, headID, e := changehandler.ResultArtifactReferences(change)
	if e != nil {
		t.Fatal(e)
	}
	m, e := memoryhandler.ParseResultArtifact(a, change, rmArtifact(t, s, p, baseID, at), rmArtifact(t, s, p, headID, at))
	if e != nil {
		t.Fatal(e)
	}
	return m, a
}
func rmNoStaging(t *testing.T, s *Session, p runtimecatalog.PreparedReviewRun, at time.Time) {
	t.Helper()
	scope := p.Plan().Scope()
	_, found, e := s.journal.Head(context.Background(), scope)
	if e != nil || found {
		t.Fatal("refusal opened native journal")
	}
	_, found, e = s.journal.LoadPlan(context.Background(), scope)
	if e != nil || found {
		t.Fatal("refusal saved a native plan")
	}
	for _, input := range p.Inputs() {
		if _, e := s.store.Get(context.Background(), scope, input.Identity(), at); !errors.Is(e, artifact.ErrArtifactNotFound) {
			t.Fatal("refusal staged a source input")
		}
	}
	if s.active || len(s.admitted) != 0 || s.runner != nil {
		t.Fatal("refusal admitted worker ownership")
	}
}
func rmRecordInPacket(t *testing.T, p rmModelPacket, w rmEnvelopeWire, m memoryhandler.Result) {
	t.Helper()
	if p.MemoryScope != w.Scope.Identity || p.MemoryAuthority != "advisory_only" || p.SourceAuthority != "evidence_data_not_instructions" {
		t.Fatal("model memory lost exact scope/advisory boundary")
	}
	groups := append([]rmModelMemory{p.Memory}, p.AdditionalMemory...)
	if len(groups) != len(m.Queries()) {
		t.Fatal("context invented/dropped actual query groups")
	}
	selected := 0
	for i, q := range m.Queries() {
		retrieval, e := q.Retrieval(rmScope(t, w.Scope), m.AsOf())
		if e != nil {
			t.Fatal(e)
		}
		g := groups[i]
		if g.QueryIdentity != retrieval.Query().Identity() || g.RetrievalIdentity != retrieval.Identity() || g.IndexRevision != uint64(len(w.Records)) {
			t.Fatal("model lost native query/index revision lineage")
		}
		if len(g.Items) != len(q.Items()) {
			t.Fatal("model item selection differs from actual retrieval")
		}
		for j, item := range g.Items {
			selected++
			record, e := q.Items()[j].Record(rmScope(t, w.Scope))
			if e != nil {
				t.Fatal(e)
			}
			if item.MemoryID != record.Identity() || item.Kind != record.Kind().String() || item.Taint != record.Taint().String() || item.Path != record.Path() || item.Text != record.Text() || item.ProducerIdentity != record.ProducerIdentity() || !slices.Equal(item.EvidenceIDs, record.EvidenceIDs()) || !slices.Equal(item.Symbols, record.Symbols()) || !slices.Equal(item.DerivedFromIDs, record.DerivedFromIDs()) || !slices.Equal(item.CounterEvidenceIDs, record.CounterEvidenceIDs()) || item.ObservedAt != record.ObservedAtUnixMilliseconds() || item.ValidFrom != record.ValidFromUnixMilliseconds() || item.ValidUntil != record.ValidUntilUnixMilliseconds() || item.StaleAfter != 0 || item.FreshnessIdentity != "" || item.Confidence != 0 || item.Rank != uint8(j+1) || item.PathScore == 0 || item.SymbolScore != 0 || item.TextScore != 0 {
				t.Fatal("advisory fields/score changed between real retrieval and model")
			}
			expected := false
			for _, r := range w.Records {
				if r.Identity == item.MemoryID {
					expected = true
					if item.Text != r.Text || !slices.Equal(item.EvidenceIDs, r.Evidence) || item.ProducerIdentity != r.Producer || item.ObservedAt != r.Observed || item.ValidFrom != r.From || item.ValidUntil != r.Until {
						t.Fatal("loaded declaration changed")
					}
				}
			}
			if !expected {
				t.Fatal("query returned a record never loaded")
			}
			for _, source := range p.Sources {
				if source.ID == item.MemoryID || slices.Contains(item.EvidenceIDs, source.ID) {
					t.Fatal("advisory note promoted to acquired source")
				}
			}
		}
	}
	if selected != 1 {
		t.Fatal("expected only the actual changed-path advisory")
	}
}
func rmResultBounds(t *testing.T, r Result, path string, opted bool) {
	t.Helper()
	encoded, e := EncodeResult(r)
	var text bytes.Buffer
	if e != nil || len(encoded) > 256<<10 || RenderResult(&text, r) != nil || text.Len() > 64<<10 || MaxResultJSONBytes != 256<<10 || MaxResultTextBytes != 64<<10 {
		t.Fatal("result bounds changed")
	}
	for _, forbidden := range []string{rmAdvice, path, rmModelKey, rmModelSecret} {
		if strings.Contains(string(encoded), forbidden) || strings.Contains(text.String(), forbidden) {
			t.Fatal("private input/source/credential leaked in result")
		}
	}
	l := r.wire.Limitations
	if slices.Contains(l, "empty_memory_index") == opted || slices.Contains(l, "retained_input_advisory_not_all_records_selected") != opted || slices.Contains(l, "retained_input_read_only") != opted {
		t.Fatal("opt-in result limitations are inaccurate")
	}
	for _, x := range []string{"loose_git_objects_only", "bounded_source_context", "no_publication", "ephemeral_state_no_resume"} {
		if !slices.Contains(l, x) {
			t.Fatal("existing limitation disappeared")
		}
	}
	if r.wire.ComprehensiveClearance {
		t.Fatal("advisory import asserted comprehensive clearance")
	}
}

func TestRetainedSessionFreshGraphsUseActualRetrievedAdvice(t *testing.T) {
	f := newRmModelFixture(t, rmModelFixtureOptions{})
	seed, w, path := rmOpted(t, f, rmNewClock(), []string{"a.go", "caller.go"})
	inputID := seed.RetainedMemoryInput.Identity()
	_ = seed.ObjectsRoot.Close()
	seed = SessionOptions{}
	before, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	type observation struct{ root, request, scope, context, retrieval string }
	execute := func(run string) observation {
		o := rmOptions(t, f, rmNewClock())
		input := rmLoad(t, path, w, o)
		o.RetainedMemoryInput = &input
		s, e := NewSession(o)
		if e != nil {
			t.Fatal(e)
		}
		defer rmClose(t, s)
		p := rmPrepare(t, s, f, run)
		rmNineTasks(t, p)
		if !s.issued[p.RequestIdentity()] {
			t.Fatal("Prepare did not seal issued request authority")
		}
		r, e := s.Run(context.Background(), p)
		if e != nil {
			t.Fatal(e)
		}
		if r.wire.Status != "findings" || r.wire.RunStatus != "succeeded" || r.wire.Independence != "distinct_provider" || len(r.wire.Tasks) != 9 || !r.wire.UsageKnown || r.wire.ActualCostMicroUSD != 0 || r.ExitCode() != 4 {
			t.Fatal("real pipeline did not produce bounded independent finding")
		}
		for _, task := range r.wire.Tasks {
			if task.Status != "succeeded" || task.Attempts != 1 {
				t.Fatal("native nine-task run did not finish once")
			}
		}
		rmResultBounds(t, r, path, true)
		m, a := rmReadMemory(t, s, p, o.Clock.Now())
		if m.RetrieverIdentity() != inputID || m.MemoryScopeIdentity() != w.Scope.Identity || m.PolicyIdentity() != o.Policy.ReviewPolicyIdentity() || len(m.Queries()) != 1 || m.Queries()[0].Path() != "a.go" || len(m.Omissions()) != 0 {
			t.Fatal("changed-path selection or input handler identity changed")
		}
		if !slices.Contains(a.Provenance(), inputID) || !slices.Contains(a.Provenance(), w.Scope.Identity) {
			t.Fatal("native retrieval lacks input/scope provenance")
		}
		taskInput := rmTaskArtifact(t, s, p, "context", o.Clock.Now())
		gi, e := modelhandler.ParseGenerationInput(taskInput.Payload())
		if e != nil {
			t.Fatal(e)
		}
		packet := rmArtifact(t, s, p, gi.ContextArtifactIdentity(), o.Clock.Now())
		if packet.PayloadDigest() != r.wire.Context || !slices.Contains(packet.Provenance(), a.Identity()) || !slices.Contains(packet.Provenance(), m.Identity()) || !packet.ExpiresAt().Equal(time.UnixMilli(w.Records[0].Until)) {
			t.Fatal("native context lost retrieval lineage/freshness")
		}
		_, gc := f.generation.snapshot()
		_, vc := f.verification.snapshot()
		g, v := gc[len(gc)-1], vc[len(vc)-1]
		if g.ContextID != r.wire.Context || g.RequestID != r.wire.GenerationRequest || v.ContextID != r.wire.VerificationContext || v.RequestID != r.wire.VerificationRequest || v.Packet.GenerationContext != g.ContextID || v.Packet.CandidateBatch != r.wire.CandidateBatch || g.Packet.Scope != p.Plan().Scope().Identity() || v.Packet.Scope != g.Packet.Scope {
			t.Fatal("actual independent requests lost context/candidate lineage")
		}
		rmRecordInPacket(t, g.Packet, w, m)
		rmRecordInPacket(t, v.Packet, w, m)
		return observation{s.rootID, p.RequestIdentity(), p.Plan().Scope().Identity(), r.wire.Context, m.ArtifactIdentity()}
	}
	// The closure returns IDs only. Graph A is closed and unreachable before B.
	a := execute("retained-graph-a")
	b := execute("retained-graph-b")
	if a.root == b.root || a.request == b.request || a.scope == b.scope || a.context == b.context || a.retrieval == b.retrieval {
		t.Fatal("fresh graph reused prior root/run/context authority")
	}
	after, e := os.ReadFile(path)
	if e != nil || !bytes.Equal(before, after) {
		t.Fatal("read-only import rewrote the protected input")
	}
	gc, _ := f.generation.snapshot()
	vc, _ := f.verification.snapshot()
	if gc != 2 || vc != 2 {
		t.Fatal("fresh runs did not dispatch exactly one generation and independent verification each")
	}
}

func TestRetainedSessionLoadedDoesNotMeanSelected(t *testing.T) {
	f := newRmModelFixture(t, rmModelFixtureOptions{})
	o, w, path := rmOpted(t, f, rmNewClock(), []string{"caller.go"})
	s := rmSession(t, o)
	p := rmPrepare(t, s, f, "unchanged-only")
	r, e := s.Run(context.Background(), p)
	if e != nil || r.wire.RunStatus != "succeeded" {
		t.Fatal("real unchanged-only graph failed")
	}
	rmResultBounds(t, r, path, true)
	m, _ := rmReadMemory(t, s, p, o.Clock.Now())
	if len(m.Queries()) != 1 || m.Queries()[0].Path() != "a.go" || len(m.Queries()[0].Items()) != 0 || m.RetrieverIdentity() != o.RetainedMemoryInput.Identity() {
		t.Fatal("loaded unchanged record became a queried source")
	}
	_, g := f.generation.snapshot()
	_, v := f.verification.snapshot()
	if len(g) != 1 || len(v) != 1 {
		t.Fatal("real models missing")
	}
	for _, c := range []rmModelCapture{g[0], v[0]} {
		if len(c.Packet.Memory.Items) != 0 || c.Packet.Memory.IndexRevision != 1 || c.Packet.MemoryScope != w.Scope.Identity || len(c.Packet.AdditionalMemory) != 0 {
			t.Fatal("unselected input falsely delivered as new source evidence")
		}
	}
	// Direct private helper checks only its closed search surface; it is never
	// injected into Session and cannot substitute for the real graph above.
	retriever, e := newRetainedMemoryRetriever(*o.RetainedMemoryInput)
	if e != nil {
		t.Fatal(e)
	}
	foreign, e := memory.NewScope("other", o.RepositoryID, "local-reviewer", memory.RefVisibilityExact, w.Head.Identity, []string{"."})
	if e != nil {
		t.Fatal(e)
	}
	q, e := memory.NewLexicalQuery(foreign, "caller.go", nil, nil, o.Clock.Now(), 1)
	if e != nil {
		t.Fatal(e)
	}
	got, e := retriever.Search(context.Background(), foreign, q)
	if (!errors.Is(e, memory.ErrMemoryQueryScopeMismatch) && !errors.Is(e, memory.ErrMemoryRecordScopeMismatch)) || got.Identity() != "" {
		t.Fatal("private retriever did not return a closed scope error")
	}
}

func TestRetainedSessionConstructorRefusesBeforeCredentialsAndKeepsRoot(t *testing.T) {
	for _, kind := range []string{"forged", "expired", "runtime policy", "repository identity", "tenant", "repository partition", "egress", "investigation"} {
		t.Run(kind, func(t *testing.T) {
			f := newRmModelFixture(t, rmModelFixtureOptions{})
			c := rmNewClock()
			o, _, _ := rmOpted(t, f, c, []string{"a.go"})
			forbidden := &rmForbiddenCredentials{}
			o.Credentials = forbidden
			switch kind {
			case "forged":
				var forged runtimeconfig.RetainedMemoryInput
				if json.Unmarshal([]byte(`{"identity":"pretend","records":[]}`), &forged) != nil {
					t.Fatal("JSON fixture")
				}
				o.RetainedMemoryInput = &forged
			case "expired":
				c.set(c.Now().Add(time.Minute))
			case "tenant":
				o.TenantID = "other-tenant"
			case "repository partition":
				o.RepositoryID = "other-repository"
			case "repository identity":
				var e error
				o.Repository, e = evidence.NewRepositoryIdentity("example.test", []string{"other"}, "sample")
				if e != nil {
					t.Fatal(e)
				}
			case "runtime policy":
				b, e := os.ReadFile(f.policyPath)
				if e != nil {
					t.Fatal(e)
				}
				var w map[string]any
				if json.Unmarshal(b, &w) != nil {
					t.Fatal("policy fixture")
				}
				w["max_output_tokens"] = 4097
				o.Policy, e = runtimeconfig.DecodeRuntimePolicy(context.Background(), bytes.NewReader(rmJSON(t, w)), o.Inventory)
				if e != nil {
					t.Fatal(e)
				}
			case "egress":
				o.Egress = EgressPolicyApproved
			}
			var s *Session
			var e error
			if kind == "investigation" {
				policy, e2 := review.ParseInvestigationPolicy(rmJSON(t, map[string]any{"contract": "open-trestle/investigation-policy", "schema_version": 1, "profile": "snapshot-read-v1", "max_model_turns": 5, "max_tool_calls": 3, "max_returned_bytes": 32768, "max_scanned_bytes": 65536, "max_files": 16, "max_lines_per_read": 20, "max_matches": 8, "max_result_bytes": 8192, "max_cost_micro_usd": 0, "timeout_milliseconds": 5000}))
				if e2 != nil || validateInvestigationSessionPolicy(o, policy) != nil {
					t.Fatal("investigation negative lacks an otherwise valid policy")
				}
				s, e = NewInvestigationSession(o, policy)
			} else {
				s, e = NewSession(o)
			}
			if s != nil || !errors.Is(e, ErrInvalidSession) || forbidden.calls != 0 {
				if s != nil {
					rmClose(t, s)
				}
				t.Fatal("input refusal reached credential factory or transferred ownership")
			}
			if _, e := o.ObjectsRoot.Stat("."); e != nil {
				t.Fatal("failed constructor stole caller root")
			}
			rmNoCalls(t, f)
		})
	}
}

func TestRetainedSessionPrepareHeadAndCallerPointerAreBound(t *testing.T) {
	f := newRmModelFixture(t, rmModelFixtureOptions{})
	c := rmNewClock()
	o, w, path := rmOpted(t, f, c, []string{"a.go"})
	inputID := o.RetainedMemoryInput.Identity()
	s := rmSession(t, o)
	// Caller mutation is legal after construction. Session must own the value.
	*o.RetainedMemoryInput = runtimeconfig.RetainedMemoryInput{}
	// The real Prepare/Run below must still validate and deliver the original
	// value. Do not require a particular private field layout for its owned copy.
	base, head := rmRevisions(t, f)
	scope, e := audit.NewReviewScope(o.TenantID, o.RepositoryID, "wrong-head")
	if e != nil {
		t.Fatal(e)
	}
	wrong, e := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("f", 40))
	if e != nil {
		t.Fatal(e)
	}
	p, e := s.Prepare(context.Background(), scope, rmHash([]byte("wrong-head")), base, wrong)
	if !errors.Is(e, ErrPreparedReviewMismatch) || !reflect.DeepEqual(p, runtimecatalog.PreparedReviewRun{}) || len(s.issued) != 0 {
		t.Fatal("wrong actual head minted prepared authority")
	}
	good := rmPrepare(t, s, f, "original-head")
	rmNoStaging(t, s, good, c.Now())
	otherOptions := rmOptions(t, f, rmNewClock())
	otherInput := rmLoad(t, path, w, otherOptions)
	otherOptions.RetainedMemoryInput = &otherInput
	other := rmSession(t, otherOptions)
	foreignResult, foreignError := other.Run(context.Background(), good)
	if !errors.Is(foreignError, ErrPreparedReviewMismatch) || !reflect.DeepEqual(foreignResult, Result{}) {
		t.Fatal("new root Session accepted another Session's sealed request")
	}
	rmNoStaging(t, other, good, c.Now())
	rmNoCalls(t, f)

	if !s.issued[good.RequestIdentity()] || head.Identity() != w.Scope.RefSet {
		t.Fatal("actual Prepare head not sealed by issued request")
	}
	r, e := s.Run(context.Background(), good)
	if e != nil || r.wire.RunStatus != "succeeded" {
		t.Fatal("caller pointer mutation corrupted the owned loaded value")
	}
	m, _ := rmReadMemory(t, s, good, c.Now())
	if m.RetrieverIdentity() != inputID {
		t.Fatal("caller changed private index authority")
	}
	c.set(time.UnixMilli(w.Records[0].Until))
	before := len(s.issued)
	p, e = s.Prepare(context.Background(), scope, rmHash([]byte("late")), base, head)
	if !errors.Is(e, ErrPreparedReviewMismatch) || !reflect.DeepEqual(p, runtimecatalog.PreparedReviewRun{}) || len(s.issued) != before {
		t.Fatal("expired Prepare minted authority")
	}
}

func TestRetainedSessionRunFreshnessIsStrictAndPreEffect(t *testing.T) {
	for _, offset := range []time.Duration{-time.Nanosecond, 0, time.Nanosecond, 5 * time.Second} {
		t.Run(offset.String(), func(t *testing.T) {
			f := newRmModelFixture(t, rmModelFixtureOptions{})
			c := rmNewClock()
			o, w, path := rmOpted(t, f, c, []string{"a.go"})
			s := rmSession(t, o)
			p := rmPrepare(t, s, f, "freshness-bound")
			until := time.UnixMilli(w.Records[0].Until)
			c.set(until.Add(-o.Timeout).Add(offset))
			r, e := s.Run(context.Background(), p)
			if offset < 0 {
				if e != nil || r.wire.RunStatus != "succeeded" {
					t.Fatal("strictly beyond through-run bound was refused")
				}
				m, a := rmReadMemory(t, s, p, c.Now())
				if !a.ExpiresAt().Equal(until) || len(m.Queries()[0].Items()) != 1 {
					t.Fatal("freshness admission extended advisory dates")
				}
			}
			if offset >= 0 {
				if !errors.Is(e, ErrPreparedReviewMismatch) || !reflect.DeepEqual(r, Result{}) {
					t.Fatal("expired/through-run boundary did not return zero mismatch")
				}
				rmNoStaging(t, s, p, c.Now())
				rmNoCalls(t, f)
			}
			b, e := os.ReadFile(path)
			if e != nil || !bytes.Equal(b, rmJSON(t, w)) || s.options.RetainedMemoryInput.Records()[0].ValidUntilUnixMilliseconds() != until.UnixMilli() {
				t.Fatal("Run extended retained input validity")
			}
		})
	}
	t.Run("unqueried record also bounds admission", func(t *testing.T) {
		f := newRmModelFixture(t, rmModelFixtureOptions{})
		c := rmNewClock()
		o, w, path := rmOpted(t, f, c, []string{"a.go", "caller.go"})
		until := c.Now().Add(30 * time.Second)
		for i := range w.Records {
			if w.Records[i].Path == "caller.go" {
				w.Records[i].Until = until.UnixMilli()
			}
		}
		rmReseal(t, &w, true)
		if e := os.WriteFile(path, rmJSON(t, w), 0600); e != nil {
			t.Fatal(e)
		}
		input := rmLoad(t, path, w, o)
		o.RetainedMemoryInput = &input
		s := rmSession(t, o)
		p := rmPrepare(t, s, f, "unselected-expiry")
		c.set(until.Add(-o.Timeout))
		r, e := s.Run(context.Background(), p)
		if !errors.Is(e, ErrPreparedReviewMismatch) || !reflect.DeepEqual(r, Result{}) {
			t.Fatal("Run checked only the changed-path record, not each loaded record")
		}
		rmNoStaging(t, s, p, c.Now())
		rmNoCalls(t, f)
	})

}

func TestRetainedSessionContextExpiresBeforeGenerationDispatch(t *testing.T) {
	f := newRmModelFixture(t, rmModelFixtureOptions{})
	c := rmNewClock()
	o, w, _ := rmOpted(t, f, c, []string{"a.go"})
	s := rmSession(t, o)
	p := rmPrepare(t, s, f, "context-expiry")
	at := c.Now()
	until := time.UnixMilli(w.Records[0].Until)
	c.arm(s, p.Plan().Scope(), until)
	_, _ = s.Run(context.Background(), p)
	c.mu.Lock()
	jumped := c.jumped
	c.mu.Unlock()
	if !jumped {
		t.Fatal("native context-completion boundary never observed")
	}
	inputArtifact := rmTaskArtifact(t, s, p, "context", at)
	input, e := modelhandler.ParseGenerationInput(inputArtifact.Payload())
	if e != nil {
		t.Fatal(e)
	}
	a := rmArtifact(t, s, p, input.ContextArtifactIdentity(), at)
	if !a.ExpiresAt().Equal(until) {
		t.Fatal("actual assembled context extended input expiry")
	}
	if _, e := s.store.Get(context.Background(), p.Plan().Scope(), a.Identity(), until); !errors.Is(e, artifact.ErrArtifactExpired) {
		t.Fatal("context usable at exact expiry")
	}
	events, e := s.journal.Read(context.Background(), p.Plan().Scope(), 0, 1000)
	if e != nil {
		t.Fatal(e)
	}
	failed := false
	for _, event := range events {
		if event.TaskKey() == "candidates" && event.Kind() == controlplane.RunEventTaskFailed {
			failed = true
		}
	}
	if !failed {
		t.Fatal("actual generation task did not refuse expired context")
	}
	rmNoCalls(t, f)
	auditEvents, e := s.ledger.Read(context.Background(), p.Plan().Scope(), 0, 32)
	if e != nil {
		t.Fatal(e)
	}
	for _, event := range auditEvents {
		if event.Kind() == audit.EventRouteAttemptClaimed {
			t.Fatal("expired context claimed external model authority")
		}
	}

}

func TestRetainedSessionCancellationBusyDuplicateAndCloseDrain(t *testing.T) {
	t.Run("pre-canceled precedence", func(t *testing.T) {
		f := newRmModelFixture(t, rmModelFixtureOptions{})
		c := rmNewClock()
		o, w, path := rmOpted(t, f, c, []string{"a.go"})
		s := rmSession(t, o)
		p := rmPrepare(t, s, f, "precanceled")
		c.set(time.UnixMilli(w.Records[0].Until))
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		r, e := s.Run(ctx, p)
		if e != nil || r.wire.Status != "canceled" || r.wire.RunStatus != "not_opened" {
			t.Fatal("freshness gate stole existing pre-canceled disposition")
		}
		rmResultBounds(t, r, path, true)
		rmNoCalls(t, f)
		if _, e := s.Run(context.Background(), p); !errors.Is(e, ErrReviewRunAlreadyExists) {
			t.Fatal("pre-canceled claim replayed")
		}
	})
	t.Run("in flight", func(t *testing.T) {
		f := newRmModelFixture(t, rmModelFixtureOptions{generationMode: "wait"})
		c := rmNewClock()
		o, _, _ := rmOpted(t, f, c, []string{"a.go"})
		s := rmSession(t, o)
		p := rmPrepare(t, s, f, "active")
		other := rmPrepare(t, s, f, "other")
		type outcome struct {
			r Result
			e error
		}
		done := make(chan outcome, 1)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() { r, e := s.Run(ctx, p); done <- outcome{r, e} }()
		select {
		case <-f.generation.entered:
		case <-time.After(3 * time.Second):
			t.Fatal("real HTTP barrier not reached")
		}
		if _, e := o.ObjectsRoot.Stat("."); e != nil {
			t.Fatal("active source root closed early")
		}
		c.set(c.Now().Add(time.Minute - o.Timeout)) // now+Timeout equals retained expiry; busy/duplicate still win.
		if _, e := s.Run(context.Background(), p); !errors.Is(e, ErrReviewRunAlreadyExists) {
			t.Fatal("active duplicate replayed")
		}
		if _, e := s.Run(context.Background(), other); !errors.Is(e, ErrSessionBusy) {
			t.Fatal("active Session admitted second scope")
		}
		rmClose(t, s)
		select {
		case <-f.generation.canceled:
		case <-time.After(3 * time.Second):
			t.Fatal("Close did not cancel actual HTTP")
		}
		select {
		case out := <-done:
			if out.e != nil || out.r.wire.Status != "canceled" || out.r.wire.RunStatus != "canceled" {
				t.Fatal("Close lost native canceled readback")
			}
		case <-time.After(3 * time.Second):
			t.Fatal("Close did not drain Run")
		}
		if _, e := o.ObjectsRoot.Stat("."); e == nil {
			t.Fatal("drained Close retained root")
		}
		if _, e := s.Run(context.Background(), other); !errors.Is(e, ErrSessionClosed) {
			t.Fatal("closed precedence changed")
		}
		rmClose(t, s)
		g, _ := f.generation.snapshot()
		v, _ := f.verification.snapshot()
		if g != 1 || v != 0 {
			t.Fatal("drain duplicated model effect")
		}
	})
}

func TestRetainedSessionNilIdentityAndResourceControls(t *testing.T) {
	f := newRmModelFixture(t, rmModelFixtureOptions{})
	c := rmNewClock()
	o := rmOptions(t, f, c)
	s := rmSession(t, o)
	explicit := rmOptions(t, f, rmNewClock())
	explicit.RetainedMemoryInput = nil
	s2 := rmSession(t, explicit)
	if s.catalog.Identity() != s2.catalog.Identity() || !reflect.DeepEqual(s.catalog.Bindings(), s2.catalog.Bindings()) {
		t.Fatal("explicit nil changed legacy catalog identity")
	}
	p := rmPrepare(t, s, f, "legacy")
	r, e := s.Run(context.Background(), p)
	if e != nil {
		t.Fatal(e)
	}
	rmResultBounds(t, r, "unused-private-path", false)
	m, _ := rmReadMemory(t, s, p, c.Now())
	if m.RetrieverIdentity() != digest("empty-memory-index-v1") || len(m.Queries()) != 1 || len(m.Queries()[0].Items()) != 0 {
		t.Fatal("nil changed original empty-memory handler")
	}
	// Pure existing unstarted projection under equal options and the same sealed
	// request has no random fields to normalize. No second Run is fabricated.
	implicitBytes, e := EncodeResult(s.unstarted(p, "canceled"))
	if e != nil {
		t.Fatal(e)
	}
	explicitBytes, e := EncodeResult(s2.unstarted(p, "canceled"))
	if e != nil || !bytes.Equal(implicitBytes, explicitBytes) {
		t.Fatal("explicit nil changed default result bytes")
	}
	for _, mode := range []string{"artifact capacity", "cost", "route capacity", "verifier pending", "unsupported storage"} {
		t.Run(mode, func(t *testing.T) {
			settings := rmModelFixtureOptions{expensive: mode == "cost", capacity: mode == "route capacity", verifierPending: mode == "verifier pending"}
			f := newRmModelFixture(t, settings)
			o, _, path := rmOpted(t, f, rmNewClock(), []string{"a.go"})
			if mode == "unsupported storage" {
				if e := os.WriteFile(f.objects+"/alternates", []byte("never-follow"), 0600); e != nil {
					t.Fatal(e)
				}
				forbidden := &rmForbiddenCredentials{}
				o.Credentials = forbidden
				s, e := NewSession(o)
				if s != nil || !errors.Is(e, ErrUnsupportedSource) || forbidden.calls != 0 {
					t.Fatal("memory weakened source admission")
				}
				if _, e := o.ObjectsRoot.Stat("."); e != nil {
					t.Fatal("source refusal stole root")
				}
				rmNoCalls(t, f)
				return
			}
			if mode == "artifact capacity" {
				o.ArtifactCapacity = 2
			}
			s := rmSession(t, o)
			p := rmPrepare(t, s, f, "bounded")
			r, e := s.Run(context.Background(), p)
			if e != nil || r.wire.CI == "pass" || r.wire.RunStatus == "active" || r.wire.Status == "findings" {
				t.Fatal("memory bypassed resource/inventory guard")
			}
			rmResultBounds(t, r, path, true)
			g, _ := f.generation.snapshot()
			v, _ := f.verification.snapshot()
			if v != 0 || mode != "verifier pending" && g != 0 {
				t.Fatal("bound failure gained external attempt")
			}
		})
	}
}
