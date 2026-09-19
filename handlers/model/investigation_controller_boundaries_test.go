package model_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	model "github.com/georgejieh/open-trestle/handlers/model"
	source "github.com/georgejieh/open-trestle/handlers/source"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/memory"
	"github.com/georgejieh/open-trestle/internal/review"
)

func boundaryInitialFixture(t *testing.T, path string) (model.InvestigationOptions, *upperStore, *upperModel, *upperModel) {
	t.Helper()
	o, store, a, b, head, _ := upperFixture(t, "")
	ctx := context.Background()
	// A broader REAL setup reader constructs host selection data, not profile authority.
	reader, err := source.NewSnapshotReader(ctx, o.Store, o.Clock, o.Scope, o.HeadSnapshotArtifactIdentity, head.Identity(), source.SnapshotReadLimits{MaxFiles: 2, MaxLines: 20, MaxScannedBytes: 65536, MaxResultBytes: 8192, MaxMatches: 8})
	upperCheck(t, err)
	listing, err := reader.List(ctx)
	upperCheck(t, err)
	selected := []source.SnapshotSlice{}
	files := []evidence.RepositoryFile{}
	for _, ref := range head.Files() {
		value, err := store.Get(ctx, o.Scope, ref.ArtifactIdentity(), o.Clock.Now())
		upperCheck(t, err)
		file, err := source.ParseFileArtifact(value, head, ref)
		upperCheck(t, err)
		metadata, err := evidence.NewRepositoryFile(file.Path(), file.Content())
		upperCheck(t, err)
		files = append(files, metadata)
	}
	for _, ref := range listing.Files() {
		if path == "both" || ref.Path() == path {
			value, err := reader.Read(ctx, ref.Ref(), 2, 2)
			upperCheck(t, err)
			selected = append(selected, value)
		}
	}
	if len(selected) == 0 {
		t.Fatal("setup did not bind selected physical source")
	}
	manifest, err := evidence.NewRepositoryManifest(files)
	upperCheck(t, err)
	ranges := []evidence.SourceRange{}
	sources := []review.ContextSource{}
	for _, value := range selected {
		span := value.Binding().SourceRange()
		item, err := evidence.NewEvidenceItem(value.Binding().Identity(), evidence.EvidenceKindSource, value.Binding().SliceDigest(), span)
		upperCheck(t, err)
		bound, err := review.NewBoundContextSource(review.ContextStageChangedHunk, memory.TaintRepositoryControlled, item, value.Content(), value.Binding())
		upperCheck(t, err)
		ranges = append(ranges, span)
		sources = append(sources, bound)
	}
	snapshot, err := review.NewAcquiredReviewPipelineSnapshot(o.Scope.ReviewRunID(), manifest, ranges)
	upperCheck(t, err)
	memScope, err := memory.NewScope(o.Scope.TenantID(), o.Scope.RepositoryID(), "reviewer", memory.RefVisibilityExact, upperDigest([]byte("review-policy")), []string{"."})
	upperCheck(t, err)
	limits, err := review.NewContextLimits(65536, 0)
	upperCheck(t, err)
	packet, err := review.NewContextPacket(o.Scope, memScope, snapshot, review.ContextTaskCandidateGeneration, sources, o.InitialContext.Retrieval(), limits)
	upperCheck(t, err)
	encoded, err := review.EncodeInvestigationPolicy(o.Policy)
	upperCheck(t, err)
	var policy map[string]any
	upperCheck(t, json.Unmarshal(encoded, &policy))
	policy["max_files"] = 1
	o.Policy, err = review.ParseInvestigationPolicy(upperJSON(t, policy))
	upperCheck(t, err)
	o.MemoryScope = memScope
	o.InitialContext = packet
	o.InitialSnapshot = snapshot
	return o, store, a, b
}
func TestInvestigationInitialSelectionOutsideIssuedReferencesRefusesBeforeBootstrap(t *testing.T) {
	for _, path := range []string{"a.go", "notes.txt", "both"} {
		t.Run(path, func(t *testing.T) {
			o, store, a, b := boundaryInitialFixture(t, path)
			before := store.fileGets()
			controller, err := model.NewInvestigation(context.Background(), o)
			if path != "a.go" {
				if err == nil || controller != nil {
					t.Fatal("excluded initial source received a controller")
				}
				if store.fileGets() != before || a.count() != 0 || b.count() != 0 {
					t.Fatal("coverage refusal happened after bootstrap/model effect")
				}
				events, err := o.Ledger.Read(context.Background(), o.Scope, 0, 100)
				upperCheck(t, err)
				if len(events) != 0 {
					t.Fatal("coverage refusal created route/tool authority")
				}
				return
			}
			upperCheck(t, err)
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				upperCheck(t, controller.Close(ctx))
			})
			step, err := controller.Step(context.Background())
			upperCheck(t, err)
			if a.count() != 1 || b.count() != 0 || store.fileGets()-before != 1 || step.ScannedBytes() != uint64(len(upperInitial)) {
				t.Fatal("same low policy did not admit its actual first-file positive")
			}
		})
	}
}

type boundaryLedger struct {
	audit.Ledger
	mu               sync.Mutex
	target           audit.EventKind
	mode             string
	attempts         []audit.Event
	competingWritten bool
}

func (l *boundaryLedger) arm(kind audit.EventKind, mode string) {
	l.mu.Lock()
	l.target = kind
	l.mode = mode
	l.attempts = nil
	l.competingWritten = false
	l.mu.Unlock()
}
func (l *boundaryLedger) snapshot() ([]audit.Event, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]audit.Event(nil), l.attempts...), l.competingWritten
}
func (l *boundaryLedger) Append(ctx context.Context, head string, event audit.Event) error {
	l.mu.Lock()
	target, mode := l.target, l.mode
	if event.Kind() != target {
		l.mu.Unlock()
		return l.Ledger.Append(ctx, head, event)
	}
	l.attempts = append(l.attempts, event)
	attempt := len(l.attempts)
	l.mu.Unlock()
	switch mode {
	case "conflict once":
		if attempt == 1 {
			return audit.ErrAuditHeadConflict
		}
	case "all conflicts":
		return audit.ErrAuditHeadConflict
	case "competing actual claim":
		if attempt == 1 {
			if err := l.Ledger.Append(ctx, head, event); err != nil {
				return err
			}
			l.mu.Lock()
			l.competingWritten = true
			l.mu.Unlock()
			return audit.ErrAuditHeadConflict
		}
	case "unknown actual write":
		if err := l.Ledger.Append(ctx, head, event); err != nil {
			return err
		}
		return errors.New("fixture unknown append outcome")
	}
	return l.Ledger.Append(ctx, head, event)
}
func boundaryController(t *testing.T) (model.InvestigationOptions, *upperStore, *upperModel, *upperModel, *boundaryLedger, *model.Investigation, model.InvestigationStep) {
	t.Helper()
	o, store, a, b, _, _ := upperFixture(t, "")
	ledger := &boundaryLedger{Ledger: o.Ledger}
	o.Ledger = ledger
	controller, err := model.NewInvestigation(context.Background(), o)
	upperCheck(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		upperCheck(t, controller.Close(ctx))
	})
	first, err := controller.Step(context.Background())
	upperCheck(t, err)
	if a.count() != 1 || b.count() != 0 {
		t.Fatal("real initial list did not complete before targeted ledger injection")
	}
	return o, store, a, b, ledger, controller, first
}
func boundaryCheckClaim(t *testing.T, o model.InvestigationOptions, ledger *boundaryLedger, step model.InvestigationStep, attempt audit.Event) {
	t.Helper()
	var next upperPacket
	upperCheck(t, json.Unmarshal(step.NextRequest().Payload(), &next))
	parents := []string{next.Investigation.Session, o.HeadSnapshotArtifactIdentity, step.Turn().Identity(), step.Turn().Outcome().Identity(), step.Turn().Dispatch().Response().Identity()}
	slices.Sort(parents)
	if attempt.Kind() != audit.EventInvestigationToolClaimed || attempt.Scope().Identity() != o.Scope.Identity() || !slices.Equal(attempt.CausalParentIdentities(), parents) {
		t.Fatal("actual claimed operation lost exact scope/model/head parents")
	}
	events, err := ledger.Read(context.Background(), o.Scope, 0, 100)
	upperCheck(t, err)
	claims := 0
	for _, event := range events {
		if event.Kind() == audit.EventInvestigationToolClaimed && event.SubjectIdentity() == attempt.SubjectIdentity() {
			claims++
		}
	}
	if claims != 1 {
		t.Fatal("CAS retry duplicated or omitted actual claim")
	}
}
func TestInvestigationClaimConflictThenSuccessExecutesReaderExactlyOnce(t *testing.T) {
	o, store, a, b, ledger, c, first := boundaryController(t)
	ledger.arm(audit.EventInvestigationToolClaimed, "conflict once")
	before := store.fileGets()
	step, err := c.Step(context.Background())
	upperCheck(t, err)
	attempts, _ := ledger.snapshot()
	if len(attempts) != 2 || store.fileGets()-before != 1 || a.count() != 2 || b.count() != 0 || step.ScannedBytes() != first.ScannedBytes()+uint64(len(upperNotes)) {
		t.Fatal("claim conflict duplicated effects or lost full scan accounting")
	}
	if attempts[0].SubjectIdentity() != attempts[1].SubjectIdentity() || !slices.Equal(attempts[0].CausalParentIdentities(), attempts[1].CausalParentIdentities()) {
		t.Fatal("claim retry changed operation identity or authority")
	}
	boundaryCheckClaim(t, o, ledger, step, attempts[1])
}
func TestInvestigationClaimConflictCompetingOrUnknownNeverGrantsReaderPermission(t *testing.T) {
	for _, mode := range []string{"competing actual claim", "unknown actual write", "all conflicts"} {
		t.Run(mode, func(t *testing.T) {
			o, store, a, b, ledger, c, first := boundaryController(t)
			ledger.arm(audit.EventInvestigationToolClaimed, mode)
			before := store.fileGets()
			step, err := c.Step(context.Background())
			if err == nil || step.NextRequest().Identity() != "" {
				t.Fatal("unknown/conflicting claim exposed next authority")
			}
			attempts, written := ledger.snapshot()
			want := 1
			if mode == "all conflicts" {
				want = 3
			}
			if len(attempts) != want || store.fileGets() != before || a.count() != 2 || b.count() != 0 {
				t.Fatal("claim refusal retried unknown effect, exceeded three attempts or read source")
			}
			if mode == "competing actual claim" && !written {
				t.Fatal("fixture did not commit the actual competing claim")
			}
			events, err := o.Ledger.Read(context.Background(), o.Scope, 0, 100)
			upperCheck(t, err)
			present := 0
			for _, event := range events {
				if event.Kind() == audit.EventInvestigationToolClaimed && event.SubjectIdentity() == attempts[0].SubjectIdentity() {
					present++
				}
			}
			if mode == "all conflicts" && present != 0 || mode != "all conflicts" && present != 1 {
				t.Fatal("fixture/guard did not preserve real append outcome")
			}
			if step.ScannedBytes() != first.ScannedBytes() || step.ReturnedBytes() != first.ReturnedBytes() {
				t.Fatal("claim-only failure invented reader charges")
			}
			if _, err := c.Verify(context.Background()); err == nil || b.count() != 0 {
				t.Fatal("Verify erased unknown claim progression")
			}
			if _, err := c.Generate(context.Background()); err == nil || a.count() != 2 || store.fileGets() != before {
				t.Fatal("failed claim was retried as fresh controller work")
			}
		})
	}
}
func TestInvestigationCompletionConflictOrUnknownKeepsSpentWorkAndFreezes(t *testing.T) {
	for _, mode := range []string{"all conflicts", "unknown actual write"} {
		t.Run(mode, func(t *testing.T) {
			o, store, a, b, ledger, c, first := boundaryController(t)
			ledger.arm(audit.EventInvestigationToolCompleted, mode)
			before := store.fileGets()
			step, err := c.Step(context.Background())
			if err == nil || step.NextRequest().Identity() != "" {
				t.Fatal("unrecorded completion exposed continuation")
			}
			attempts, _ := ledger.snapshot()
			want := 1
			if mode == "all conflicts" {
				want = 3
			}
			if len(attempts) != want || store.fileGets()-before != 1 || a.count() != 2 || b.count() != 0 {
				t.Fatal("completion handling repeated reader/model work or exceeded bounded retries")
			}
			result, err := store.Get(context.Background(), o.Scope, attempts[0].SubjectIdentity(), o.Clock.Now())
			upperCheck(t, err)
			encoded, err := artifact.Encode(result)
			upperCheck(t, err)
			var wire struct {
				Operation string `json:"operation_identity"`
				Turn      string `json:"turn_identity"`
			}
			upperCheck(t, json.Unmarshal(result.Payload(), &wire))
			parents := []string{wire.Operation, wire.Turn, o.HeadSnapshotArtifactIdentity}
			slices.Sort(parents)
			for _, attempt := range attempts {
				if attempt.Scope().Identity() != o.Scope.Identity() || attempt.SubjectIdentity() != result.Identity() || !slices.Equal(attempt.CausalParentIdentities(), parents) {
					t.Fatal("completion retry changed exact operation/result/head authority")
				}
			}
			if step.ScannedBytes() != first.ScannedBytes()+uint64(len(upperNotes)) || step.ReturnedBytes() != first.ReturnedBytes()+uint64(len(encoded)) {
				t.Fatal("unknown completion refunded actual scan or full retained envelope")
			}
			if _, err := c.Verify(context.Background()); err == nil || b.count() != 0 {
				t.Fatal("Verify cleared unknown completion state")
			}
			if _, err := c.Step(context.Background()); err == nil || store.fileGets()-before != 1 || a.count() != 2 {
				t.Fatal("unrecorded completion caused another reader/model effect")
			}
		})
	}
}

func TestInvestigationMemoryScopeInputMustMatchBeforeEffects(t *testing.T) {
	for _, mode := range []string{"zero", "actor", "tenant"} {
		t.Run(mode, func(t *testing.T) {
			o, store, a, b, _, _ := upperFixture(t, "")
			original := o.MemoryScope
			var replacement memory.Scope
			var err error
			switch mode {
			case "actor":
				replacement, err = memory.NewScope(original.TenantID(), original.RepositoryID(), "different-actor", original.RefVisibility(), original.RefSetIdentity(), original.PathPrefixes())
			case "tenant":
				replacement, err = memory.NewScope("different-tenant", original.RepositoryID(), original.ActorID(), original.RefVisibility(), original.RefSetIdentity(), original.PathPrefixes())
			}
			upperCheck(t, err)
			if replacement.Identity() == o.InitialContext.MemoryScopeIdentity() {
				t.Fatal("fixture did not change memory scope authority")
			}
			o.MemoryScope = replacement
			before := store.fileGets()
			controller, err := model.NewInvestigation(context.Background(), o)
			if err == nil || controller != nil || store.fileGets() != before || a.count() != 0 || b.count() != 0 {
				t.Fatal("missing or mismatched memory scope admitted effects")
			}
			events, err := o.Ledger.Read(context.Background(), o.Scope, 0, 100)
			upperCheck(t, err)
			if len(events) != 0 {
				t.Fatal("memory scope rejection created route or tool authority")
			}
		})
	}
}

func TestInvestigationInitialSelectionOmissionsRefuseBeforeEffects(t *testing.T) {
	for _, omitted := range []bool{false, true} {
		name := "supported"
		if omitted {
			name = "selection-omitted"
		}
		t.Run(name, func(t *testing.T) {
			o, store, a, b, _, _ := upperFixture(t, "")
			initial := o.InitialContext.Sources()[0]
			limits, err := review.NewContextLimits(uint32(initial.SizeBytes()), 0)
			upperCheck(t, err)
			candidates := []review.ContextSource{initial}
			if omitted {
				// A distinct host reference to the SAME genuinely bound physical slice at
				// a lower-priority stage. No new physical binding or analysis success.
				item, err := evidence.NewEvidenceItem(upperDigest([]byte("selection-omitted-reference")), evidence.EvidenceKindSource, initial.SliceBinding().SliceDigest(), initial.SliceBinding().SourceRange())
				upperCheck(t, err)
				extra, err := review.NewBoundContextSource(review.ContextStageRepositoryContext, initial.Taint(), item, initial.Content(), initial.SliceBinding())
				upperCheck(t, err)
				candidates = append(candidates, extra)
			}
			packet, err := review.NewContextPacketWithAccounting(o.Scope, o.MemoryScope, o.InitialSnapshot, review.ContextTaskCandidateGeneration, candidates, o.InitialContext.Retrievals(), o.InitialContext.SourceOmissions(), limits)
			upperCheck(t, err)
			wantOmitted := 0
			if omitted {
				wantOmitted = 1
			}
			if packet.SourceSelection().OmittedCount() != wantOmitted || packet.SourceCount() != 1 || packet.Sources()[0].Identity() != initial.Identity() {
				t.Fatal("fixture failed to isolate selection-level omission")
			}
			o.InitialContext = packet
			before := store.fileGets()
			controller, err := model.NewInvestigation(context.Background(), o)
			if omitted {
				if err == nil || controller != nil || store.fileGets() != before || a.count() != 0 || b.count() != 0 {
					t.Fatal("unrecoverable selection accounting admitted effects")
				}
				events, err := o.Ledger.Read(context.Background(), o.Scope, 0, 100)
				upperCheck(t, err)
				if len(events) != 0 {
					t.Fatal("selection omission refusal created authority")
				}
				return
			}
			upperCheck(t, err)
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				upperCheck(t, controller.Close(ctx))
			})
			step, err := controller.Step(context.Background())
			upperCheck(t, err)
			if a.count() != 1 || b.count() != 0 || store.fileGets()-before != 1 || step.ScannedBytes() != uint64(len(upperInitial)) {
				t.Fatal("same-byte-limit supported initial selection failed")
			}
		})
	}
}
