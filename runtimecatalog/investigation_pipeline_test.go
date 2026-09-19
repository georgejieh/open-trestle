package runtimecatalog_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	modelhandler "github.com/georgejieh/open-trestle/handlers/model"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/worker"
)

func TestInvestigationPipelineRunnerCompletesLiveNineTaskReview(t *testing.T) {
	f := newBridgeFixture(t, "")
	plan := f.prepared.Plan()
	if plan.Mode() != controlplane.ReviewRunLocal || plan.TaskCount() != 9 || len(f.catalog.Bindings()) != 8 {
		t.Fatal("factory changed the local task graph")
	}
	initial, err := f.control.GetRun(f.ctx, plan.Scope())
	requiredCheck(t, err)
	readySources := 0
	for _, task := range initial.Tasks() {
		definition, ok := plan.Task(task.Key())
		if !ok || !definition.Required() {
			t.Fatal("actual prepared task missing")
		}
		attempts, err := controlplane.DefaultTaskAttemptPolicy(definition.Kind())
		requiredCheck(t, err)
		if definition.MaxAttempts() != attempts.MaximumAttempts() || definition.RetryDelayMilliseconds() != attempts.RetryDelayMilliseconds() || definition.LeaseDurationMilliseconds() != attempts.LeaseDurationMilliseconds() {
			t.Fatal("factory changed default attempts")
		}
		if definition.Kind() == controlplane.TaskAcquireSource {
			if len(definition.Dependencies()) != 0 || task.Status() != controlplane.TaskRuntimeAvailable {
				t.Fatal("source serialization was forced by a new dependency")
			}
			readySources++
		}
		if definition.Kind() == controlplane.TaskPublishResult {
			t.Fatal("local factory gained publication")
		}
	}
	if readySources != 2 {
		t.Fatal("both actual sources were not initially ready")
	}
	for _, key := range []string{"candidates", "verification"} {
		task, _ := plan.Task(key)
		handler, ok := f.catalog.Catalog().Resolve(task.HandlerIdentity())
		if !ok {
			t.Fatal("actual model handler missing")
		}
		if key == "candidates" {
			if _, ok := handler.(*modelhandler.InvestigationGenerationTaskHandler); !ok {
				t.Fatal("old generation handler used for investigation")
			}
		} else if _, ok := handler.(*modelhandler.InvestigationVerificationTaskHandler); !ok {
			t.Fatal("old verification handler used for investigation")
		}
	}
	f.start()
	requiredCheck(t, f.runner.Run(f.ctx))
	requiredCheck(t, f.runner.Wait(f.ctx))
	state := f.settle()
	if state.Status() != controlplane.ReviewRunSucceeded {
		t.Fatalf("real nine-task run failed: %s", state.Failure())
	}
	for _, task := range plan.Tasks() {
		value := f.output(state, task.Key())
		runtime, _ := state.Task(task.Key())
		completion := f.trace.completions[task.Key()]
		if runtime.Attempts() != 1 || completion.Status() != controlplane.TaskCompletionSucceeded || completion.OutputIdentity() != value.Identity() {
			t.Fatal("actual successful handler completion was not journaled")
		}
		if f.trace.contexts[task.Key()].Err() == nil {
			t.Fatal("Runner retained a completed task execution context")
		}
	}
	for _, pair := range []string{"context->candidates", "candidates->verification", "verification->readiness"} {
		if !f.trace.canceledBefore[pair] {
			t.Fatalf("later real task started before %s execution context ended", pair)
		}
	}
	if f.ctx.Err() != nil {
		t.Fatal("successful controller outlived a canceled run root")
	}
	trace := f.trace.eventsCopy()
	acquisitions := []string{}
	for _, event := range trace {
		if strings.HasPrefix(event, "acquire:") {
			acquisitions = append(acquisitions, strings.TrimPrefix(event, "acquire:"))
		}
	}
	if len(acquisitions) != 2 || acquisitions[0] == acquisitions[1] || f.trace.sourceCalls != 2 || f.trace.sourceMaximum != 1 || f.trace.sourceActive != 0 {
		t.Fatal("actual source admission was repeated, concurrent, or undrained")
	}
	firstDone := slices.Index(trace, "complete-recorded:"+acquisitions[0])
	secondStarted := slices.Index(trace, "acquire:"+acquisitions[1])
	if firstDone < 0 || secondStarted <= firstDone {
		t.Fatal("next actual Acquire began before the prior real CompleteTask")
	}
	view, err := f.bridge.ReadResult(f.ctx)
	requiredCheck(t, err)
	if view.PlanIdentity() != plan.Identity() || view.ScopeIdentity() != plan.Scope().Identity() || view.RunStatus() != state.Status() || view.OutputIdentity() != state.OutputIdentity() {
		t.Fatal("bridge readback diverged from the actual finalized journal")
	}
	generation, generated := view.Generation()
	verification, verified := view.Verification()
	if !generated || !verified {
		t.Fatal("successful readback lost live admitted final values")
	}
	intent, initialContext := view.ContextIntentArtifact(), view.InitialContextArtifact()
	if !bridgeIsIntent(intent) || intent.Identity() != f.output(state, "context").Identity() || intent.Identity() == generation.InputArtifact().Identity() || initialContext.Identity() == generation.ContextArtifact().Identity() {
		t.Fatal("context intent was mistaken for the final expanded generation input")
	}
	storedInitial, err := f.underlying.Get(f.ctx, plan.Scope(), initialContext.Identity(), f.clock.Now())
	requiredCheck(t, err)
	if storedInitial.Identity() != initialContext.Identity() || generation.ResultArtifact().Identity() != f.output(state, "candidates").Identity() || view.VerificationArtifact().Identity() != f.output(state, "verification").Identity() {
		t.Fatal("held initial/final artifacts are not actual stored task outputs")
	}
	if view.AnalysisArtifactIdentity() != f.output(state, "analysis").Identity() || view.ChangeArtifactIdentity() != f.output(state, "change").Identity() || view.HeadSnapshotArtifactIdentity() != f.output(state, "source-head").Identity() {
		t.Fatal("bridge lost actual upstream lineage")
	}
	headTask, _ := plan.Task("source-head")
	if view.SourceHeadTaskIdentity() != headTask.Identity() {
		t.Fatal("bridge replaced actual source-head task authority")
	}
	if verification.GenerationArtifactIdentity() != generation.ResultArtifact().Identity() || verification.VerificationContext().GenerationContextIdentity() != generation.ContextIdentity() || verification.VerificationContext().CandidateBatchIdentity() != generation.Candidates().Identity() {
		t.Fatal("independent verifier lost final context/candidates")
	}
	requiredCheck(t, gateway.VerifyIndependentRouteAuthorizations(f.configuration.Independence(), generation.RouteExecution().Authorization(), verification.RouteExecution().Authorization()))
	readiness, err := review.EvaluatePublicationReadiness(f.configuration.Publication(), verification.IndependentReceipt(), verification.VerifiedFindings())
	requiredCheck(t, err)
	var recorded struct {
		Readiness    string `json:"readiness_identity"`
		Verification string `json:"verification_artifact_identity"`
		Result       string `json:"verification_result_identity"`
	}
	requiredCheck(t, json.Unmarshal(f.output(state, "readiness").Payload(), &recorded))
	if recorded.Readiness != readiness.Identity() || recorded.Verification != view.VerificationArtifact().Identity() || recorded.Result != verification.Identity() || len(readiness.InlineFindings()) != 1 {
		t.Fatal("existing readiness did not consume the held final verifier")
	}
	set, err := f.diagnostics.GetDiagnosticSet(f.ctx, plan.Scope())
	requiredCheck(t, err)
	if set.VerifiedCount() != 1 || set.VerifiedSetIdentity() != verification.VerifiedFindings().Identity() || set.VerificationContextIdentity() != verification.VerificationContext().Identity() {
		t.Fatal("existing diagnostic materialization lost final-context authority")
	}
	f.assertHistory(view)
	upstreamGets, controllerGets := 0, 0
	for _, get := range f.trace.gets {
		if get.kind != artifact.KindSourceFile {
			continue
		}
		if get.phase == "context" {
			upstreamGets++
		}
		if get.phase == "candidates" {
			controllerGets++
		}
	}
	if upstreamGets == 0 || controllerGets == 0 {
		t.Fatal("fixture did not observe both real context assembly and controller source work")
	}
	t.Logf("observed source-file Gets: context assembly=%d, candidates/bootstrap/tools=%d; controller scan charge=%d, returned=%d", upstreamGets, controllerGets, view.ScannedBytes(), view.ReturnedBytes())
	before := len(f.models.snapshot())
	if err := f.bridge.StartRun(f.ctx, plan); err == nil {
		t.Fatal("one-run bridge admitted another account")
	}
	if len(f.models.snapshot()) != before {
		t.Fatal("refused StartRun replayed paid work")
	}
}

func (f *bridgeFixture) assertHistory(view modelhandler.InvestigationPipelineReadback) {
	f.t.Helper()
	t := f.t
	captures, turns, events := f.models.snapshot(), view.Turns(), f.events()
	if len(captures) != 5 || len(turns) != 5 || view.ToolCalls() != 3 || view.ReturnedBytes() == 0 || view.ReturnedBytes() > 32768 || view.ScannedBytes() == 0 || view.ScannedBytes() > 65536 || !view.UsageKnown() {
		t.Fatal("complete readback omitted actual turns/tools/usage")
	}
	counts := map[audit.EventKind]int{}
	for _, event := range events {
		counts[event.Kind()]++
		if strings.HasPrefix(event.Kind().String(), "publication_") {
			t.Fatal("read-only pipeline gained publication audit authority")
		}
	}
	for _, kind := range []audit.EventKind{audit.EventRouteSelected, audit.EventRouteAttemptClaimed, audit.EventRouteDispatchCompleted, audit.EventRouteCostReconciled} {
		if counts[kind] != 5 {
			t.Fatal("ledger does not contain all five actual paid turns")
		}
	}
	if counts[audit.EventInvestigationToolClaimed] != 3 || counts[audit.EventInvestigationToolCompleted] != 3 {
		t.Fatal("ledger lost actual tool claims/completions")
	}
	previous := ""
	cost := uint64(0)
	seen := map[string]bool{}
	for i, turn := range turns {
		record := turn.Record()
		requiredCheck(t, record.Validate())
		if record.PreviousTurnIdentity() != previous || record.RequestIdentity() != captures[i].request.Request().Identity() || record.Authorization().Identity() != captures[i].request.Authorization().Identity() || seen[record.Identity()] {
			t.Fatal("history did not retain the actual owner turn chain")
		}
		previous, seen[record.Identity()] = record.Identity(), true
		stored, err := f.underlying.Get(f.ctx, f.prepared.Plan().Scope(), turn.Artifact().Identity(), f.clock.Now())
		requiredCheck(t, err)
		payload, err := gateway.EncodeInvestigationTurnRecord(record)
		requiredCheck(t, err)
		if stored.Kind() != artifact.KindInvestigationTurn || !bytes.Equal(stored.Payload(), payload) {
			t.Fatal("turn history reconstructed an unstored capture")
		}
		selection := requiredEvent(t, events, audit.EventRouteSelected, record.Selection().Identity())
		claim := requiredEvent(t, events, audit.EventRouteAttemptClaimed, record.Authorization().Identity())
		outcome := requiredEvent(t, events, audit.EventRouteDispatchCompleted, record.Outcome().Identity())
		reconciliation := requiredEvent(t, events, audit.EventRouteCostReconciled, record.Reconciliation().Identity())
		if selection.Sequence() >= claim.Sequence() || claim.Sequence() >= outcome.Sequence() || outcome.Sequence() >= reconciliation.Sequence() {
			t.Fatal("actual paid turn events changed causal order")
		}
		actual := record.Reconciliation().ActualCost()
		if !actual.IsKnown() || actual.TotalCostMicroUSD() != 200 {
			t.Fatal("priced fake provider usage was lost")
		}
		cost += actual.TotalCostMicroUSD()
		toolIDs := turn.ToolResultArtifactIdentities()
		if i < 3 {
			if len(toolIDs) != 1 {
				t.Fatal("tool-producing turn lost its protected artifact link")
			}
			tool, err := f.underlying.Get(f.ctx, f.prepared.Plan().Scope(), toolIDs[0], f.clock.Now())
			requiredCheck(t, err)
			if tool.Kind() != artifact.KindInvestigationToolResult {
				t.Fatal("tool link points to another stage")
			}
			completed := requiredEvent(t, events, audit.EventInvestigationToolCompleted, tool.Identity())
			if completed.Sequence() <= reconciliation.Sequence() {
				t.Fatal("tool completion preceded its actual model proposal")
			}
			next := captures[i+1].packet.Investigation
			if next.PreviousRequest != record.RequestIdentity() || next.PreviousOutcome != record.Outcome().Identity() || !slices.Equal(next.PreviousResults, toolIDs) {
				t.Fatal("successor request lost actual protected tool result")
			}
		} else if len(toolIDs) != 0 {
			t.Fatal("terminal generation/verifier invented tool work")
		}
	}
	if cost != 1000 || view.KnownCostMicroUSD() != cost {
		t.Fatal("known cumulative cost is not the sum of all five actual turns")
	}
}

func TestInvestigationPipelineSourceCompletionCannotGrantUnrecordedStage(t *testing.T) {
	for _, mode := range []string{"head-complete-refused", "head-complete-unknown"} {
		t.Run(mode, func(t *testing.T) {
			f := newBridgeFixture(t, mode)
			f.start()
			if err := f.runner.Run(f.ctx); !errors.Is(err, errBridgeInjected) {
				t.Fatalf("real completion fault not reached: %v", err)
			}
			requiredCheck(t, f.runner.Wait(f.ctx))
			completion := f.trace.completions["source-head"]
			if f.control.faults != 1 || completion.Status() != controlplane.TaskCompletionSucceeded {
				t.Fatal("fault did not follow actual successful source acquisition")
			}
			stored, err := f.underlying.Get(f.ctx, f.prepared.Plan().Scope(), completion.OutputIdentity(), f.clock.Now())
			requiredCheck(t, err)
			if stored.Kind() != artifact.KindSourceSnapshot {
				t.Fatal("actual acquired head was not stored")
			}
			_, before, err := f.coordinator.Resume(f.ctx, f.prepared.Plan().Scope())
			requiredCheck(t, err)
			head, _ := before.Task("source-head")
			if mode == "head-complete-refused" && head.Status() == controlplane.TaskRuntimeSucceeded {
				t.Fatal("pre-write refusal recorded head success")
			}
			if mode == "head-complete-unknown" && (head.Status() != controlplane.TaskRuntimeSucceeded || head.OutputIdentity() != stored.Identity()) {
				t.Fatal("committed-but-error control did not preserve actual journal commit")
			}
			for _, key := range []string{"context", "candidates", "verification", "readiness"} {
				if _, started := f.trace.requests[key]; started {
					t.Fatal("failed foreground completion advanced downstream")
				}
			}
			if len(f.models.snapshot()) != 0 {
				t.Fatal("stored acquisition alone started a model")
			}
			state := f.settle()
			if state.Status() == controlplane.ReviewRunSucceeded {
				t.Fatal("completion fault became successful terminal authority")
			}
			f.requireNoSuccessfulReadback()
		})
	}
}

func TestInvestigationPipelineContextCompletionGatesRealIntent(t *testing.T) {
	f := newBridgeFixture(t, "context-complete-refused")
	f.start()
	if err := f.runner.Run(f.ctx); !errors.Is(err, errBridgeInjected) {
		t.Fatalf("context completion fault not reached: %v", err)
	}
	requiredCheck(t, f.runner.Wait(f.ctx))
	completion := f.trace.completions["context"]
	if completion.Status() != controlplane.TaskCompletionSucceeded || f.control.faults != 1 {
		t.Fatal("context did not actually store/register its intent before the fault")
	}
	intent, err := f.underlying.Get(f.ctx, f.prepared.Plan().Scope(), completion.OutputIdentity(), f.clock.Now())
	requiredCheck(t, err)
	if !bridgeIsIntent(intent) {
		t.Fatal("context returned something other than the actual stored intent")
	}
	_, state, err := f.coordinator.Resume(f.ctx, f.prepared.Plan().Scope())
	requiredCheck(t, err)
	contextTask, _ := state.Task("context")
	if contextTask.Status() == controlplane.TaskRuntimeSucceeded {
		t.Fatal("stored intent manufactured journal success")
	}
	for _, key := range []string{"source-base", "source-head", "change", "analysis", "memory"} {
		f.output(state, key)
	}
	if _, ran := f.trace.requests["candidates"]; ran || len(f.models.snapshot()) != 0 {
		t.Fatal("uncompleted context reached controller/model work")
	}
	f.settle()
	f.requireNoSuccessfulReadback()
}

func TestInvestigationPipelineRejectsRehashedStoredIntent(t *testing.T) {
	f := newBridgeFixture(t, "rehashed-intent")
	f.start()
	requiredCheck(t, f.runner.Run(f.ctx))
	state := f.settle()
	f.output(state, "context")
	if f.store.injected == 0 || f.store.attempted.Identity() == f.store.substituted.Identity() || f.store.substituted.Validate() != nil {
		t.Fatal("real candidates task never received a validly rehashed wrong intent")
	}
	if _, ran := f.trace.requests["candidates"]; !ran {
		t.Fatal("wrong intent test stopped before its actual consumer")
	}
	candidates, _ := state.Task("candidates")
	if candidates.Status() != controlplane.TaskRuntimeFailed || state.Status() == controlplane.ReviewRunSucceeded || len(f.models.snapshot()) != 0 {
		t.Fatal("rehashed intent granted model authority")
	}
	f.requireNoSuccessfulReadback()
}

func (f *bridgeFixture) requireNoSuccessfulReadback() {
	f.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	view, err := f.bridge.ReadResult(ctx)
	if err == nil {
		_, generated := view.Generation()
		_, verified := view.Verification()
		if view.RunStatus() == controlplane.ReviewRunSucceeded || generated || verified {
			f.t.Fatal("failure exposed live successful generation/verification")
		}
	}
}

func TestInvestigationPipelineCancellationDrainsActualWork(t *testing.T) {
	for _, mode := range []string{"source-wait", "bootstrap-wait", "generation-wait", "verification-wait"} {
		t.Run(mode, func(t *testing.T) {
			f := newBridgeFixture(t, mode)
			f.start()
			done := make(chan error, 1)
			go func() { done <- f.runner.Run(f.ctx) }()
			select {
			case <-f.gate.entered:
			case err := <-done:
				t.Fatalf("actual wait not reached: %v", err)
			case <-time.After(10 * time.Second):
				t.Fatal("actual wait not reached")
			}
			f.cancel()
			select {
			case <-f.gate.canceled:
			case <-time.After(time.Second):
				t.Fatal("run cancellation did not reach actual external/source wait")
			}
			select {
			case err := <-done:
				if errors.Is(err, worker.ErrWorkerDrain) {
					t.Fatal("cooperative actual work did not drain")
				}
			case <-time.After(10 * time.Second):
				t.Fatal("canceled Runner did not return")
			}
			cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
			defer stop()
			requiredCheck(t, f.runner.Wait(cleanup))
			state := f.settle()
			if state.Status() == controlplane.ReviewRunSucceeded {
				t.Fatal("canceled run succeeded")
			}
			want := 0
			if mode == "generation-wait" {
				want = 2
			}
			if mode == "verification-wait" {
				want = 5
			}
			if len(f.models.snapshot()) != want {
				t.Fatal("cancellation repeated or skipped the actual triggering model call")
			}
			if _, ran := f.trace.requests["readiness"]; ran {
				t.Fatal("canceled work reached readiness")
			}
			if mode == "bootstrap-wait" {
				f.output(state, "context")
				if _, ran := f.trace.requests["candidates"]; !ran {
					t.Fatal("source wait was not reached in actual controller bootstrap")
				}
			}
			f.requireNoSuccessfulReadback()
			requiredCheck(t, f.bridge.Close(cleanup))
			if len(f.models.snapshot()) != want {
				t.Fatal("close replayed canceled model work")
			}
		})
	}
}

func TestInvestigationPipelineUncooperativeModelRetainsDrainOwnership(t *testing.T) {
	f := newBridgeFixture(t, "generation-uncooperative")
	f.start()
	done := make(chan error, 1)
	go func() { done <- f.runner.Run(f.ctx) }()
	select {
	case <-f.gate.entered:
	case err := <-done:
		t.Fatalf("uncooperative provider not reached: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("provider not reached")
	}
	f.cancel()
	select {
	case <-f.gate.canceled:
	case <-time.After(time.Second):
		t.Fatal("provider did not observe canceled work")
	}
	short, stop := context.WithTimeout(context.Background(), 50*time.Millisecond)
	if err := f.runner.Wait(short); !errors.Is(err, worker.ErrWorkerDrain) {
		t.Fatalf("Runner abandoned active external work: %v", err)
	}
	stop()
	short, stop = context.WithTimeout(context.Background(), 50*time.Millisecond)
	if err := f.bridge.Close(short); err == nil {
		t.Fatal("bridge claimed closure while actual external work remained")
	}
	stop()
	if len(f.models.snapshot()) != 2 {
		t.Fatal("uncooperative call granted another model stage")
	}
	f.gate.unblock()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("released external did not drain Runner")
	}
	cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	requiredCheck(t, f.runner.Wait(cleanup))
	f.settle()
	f.requireNoSuccessfulReadback()
	requiredCheck(t, f.bridge.Close(cleanup))
	if err := f.bridge.StartRun(cleanup, f.prepared.Plan()); err == nil {
		t.Fatal("closed blocked bridge admitted a new account")
	}
	if len(f.models.snapshot()) != 2 {
		t.Fatal("drain or second close repeated model effects")
	}
}

func TestInvestigationPipelineUnknownEffectsKeepPriorDiagnosticsWithoutReplay(t *testing.T) {
	for _, mode := range []string{"unknown-usage", "turn-put-refused", "turn-put-unknown"} {
		t.Run(mode, func(t *testing.T) {
			f := newBridgeFixture(t, mode)
			f.start()
			requiredCheck(t, f.runner.Run(f.ctx))
			state := f.settle()
			if state.Status() == controlplane.ReviewRunSucceeded || len(f.models.snapshot()) != 2 {
				t.Fatal("unknown effect failed to freeze the actual second turn")
			}
			for _, key := range []string{"source-base", "source-head", "change", "analysis", "memory", "context"} {
				f.output(state, key)
			}
			for _, key := range []string{"verification", "readiness"} {
				if _, ran := f.trace.requests[key]; ran {
					t.Fatal("unknown effect reached downstream verification/readiness")
				}
			}
			events := f.events()
			claims, toolCompletions := 0, 0
			for _, event := range events {
				if event.Kind() == audit.EventRouteAttemptClaimed {
					claims++
				}
				if event.Kind() == audit.EventInvestigationToolCompleted {
					toolCompletions++
				}
			}
			if claims != 2 || toolCompletions != 1 {
				t.Fatal("unknown effect erased prior diagnostics or repeated paid/tool work")
			}
			if mode != "unknown-usage" {
				if f.store.injected != 1 || f.store.attempted.Kind() != artifact.KindInvestigationTurn {
					t.Fatal("actual second turn retention fault not reached")
				}
				stored, err := f.underlying.Get(f.ctx, f.prepared.Plan().Scope(), f.store.attempted.Identity(), f.clock.Now())
				if mode == "turn-put-refused" && !errors.Is(err, artifact.ErrArtifactNotFound) {
					t.Fatal("pre-write control unexpectedly persisted a turn")
				}
				if mode == "turn-put-unknown" && (err != nil || stored.Identity() != f.store.attempted.Identity()) {
					t.Fatal("unknown Put control did not actually commit before its error")
				}
			}
			view, err := f.bridge.ReadResult(f.ctx)
			if err == nil {
				_, generated := view.Generation()
				_, verified := view.Verification()
				if view.UsageKnown() || generated || verified || view.RunStatus() == controlplane.ReviewRunSucceeded {
					t.Fatal("unrecorded/unknown turn became a known successful projection")
				}
			}
			if err := f.bridge.StartRun(f.ctx, f.prepared.Plan()); err == nil {
				t.Fatal("frozen bridge acquired a second account")
			}
			if len(f.models.snapshot()) != 2 || len(f.events()) != len(events) {
				t.Fatal("failed readback/restart repeated actual effects")
			}
		})
	}
}
