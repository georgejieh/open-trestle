package runtimecatalog_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	analysishandler "github.com/georgejieh/open-trestle/handlers/analysis"
	changehandler "github.com/georgejieh/open-trestle/handlers/change"
	modelhandler "github.com/georgejieh/open-trestle/handlers/model"
	sourcehandler "github.com/georgejieh/open-trestle/handlers/source"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/policy"
	"github.com/georgejieh/open-trestle/internal/review"
)

func TestRequiredPipelineCompletesProtectedIndependentReview(t *testing.T) {
	f := newRequiredPipeline(t, true, false)
	state := f.run()
	if state.Status() != controlplane.ReviewRunSucceeded {
		for _, task := range f.plan.Tasks() {
			if completion, ok := f.completions[task.Key()]; ok && completion.Status() != controlplane.TaskCompletionSucceeded {
				t.Errorf("handler %s failed: %s", task.Key(), completion.Failure())
			}
		}
		t.Fatalf("required pipeline status=%s failure=%s completions=%d", state.Status(), state.Failure(), len(f.completions))
	}
	for _, task := range f.plan.Tasks() {
		if !task.Required() {
			t.Fatalf("task %s was optional", task.Key())
		}
		f.output(state, task.Key())
		runtime, _ := state.Task(task.Key())
		completion, ok := f.completions[task.Key()]
		if !ok || runtime.Attempts() != 1 || completion.Status() != controlplane.TaskCompletionSucceeded || runtime.OutputIdentity() != completion.OutputIdentity() {
			t.Fatalf("task %s lacks its single accepted handler completion", task.Key())
		}
	}
	if f.source.calls != 2 || f.generation.calls != 1 || f.verification.calls != 1 || f.publisher.calls != 1 || f.publisher.headCalls != 1 {
		t.Fatalf("external calls source=%d generation=%d verification=%d publication=%d head=%d", f.source.calls, f.generation.calls, f.verification.calls, f.publisher.calls, f.publisher.headCalls)
	}
	f.assertLineage(state)
	f.assertReplay(state)
	f.assertDuplicateEffectsRefused()
}

func (f *requiredPipeline) assertLineage(state controlplane.ReviewRunState) {
	f.t.Helper()
	t := f.t
	ctx := context.Background()
	inputArtifact := f.output(state, "context")
	input, err := modelhandler.ParseGenerationInput(inputArtifact.Payload())
	requiredCheck(t, err)
	contextArtifact, err := f.store.Get(ctx, f.plan.Scope(), input.ContextArtifactIdentity(), f.clock.Now())
	requiredCheck(t, err)
	requiredCheck(t, review.ValidateContextPacketRequest(contextArtifact.Payload(), input.ContextIdentity(), f.plan.Scope().Identity(), input.MemoryScopeIdentity(), input.MemoryIdentity(), input.Snapshot(), input.EvidenceItems()))
	generationArtifact := f.output(state, "candidates")
	generation, err := modelhandler.ParseGenerationResultArtifact(generationArtifact, inputArtifact, contextArtifact)
	requiredCheck(t, err)
	verificationArtifact := f.output(state, "verification")
	verification, err := modelhandler.ParseVerificationResultArtifact(verificationArtifact, generationArtifact, inputArtifact, contextArtifact)
	requiredCheck(t, err)
	if generationArtifact.Kind() != artifact.KindCandidateBatch || verificationArtifact.Kind() != artifact.KindVerifiedFindingSet || len(generation.Candidates().Findings()) != 1 || len(verification.VerifiedFindings().Findings()) != 1 || verification.IndependentReceipt().VerifiedCount() != 1 || verification.RouteIndependence().Level() != gateway.RouteIndependenceDistinctProvider {
		t.Fatal("actual artifacts did not contain one independently verified finding")
	}
	candidate := generation.Candidates().Findings()[0]
	if f.verification.candidate != candidate.Identity() || candidate.SourceRange().Path() != "a.go" || candidate.SourceRange().StartLine() != 2 || candidate.SourceRange().EndLine() != 2 || len(candidate.EvidenceIDs()) != 2 {
		t.Fatal("verification candidate or finding position lost generation lineage")
	}
	generationAuthorization := generation.RouteExecution().Authorization()
	verificationAuthorization := verification.RouteExecution().Authorization()
	requiredCheck(t, gateway.VerifyIndependentRouteAuthorizations(f.configuration.Independence(), generationAuthorization, verificationAuthorization))
	pin, pinned := f.configuration.Ranking().PinnedRoute()
	if !pinned || pin != generationAuthorization.RouteReference() || pin == verificationAuthorization.RouteReference() || generationAuthorization.RouteReference().ProviderID() != "provider-a" || verificationAuthorization.RouteReference().ProviderID() != "provider-b" || generationAuthorization.Identity() != f.generation.request.Authorization().Identity() || verificationAuthorization.Identity() != f.verification.request.Authorization().Identity() || generationAuthorization.RequestIdentity() == verificationAuthorization.RequestIdentity() {
		t.Fatal("generation pin or independent verifier request authority was lost")
	}
	if generation.RouteExecution().Output().ArtifactIdentity() != generation.Candidates().Identity() || generation.RouteExecution().Output().ContextIdentity() != input.ContextIdentity() || verification.RouteExecution().Output().ArtifactIdentity() != verification.Verification().Identity() || verification.RouteExecution().Output().ContextIdentity() != verification.VerificationContext().Identity() {
		t.Fatal("route output receipts lost candidate or verification context lineage")
	}
	baseArtifact := f.output(state, "source-base")
	headArtifact := f.output(state, "source-head")
	changeArtifact := f.output(state, "change")
	analysisArtifact := f.output(state, "analysis")
	change, err := changehandler.ParseResultArtifact(changeArtifact, baseArtifact, headArtifact)
	requiredCheck(t, err)
	analysis, err := analysishandler.ParseResultArtifact(analysisArtifact, changeArtifact, baseArtifact, headArtifact)
	requiredCheck(t, err)
	head, err := sourcehandler.ParseSnapshotArtifact(headArtifact)
	requiredCheck(t, err)
	if len(analysis.Items()) != 1 || len(input.EvidenceItems()) != 2 {
		t.Fatal("fixture did not retain changed and semantic evidence")
	}
	semanticMember := false
	for _, reference := range analysis.SemanticImpact().References() {
		if reference.Path() == "caller.go" && reference.Line() == 2 {
			semanticMember = true
		}
	}
	if !semanticMember {
		t.Fatal("unchanged caller lacks actual semantic membership")
	}
	bindings := make([]string, 0, len(input.EvidenceItems()))
	for _, item := range input.EvidenceItems() {
		found := false
		for _, reference := range head.Files() {
			if reference.Path() != item.SourceRange().Path() {
				continue
			}
			value, err := f.store.Get(ctx, f.plan.Scope(), reference.ArtifactIdentity(), f.clock.Now())
			requiredCheck(t, err)
			file, err := sourcehandler.ParseFileArtifact(value, head, reference)
			requiredCheck(t, err)
			repositoryFile, err := evidence.NewRepositoryFile(file.Path(), file.Content())
			requiredCheck(t, err)
			binding, err := evidence.BindSourceRange(repositoryFile, file.Content(), item.SourceRange())
			requiredCheck(t, err)
			if binding.SliceDigest() != item.Digest() {
				t.Fatal("context evidence differs from acquired head bytes")
			}
			if item.SourceRange().Path() == "caller.go" && (binding.Identity() != item.ID() || item.SourceRange().StartLine() != 2 || item.SourceRange().EndLine() != 2) {
				t.Fatal("semantic evidence is not the exact selected source slice")
			}
			if item.SourceRange().Path() == "a.go" && (analysis.Items()[0].EvidenceID() != item.ID() || analysis.Items()[0].BindingIdentity() != binding.Identity()) {
				t.Fatal("changed evidence is not bound to actual deterministic analysis")
			}
			bindings = append(bindings, binding.Identity())
			found = true
		}
		if !found {
			t.Fatal("context evidence has no protected source file")
		}
	}
	protected, err := review.NewProtectedSourceBinding(f.plan.Scope(), change.Repository(), change.HeadRevision(), headArtifact.Identity(), head.Identity(), head.ManifestIdentity(), changeArtifact.Identity(), change.Identity(), analysisArtifact.Identity(), contextArtifact.Identity(), input.ContextIdentity(), input.Snapshot().Identity(), bindings)
	requiredCheck(t, err)
	readiness, err := review.EvaluatePublicationReadiness(f.configuration.Publication(), verification.IndependentReceipt(), verification.VerifiedFindings())
	requiredCheck(t, err)
	if readiness.Status() != review.PublicationAdvisoryReady || len(readiness.InlineFindings()) != 1 {
		t.Fatal("actual verified findings were not publication-ready")
	}
	publicationPlan := f.publisher.request.Authorization().Plan()
	if publicationPlan.ReadinessIdentity() != readiness.Identity() || publicationPlan.SourceSnapshotBindingIdentity() != protected.SourceIdentity() || publicationPlan.AcquiredContextBindingIdentity() != protected.ContextBindingIdentity() || publicationPlan.GenerationContextIdentity() != input.ContextIdentity() || publicationPlan.InlineFindings()[0].Identity() != verification.VerifiedFindings().Findings()[0].Identity() {
		t.Fatal("publisher request lost protected source, readiness, or finding lineage")
	}
	effect := f.publisher.request.Authorization().EffectAuthorization()
	if effect.Reason() != policy.AuthorizationRepositoryPolicy || effect.PolicyIdentity() != f.configuration.ReviewPolicyIdentity() || effect.PrincipalIdentity() != requiredDigest("repository-publication-operator") || !effect.Allows(policy.CapabilityPublication, f.plan.Scope().Identity(), f.clock.Now()) {
		t.Fatal("publication bypassed the legitimate repository policy authority")
	}
	readinessArtifact := f.output(state, "readiness")
	var readinessWire struct {
		Readiness    string `json:"readiness_identity"`
		Verification string `json:"verification_artifact_identity"`
	}
	requiredCheck(t, json.Unmarshal(readinessArtifact.Payload(), &readinessWire))
	if readinessArtifact.Kind() != artifact.KindPublicationPlan || readinessWire.Readiness != readiness.Identity() || readinessWire.Verification != verificationArtifact.Identity() {
		t.Fatal("readiness task did not preserve the actual verification artifact")
	}
	receiptArtifact := f.output(state, "publication")
	var receipt struct {
		Contract      string `json:"contract"`
		Version       int    `json:"schema_version"`
		Status        string `json:"status"`
		Readiness     string `json:"readiness_identity"`
		Source        string `json:"source_binding_identity"`
		Plan          string `json:"plan_identity"`
		Authorization string `json:"authorization_identity"`
		Claim         string `json:"claim_identity"`
		Attempt       string `json:"attempt_identity"`
		Head          string `json:"head_reconciliation_identity"`
		Result        string `json:"result_identity"`
		External      string `json:"external_reference_identity"`
	}
	requiredCheck(t, json.Unmarshal(receiptArtifact.Payload(), &receipt))
	request := f.publisher.request
	if receiptArtifact.Kind() != artifact.KindPublicationReceipt || state.OutputIdentity() != receiptArtifact.Identity() || receipt.Contract != "open-trestle/publication-receipt" || receipt.Version != 1 || receipt.Status != "published" || receipt.Readiness != readiness.Identity() || receipt.Source != protected.Identity() || receipt.Plan != publicationPlan.Identity() || receipt.Authorization != request.Authorization().Identity() || receipt.Claim != request.Claim().Identity() || receipt.Attempt != request.Attempt().Identity() || receipt.Head != request.HeadGate().Reconciliation().Identity() || receipt.Result == "" || receipt.External != requiredDigest(requiredExternalReference) {
		t.Fatal("terminal publication receipt lost its bound effect lineage")
	}
	for _, id := range []string{readinessArtifact.Identity(), f.requests["publication"].Task().InputIdentity(), receipt.Readiness, receipt.Source, receipt.Plan, receipt.Authorization, receipt.Claim, receipt.Attempt, receipt.Head, receipt.Result} {
		if !slices.Contains(receiptArtifact.Provenance(), id) {
			t.Fatal("publication receipt omitted a causal provenance identity")
		}
	}
	events := f.events()
	if len(events) != 15 {
		t.Fatalf("audit events=%d, want two four-event model attempts and seven publication events", len(events))
	}
	verifierRanking, err := gateway.NewRouteRankingPolicy(f.configuration.Ranking().PreferredRoutes())
	requiredCheck(t, err)
	generationSelection := requiredEvent(t, events, audit.EventRouteSelected, generationAuthorization.SelectionReceiptIdentity())
	verifierSelection := requiredEvent(t, events, audit.EventRouteSelected, verificationAuthorization.SelectionReceiptIdentity())
	if !slices.Contains(generationSelection.CausalParentIdentities(), f.configuration.Ranking().Identity()) || !slices.Contains(verifierSelection.CausalParentIdentities(), verifierRanking.Identity()) || slices.Contains(verifierSelection.CausalParentIdentities(), f.configuration.Ranking().Identity()) {
		t.Fatal("verifier ranking was not derived independently without the generation pin")
	}
	for _, execution := range []gateway.RouteExecutionRecord{generation.RouteExecution(), verification.RouteExecution()} {
		selection := requiredEvent(t, events, audit.EventRouteSelected, execution.Authorization().SelectionReceiptIdentity())
		claim := requiredEvent(t, events, audit.EventRouteAttemptClaimed, execution.Authorization().Identity())
		completed := requiredEvent(t, events, audit.EventRouteDispatchCompleted, execution.Outcome().Identity())
		cost := requiredEvent(t, events, audit.EventRouteCostReconciled, execution.Reconciliation().Identity())
		if selection.Sequence() >= claim.Sequence() || claim.Sequence() >= completed.Sequence() || completed.Sequence() >= cost.Sequence() || !slices.Contains(completed.CausalParentIdentities(), execution.Authorization().Identity()) || !slices.Contains(cost.CausalParentIdentities(), execution.Outcome().Identity()) {
			t.Fatal("model attempt did not traverse selection, claim, and completion")
		}
	}
	sourceEvent := requiredEvent(t, events, audit.EventReviewSnapshotBound, protected.SourceIdentity())
	contextEvent := requiredEvent(t, events, audit.EventContextAcquisitionBound, protected.ContextBindingIdentity())
	readyEvent := requiredEvent(t, events, audit.EventPublicationReadinessEvaluated, readiness.Identity())
	authorized := requiredEvent(t, events, audit.EventPublicationAuthorized, receipt.Authorization)
	claimed := requiredEvent(t, events, audit.EventPublicationClaimed, receipt.Authorization)
	headEvent := requiredEvent(t, events, audit.EventPublicationHeadReconciled, receipt.Head)
	completed := requiredEvent(t, events, audit.EventPublicationCompleted, receipt.Result)
	if !(sourceEvent.Sequence() < contextEvent.Sequence() && contextEvent.Sequence() < readyEvent.Sequence() && readyEvent.Sequence() < authorized.Sequence() && authorized.Sequence() < claimed.Sequence() && claimed.Sequence() < headEvent.Sequence() && headEvent.Sequence() < completed.Sequence()) {
		t.Fatal("publication prerequisites were not emitted in causal order")
	}
	if !slices.Contains(authorized.CausalParentIdentities(), effect.Identity()) || !slices.Contains(contextEvent.CausalParentIdentities(), input.ContextIdentity()) || !slices.Contains(completed.CausalParentIdentities(), receipt.External) || !slices.Contains(completed.CausalParentIdentities(), receipt.Claim) || !slices.Contains(completed.CausalParentIdentities(), receipt.Attempt) || !slices.Contains(completed.CausalParentIdentities(), headEvent.Identity()) {
		t.Fatal("publication audit omitted authorization, head, or receipt lineage")
	}
}

func (f *requiredPipeline) events() []audit.Event {
	f.t.Helper()
	events, err := f.ledger.Read(context.Background(), f.plan.Scope(), 0, 100)
	requiredCheck(f.t, err)
	previous := ""
	for index, event := range events {
		requiredCheck(f.t, event.Validate())
		if event.Scope().Identity() != f.plan.Scope().Identity() || event.Sequence() != uint64(index+1) || event.PreviousIdentity() != previous {
			f.t.Fatal("shared audit chain lost scope or sequence")
		}
		previous = event.Identity()
	}
	return events
}

func requiredEvent(t *testing.T, events []audit.Event, kind audit.EventKind, subject string) audit.Event {
	t.Helper()
	var found audit.Event
	for _, event := range events {
		if event.Kind() == kind && event.SubjectIdentity() == subject {
			if found.Identity() != "" {
				t.Fatalf("duplicate %s event", kind)
			}
			found = event
		}
	}
	if found.Identity() == "" {
		t.Fatalf("missing %s event for actual artifact lineage", kind)
	}
	return found
}

func (f *requiredPipeline) assertReplay(original controlplane.ReviewRunState) {
	f.t.Helper()
	ctx := context.Background()
	before := len(f.events())
	calls := [5]int{f.source.calls, f.generation.calls, f.verification.calls, f.publisher.calls, f.publisher.headCalls}
	restarted, err := controlplane.NewCoordinator(f.journal)
	requiredCheck(f.t, err)
	plan, state, err := restarted.Resume(ctx, f.plan.Scope())
	requiredCheck(f.t, err)
	if plan.Identity() != f.plan.Identity() || state.Status() != original.Status() || state.HeadIdentity() != original.HeadIdentity() || state.Revision() != original.Revision() || state.OutputIdentity() != original.OutputIdentity() || state.Failure() != original.Failure() {
		f.t.Fatal("journal replay changed terminal disposition")
	}
	for _, task := range plan.Tasks() {
		oldTask, _ := original.Task(task.Key())
		newTask, _ := state.Task(task.Key())
		if newTask.Status() != oldTask.Status() || newTask.Attempts() != oldTask.Attempts() || newTask.OutputIdentity() != oldTask.OutputIdentity() {
			f.t.Fatalf("journal replay changed task %s", task.Key())
		}
		_, acquired, err := restarted.ClaimTask(ctx, plan, task.Key(), task.HandlerIdentity(), "restarted-worker", f.clock.step())
		if acquired || !errors.Is(err, controlplane.ErrRunAlreadyTerminal) {
			f.t.Fatalf("terminal task %s was claimable: %v", task.Key(), err)
		}
	}
	finalizer, err := controlplane.NewRunFinalizer(f.journal)
	requiredCheck(f.t, err)
	replayed, changed, err := finalizer.ReconcileRun(ctx, plan.Scope(), f.clock.step())
	requiredCheck(f.t, err)
	if changed || replayed.HeadIdentity() != original.HeadIdentity() || len(f.events()) != before || calls != [5]int{f.source.calls, f.generation.calls, f.verification.calls, f.publisher.calls, f.publisher.headCalls} {
		f.t.Fatal("terminal reconciliation added work, external calls, or audit events")
	}
}

func (f *requiredPipeline) assertDuplicateEffectsRefused() {
	f.t.Helper()
	generationCalls, verificationCalls := f.generation.calls, f.verification.calls
	publicationCalls, headCalls, sourceCalls := f.publisher.calls, f.publisher.headCalls, f.source.calls
	for _, key := range []string{"candidates", "verification", "publication"} {
		request, executed := f.requests[key]
		if !executed {
			continue
		}
		handler, ok := f.catalog.Catalog().Resolve(request.Task().HandlerIdentity())
		if !ok {
			f.t.Fatal("executed handler missing from catalog")
		}
		completion := handler.Execute(context.Background(), request)
		requiredCheck(f.t, completion.Validate())
		if completion.Status() != controlplane.TaskCompletionFailed {
			f.t.Fatalf("duplicate %s execution was not refused", key)
		}
	}
	if f.generation.calls != generationCalls || f.verification.calls != verificationCalls || f.publisher.calls != publicationCalls || f.publisher.headCalls != headCalls || f.source.calls != sourceCalls {
		f.t.Fatal("duplicate execution repeated an external call")
	}
}

func TestRequiredPipelineRejectsStaleHead(t *testing.T) {
	f := newRequiredPipeline(t, true, true)
	state := f.run()
	if state.Status() != controlplane.ReviewRunFailed || state.Failure() != controlplane.RunFailureInvalidInput {
		t.Fatalf("stale-head run status=%s failure=%s", state.Status(), state.Failure())
	}
	for _, key := range []string{"source-base", "source-head", "change", "analysis", "memory", "context", "candidates", "verification", "readiness"} {
		f.output(state, key)
	}
	publication, _ := state.Task("publication")
	if publication.Status() != controlplane.TaskRuntimeFailed || publication.OutputIdentity() != "" || f.publisher.calls != 0 || f.publisher.headCalls != 1 || f.generation.calls != 1 || f.verification.calls != 1 {
		t.Fatal("stale head did not stop publication after actual readiness")
	}
	heads := 0
	for _, event := range f.events() {
		if event.Kind() == audit.EventPublicationCompleted {
			t.Fatal("stale head produced a publication completion")
		}
		if event.Kind() == audit.EventPublicationHeadReconciled {
			heads++
		}
	}
	if heads != 1 {
		t.Fatal("stale-head refusal was not audited")
	}
	f.assertReplay(state)
	f.assertDuplicateEffectsRefused()
}

func TestRequiredPipelineRejectsNoIndependentApprovedVerifier(t *testing.T) {
	f := newRequiredPipeline(t, false, false)
	state := f.run()
	if state.Status() != controlplane.ReviewRunFailed || state.Failure() != controlplane.RunFailurePolicy {
		t.Fatalf("unapproved-verifier run status=%s failure=%s", state.Status(), state.Failure())
	}
	for _, key := range []string{"source-base", "source-head", "change", "analysis", "memory", "context", "candidates"} {
		f.output(state, key)
	}
	verification, _ := state.Task("verification")
	publication, _ := state.Task("publication")
	if verification.Status() != controlplane.TaskRuntimeFailed || verification.Failure() != controlplane.RunFailurePolicy || publication.Attempts() != 0 || publication.OutputIdentity() != "" || f.generation.calls != 1 || f.verification.calls != 0 || f.publisher.calls != 0 || f.publisher.headCalls != 0 {
		t.Fatal("missing independent approved route did not fail closed")
	}
	events := f.events()
	if len(events) != 4 {
		t.Fatalf("unapproved verifier emitted downstream authority: events=%d", len(events))
	}
	for _, event := range events {
		switch event.Kind() {
		case audit.EventRouteSelected, audit.EventRouteAttemptClaimed, audit.EventRouteDispatchCompleted, audit.EventRouteCostReconciled:
		default:
			t.Fatalf("unauthorized downstream event %s", event.Kind())
		}
	}
	f.assertReplay(state)
	f.assertDuplicateEffectsRefused()
}
