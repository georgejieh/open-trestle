package localreview

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/diagnostics"
	modelhandler "github.com/georgejieh/open-trestle/handlers/model"
	sourcehandler "github.com/georgejieh/open-trestle/handlers/source"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/runtimecatalog"
	"github.com/georgejieh/open-trestle/worker"
)

type investigationSession struct {
	profile       modelhandler.InvestigationPipelineProfile
	configuration runtimecatalog.InvestigationCatalogOptions
	prototype     *modelhandler.InvestigationPipeline
}

// NewInvestigationSession transfers root ownership only after inert construction succeeds.
func NewInvestigationSession(options SessionOptions, policy review.InvestigationPolicy) (*Session, error) {
	return newSession(options, &policy)
}

func validateInvestigationSessionPolicy(o SessionOptions, policy review.InvestigationPolicy) error {
	if o.Policy.ValidateAgainstInventory(o.Inventory) != nil || policy.Validate() != nil || policy.ValidateRuntimeBudget(o.Policy.Budget()) != nil || o.Policy.Budget().MaxOutputTokens() < o.Policy.Requirements().MinOutputTokens() {
		return ErrInvalidSession
	}
	pin, ok := o.Policy.Ranking().PinnedRoute()
	if !ok {
		return ErrInvalidSession
	}
	var generation, verification []gateway.ObservedRouteCandidate
	var generationObservations, verificationObservations []provider.RoutePerformanceObservation
	for _, candidate := range o.Inventory.Candidates() {
		record := candidate.ResolvedRecord().RouteRegistryRecord()
		isGeneration := record.RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference() == pin
		if isGeneration {
			generation = append(generation, candidate)
		} else {
			verification = append(verification, candidate)
		}
		for _, observation := range o.Inventory.PerformanceObservations() {
			if observation.RecordIdentity() == record.Identity() {
				if isGeneration {
					generationObservations = append(generationObservations, observation)
				} else {
					verificationObservations = append(verificationObservations, observation)
				}
			}
		}
	}
	if len(generation) != 1 || len(verification) == 0 {
		return ErrInvalidSession
	}
	generationRanking, err := gateway.NewPinnedRouteRankingPolicy(pin, nil)
	if err != nil {
		return ErrInvalidSession
	}
	verificationRanking, err := gateway.NewRouteRankingPolicy(o.Policy.Ranking().PreferredRoutes())
	if err != nil {
		return ErrInvalidSession
	}
	if _, err := gateway.NewInvestigationRoutePlan(o.Inventory.RegistryRevision(), generation, generationRanking, o.Inventory.PerformanceRevision(), generationObservations); err != nil {
		return ErrInvalidSession
	}
	if _, err := gateway.NewInvestigationRoutePlan(o.Inventory.RegistryRevision(), verification, verificationRanking, o.Inventory.PerformanceRevision(), verificationObservations); err != nil {
		return ErrInvalidSession
	}
	return nil
}

func (s *Session) readFailedInvestigationRun(prepared runtimecatalog.PreparedReviewRun, canceled bool) (Result, error) {
	cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	plan, state, err := s.coordinator.Resume(cleanup, prepared.Plan().Scope())
	if err == nil && plan.Identity() == prepared.Plan().Identity() {
		if state.Status() == controlplane.ReviewRunActive {
			state, err = s.coordinator.CancelRun(cleanup, prepared.Plan(), s.options.Clock.Now())
		}
		if err == nil {
			result, readErr := s.readResult(cleanup, prepared, state)
			if readErr == nil {
				result.wire.Status, result.wire.CI = "failed", "error"
				return result, nil
			}
			return Result{}, readErr
		}
	}
	result := s.unstarted(prepared, "failed")
	if canceled {
		result = s.unstarted(prepared, "canceled")
	}
	if !errors.Is(err, controlplane.ErrRunNotOpened) {
		result.wire.RunStatus = "unknown"
		result.wire.Limitations = append(result.wire.Limitations, "execution_state_unavailable", "unknown_final_usage")
	}
	return result, nil
}

func (s *Session) newInvestigationRuntime(prepared runtimecatalog.PreparedReviewRun) (runtimecatalog.PipelineCatalog, error) {
	catalog, runtime, err := runtimecatalog.NewInvestigationPipelineCatalog(s.investigation.profile, s.investigation.configuration)
	if err != nil {
		return runtimecatalog.PipelineCatalog{}, ErrInvalidSession
	}
	s.mu.Lock()
	s.activeInvestigation = runtime
	s.mu.Unlock()
	if catalog.Validate() != nil || catalog.Identity() != s.catalog.Identity() || catalog.Mode() != prepared.Plan().Mode() {
		return runtimecatalog.PipelineCatalog{}, ErrPreparedReviewMismatch
	}
	bindings := catalog.Bindings()
	if len(bindings) != len(s.catalog.Bindings()) || prepared.Plan().TaskCount() != 9 {
		return runtimecatalog.PipelineCatalog{}, ErrPreparedReviewMismatch
	}
	for index, binding := range bindings {
		if binding != s.catalog.Bindings()[index] {
			return runtimecatalog.PipelineCatalog{}, ErrPreparedReviewMismatch
		}
	}
	for _, task := range prepared.Plan().Tasks() {
		handler, ok := catalog.Catalog().Resolve(task.HandlerIdentity())
		if !ok || handler.Kind() != task.Kind() {
			return runtimecatalog.PipelineCatalog{}, ErrPreparedReviewMismatch
		}
	}
	return catalog, nil
}

func (s *Session) retainInvestigationDiagnostics(ctx context.Context, prepared runtimecatalog.PreparedReviewRun, result *Result) {
	set, err := s.diagnostics.GetDiagnosticSet(ctx, prepared.Plan().Scope())
	if errors.Is(err, diagnostics.ErrSetNotFound) {
		return
	}
	inputs := prepared.Inputs()
	if err != nil || set.Validate() != nil || set.Scope().Identity() != prepared.Plan().Scope().Identity() || len(inputs) != 2 {
		result.wire.Limitations = append(result.wire.Limitations, "diagnostics_unavailable")
		return
	}
	head, err := sourcehandler.ParseInput(inputs[1].Payload())
	if err != nil || set.HeadRevision() != head.Revision().Digest() {
		result.wire.Limitations = append(result.wire.Limitations, "diagnostics_unavailable")
		return
	}
	encoded, err := diagnostics.EncodeSet(set)
	if err != nil {
		result.wire.Limitations = append(result.wire.Limitations, "diagnostics_unavailable")
		return
	}
	result.wire.Diagnostics = encoded
	result.diagnostics = set
	result.diagnosticOnly = true
	result.wire.Limitations = append(result.wire.Limitations, "diagnostics_not_terminal_success")
}

func fitInvestigationDiagnostics(result Result) Result {
	if !result.diagnosticOnly {
		return result
	}
	_, jsonErr := EncodeResult(result)
	var text bytes.Buffer
	textErr := RenderResult(&text, result)
	if jsonErr != nil || textErr != nil {
		result.wire.Diagnostics = []byte("null")
		result.diagnostics = diagnostics.Set{}
		result.diagnosticOnly = false
		result.wire.Limitations = append(append([]string{}, result.wire.Limitations...), "diagnostics_omitted_output_limit")
	}
	return result
}

func sealInvestigationResult(result Result) (Result, error) {
	result = fitInvestigationDiagnostics(result)
	encoded, err := EncodeResult(result)
	if err != nil {
		return Result{}, err
	}
	var text bytes.Buffer
	if err := RenderResult(&text, result); err != nil {
		return Result{}, err
	}
	result.sealedJSON = encoded
	result.sealedText = append([]byte(nil), text.Bytes()...)
	return result, nil
}

func (s *Session) rememberInvestigationResult(result Result) {
	result.wire.Limitations = append([]string{}, result.wire.Limitations...)
	result.wire.CandidateIDs = append([]string{}, result.wire.CandidateIDs...)
	result.wire.Tasks = append([]taskResult{}, result.wire.Tasks...)
	result.wire.Audit = append([]auditResult{}, result.wire.Audit...)
	result.wire.Diagnostics = append([]byte(nil), result.wire.Diagnostics...)
	if result.wire.Investigation != nil {
		wire := *result.wire.Investigation
		wire.Turns = append([]investigationTurnWire{}, wire.Turns...)
		for index := range wire.Turns {
			wire.Turns[index].ToolResults = append([]string{}, wire.Turns[index].ToolResults...)
		}
		result.wire.Investigation = &wire
	}
	s.mu.Lock()
	s.lastInvestigationResult = result
	s.mu.Unlock()
}

func (s *Session) finishInvestigationRun(result *Result, resultErr *error) {
	if result.valid {
		sealed, err := sealInvestigationResult(*result)
		if err != nil {
			*resultErr = err
		} else {
			*result = sealed
			s.rememberInvestigationResult(sealed)
		}
	}
	s.mu.Lock()
	runtime, runner, blocked := s.activeInvestigation, s.runner, s.blocked
	s.mu.Unlock()
	if runtime == nil || blocked {
		return
	}
	cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if runner != nil {
		if err := runner.Wait(cleanup); err != nil {
			s.mu.Lock()
			s.blocked = true
			s.mu.Unlock()
			*resultErr = worker.ErrWorkerDrain
			return
		}
	}
	if err := runtime.Close(cleanup); err != nil {
		s.mu.Lock()
		s.blocked = true
		s.mu.Unlock()
		*resultErr = worker.ErrWorkerDrain
		return
	}
	s.mu.Lock()
	s.activeInvestigation = nil
	s.runner = nil
	s.mu.Unlock()
}

func (s *Session) closeInvestigationResources(ctx context.Context) error {
	if s.investigation == nil {
		return nil
	}
	s.mu.Lock()
	runtime, prototype := s.activeInvestigation, s.investigation.prototype
	s.mu.Unlock()
	if runtime != nil {
		if err := runtime.Close(ctx); err != nil {
			return worker.ErrWorkerDrain
		}
	}
	if prototype != nil {
		if err := prototype.Close(ctx); err != nil {
			return worker.ErrWorkerDrain
		}
	}
	s.mu.Lock()
	s.activeInvestigation = nil
	s.investigation.prototype = nil
	s.runner = nil
	s.mu.Unlock()
	return nil
}

type investigationTurnWire struct {
	Identity           string   `json:"identity"`
	Artifact           string   `json:"artifact_identity"`
	Previous           string   `json:"previous_turn_identity"`
	Request            string   `json:"request_identity"`
	Authorization      string   `json:"authorization_identity"`
	Outcome            string   `json:"outcome_identity"`
	Reconciliation     string   `json:"reconciliation_identity"`
	Route              string   `json:"route_record_identity"`
	ActualCostMicroUSD uint64   `json:"actual_cost_micro_usd"`
	ToolResults        []string `json:"tool_result_identities"`
}

type investigationResultWire struct {
	Profile           string                  `json:"profile_identity"`
	Policy            string                  `json:"policy_identity"`
	ContextIntent     string                  `json:"context_intent_artifact_identity"`
	InitialContext    string                  `json:"initial_context_artifact_identity"`
	GenerationInput   string                  `json:"generation_input_artifact_identity"`
	FinalContext      string                  `json:"final_context_artifact_identity"`
	SourceHeadTask    string                  `json:"source_head_task_identity"`
	HeadSnapshot      string                  `json:"head_snapshot_artifact_identity"`
	Turns             []investigationTurnWire `json:"turns"`
	ToolCalls         uint8                   `json:"tool_calls"`
	ScannedBytes      uint64                  `json:"scanned_bytes"`
	ReturnedBytes     uint64                  `json:"returned_bytes"`
	KnownCostMicroUSD uint64                  `json:"known_cost_micro_usd"`
}

func (s *Session) projectInvestigation(result *Result, prepared runtimecatalog.PreparedReviewRun, state controlplane.ReviewRunState, view modelhandler.InvestigationPipelineReadback, events []audit.Event) error {
	w := &result.wire
	wire := w.Investigation
	policy := s.investigation.profile.Policy()
	wire.ContextIntent = view.ContextIntentArtifact().Identity()
	wire.InitialContext = view.InitialContextArtifact().Identity()
	wire.SourceHeadTask = view.SourceHeadTaskIdentity()
	wire.HeadSnapshot = view.HeadSnapshotArtifactIdentity()
	wire.ToolCalls, wire.ScannedBytes, wire.ReturnedBytes = view.ToolCalls(), view.ScannedBytes(), view.ReturnedBytes()
	wire.KnownCostMicroUSD = view.KnownCostMicroUSD()
	turns := view.Turns()
	if uint64(len(turns)) > policy.MaxModelTurns() || uint64(wire.ToolCalls) > policy.MaxToolCalls() || wire.ScannedBytes > policy.MaxScannedBytes() || wire.ReturnedBytes > policy.MaxReturnedBytes() {
		return ErrInvalidResult
	}
	claimed, completed, reconciled := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, event := range events {
		var subjects map[string]bool
		switch event.Kind() {
		case audit.EventRouteAttemptClaimed:
			subjects = claimed
		case audit.EventRouteDispatchCompleted:
			subjects = completed
		case audit.EventRouteCostReconciled:
			subjects = reconciled
		}
		if subjects != nil {
			if subjects[event.SubjectIdentity()] {
				return ErrInvalidResult
			}
			subjects[event.SubjectIdentity()] = true
		}
	}
	requests, toolResults := map[string]bool{}, map[string]bool{}
	previous, knownCost := "", uint64(0)
	for _, turn := range turns {
		record, value := turn.Record(), turn.Artifact()
		if record.Validate() != nil || value.Validate() != nil || value.Kind() != artifact.KindInvestigationTurn || value.Scope().Identity() != w.Scope || value.Protection() != artifact.ProtectionProcessPrivate || value.Classification() != s.classification || record.Authorization().ReviewScopeIdentity() != w.Scope || record.PreviousTurnIdentity() != previous || requests[record.RequestIdentity()] {
			return ErrInvalidResult
		}
		authorization, outcome, reconciliation := record.Authorization().Identity(), record.Outcome().Identity(), record.Reconciliation().Identity()
		if !claimed[authorization] || !completed[outcome] || !reconciled[reconciliation] {
			return ErrInvalidResult
		}
		delete(claimed, authorization)
		delete(completed, outcome)
		delete(reconciled, reconciliation)
		requests[record.RequestIdentity()] = true
		previous = record.Identity()
		cost := record.Reconciliation().ActualCost()
		if !cost.IsKnown() || knownCost > ^uint64(0)-cost.TotalCostMicroUSD() {
			return ErrInvalidResult
		}
		knownCost += cost.TotalCostMicroUSD()
		links := append([]string{}, turn.ToolResultArtifactIdentities()...)
		for _, identity := range links {
			if controlplane.ValidateHandlerIdentity(identity) != nil || toolResults[identity] {
				return ErrInvalidResult
			}
			toolResults[identity] = true
		}
		wire.Turns = append(wire.Turns, investigationTurnWire{Identity: record.Identity(), Artifact: value.Identity(), Previous: record.PreviousTurnIdentity(), Request: record.RequestIdentity(), Authorization: authorization, Outcome: outcome, Reconciliation: reconciliation, Route: record.Authorization().RouteRecordIdentity(), ActualCostMicroUSD: cost.TotalCostMicroUSD(), ToolResults: links})
	}
	if uint64(len(toolResults)) > policy.MaxToolCalls() {
		return ErrInvalidResult
	}
	w.UsageKnown = view.UsageKnown() && len(claimed)+len(completed)+len(reconciled) == 0 && knownCost == wire.KnownCostMicroUSD
	if w.UsageKnown {
		w.ActualCostMicroUSD = knownCost
	} else {
		w.Limitations = append(w.Limitations, "unknown_final_usage")
	}
	generation, hasGeneration := view.Generation()
	verification, hasVerification := view.Verification()
	matchesOutput := func(key, identity string) bool {
		task, ok := state.Task(key)
		return ok && task.Status() == controlplane.TaskRuntimeSucceeded && task.OutputIdentity() == identity && identity != ""
	}
	if hasGeneration {
		if !matchesOutput("context", wire.ContextIntent) || !matchesOutput("candidates", generation.ResultArtifact().Identity()) || !matchesOutput("analysis", view.AnalysisArtifactIdentity()) || !matchesOutput("change", view.ChangeArtifactIdentity()) || !matchesOutput("source-head", wire.HeadSnapshot) {
			return ErrInvalidResult
		}
		head, ok := prepared.Plan().Task("source-head")
		if !ok || head.Identity() != wire.SourceHeadTask || view.InitialContextArtifact().Kind() != artifact.KindContextPacket || view.ContextIntentArtifact().Kind() != artifact.KindTaskInput {
			return ErrInvalidResult
		}
		w.Context = generation.ContextIdentity()
		w.GenerationRequest = generation.RouteExecution().Authorization().RequestIdentity()
		w.GenerationRoute = generation.RouteExecution().Authorization().RouteRecordIdentity()
		w.CandidateBatch = generation.Candidates().Identity()
		wire.GenerationInput = generation.InputArtifact().Identity()
		wire.FinalContext = generation.ContextArtifact().Identity()
		for _, candidate := range generation.Candidates().Findings() {
			w.CandidateIDs = append(w.CandidateIDs, candidate.Identity())
		}
		if !requests[w.GenerationRequest] {
			return ErrInvalidResult
		}
	}
	if hasVerification {
		if !hasGeneration || !matchesOutput("verification", view.VerificationArtifact().Identity()) {
			return ErrInvalidResult
		}
		w.VerificationContext = verification.VerificationContext().Identity()
		w.VerificationRequest = verification.RouteExecution().Authorization().RequestIdentity()
		w.VerificationRoute = verification.RouteExecution().Authorization().RouteRecordIdentity()
		w.Independence = verification.RouteIndependence().Level().String()
		if !requests[w.VerificationRequest] {
			return ErrInvalidResult
		}
	}
	if state.Status() == controlplane.ReviewRunSucceeded && (!hasVerification || !w.UsageKnown || len(toolResults) != int(wire.ToolCalls)) {
		return ErrInvalidResult
	}
	return nil
}
