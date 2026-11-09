package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/diagnostics"
	publication "github.com/georgejieh/open-trestle/handlers/publication"
	sourcehandler "github.com/georgejieh/open-trestle/handlers/source"
)

var ErrInvalidLocalFinalDiagnosticProjection = errors.New("invalid local final diagnostic projection")

// LocalFinalDiagnosticProjector writes one terminal V7 result from a finalized full run.
// Its Project method can be used directly as RepositorySupervisorOptions.OnTerminal.
type LocalFinalDiagnosticProjector struct {
	artifacts               artifact.Store
	destination             diagnostics.Store
	analysisHandlerIdentity string
}

func NewLocalFinalDiagnosticProjector(artifacts artifact.Store, destination diagnostics.Store, analysisHandlerIdentity string) (*LocalFinalDiagnosticProjector, error) {
	if localFinalNil(artifacts) || localFinalNil(destination) || controlplane.ValidateHandlerIdentity(analysisHandlerIdentity) != nil {
		return nil, ErrInvalidLocalFinalDiagnosticProjection
	}
	return &LocalFinalDiagnosticProjector{artifacts: artifacts, destination: destination, analysisHandlerIdentity: analysisHandlerIdentity}, nil
}

func (p *LocalFinalDiagnosticProjector) Project(ctx context.Context, state controlplane.ReviewRunState) error {
	if p == nil || localFinalNil(p.artifacts) || localFinalNil(p.destination) || controlplane.ValidateHandlerIdentity(p.analysisHandlerIdentity) != nil || ctx == nil || ctx.Err() != nil || state.Validate() != nil || state.Status() == controlplane.ReviewRunActive {
		return ErrInvalidLocalFinalDiagnosticProjection
	}
	plan := state.Plan()
	// Older full runs used the analysis handler that wrote V6/V5 itself. Leave
	// those immutable records intact when the supervisor revisits history.
	if !isLocalFullReviewPlan(plan) {
		return nil
	}
	analysisTask, found := plan.Task("analysis")
	if !found {
		return ErrInvalidLocalFinalDiagnosticProjection
	}
	if analysisTask.HandlerIdentity() != p.analysisHandlerIdentity {
		return nil
	}
	scope := plan.Scope()
	// Replayed terminal callbacks are common. An immutable V7 in this exact scope
	// was already projected; avoid repeatedly opening the evidence graph.
	existing, err := p.destination.GetDiagnosticSet(ctx, scope)
	if err == nil {
		if existing.SchemaVersion() != 7 || existing.Scope().Identity() != scope.Identity() || !localFinalOutcomeMatchesState(existing.Outcome(), state) {
			return diagnostics.ErrSetConflict
		}
		return nil
	}
	if !errors.Is(err, diagnostics.ErrSetNotFound) {
		return err
	}
	outputs := make(map[controlplane.TaskKind]string, 3)
	for _, task := range plan.Tasks() {
		runtime, found := state.Task(task.Key())
		if !found || runtime.Definition().Identity() != task.Identity() {
			return ErrInvalidLocalFinalDiagnosticProjection
		}
		if runtime.Status() == controlplane.TaskRuntimeSucceeded {
			switch task.Kind() {
			case controlplane.TaskBuildChange, controlplane.TaskInspectDeterministic, controlplane.TaskVerifyCandidates:
				if outputs[task.Kind()] != "" || runtime.OutputIdentity() == "" {
					return ErrInvalidLocalFinalDiagnosticProjection
				}
				outputs[task.Kind()] = runtime.OutputIdentity()
			}
		}
	}
	analysisID, changeID, verificationID := outputs[controlplane.TaskInspectDeterministic], outputs[controlplane.TaskBuildChange], outputs[controlplane.TaskVerifyCandidates]
	// The evidence builder only accepts a complete analysis/change pair. A lone
	// change is not evidence of a completed deterministic analysis.
	if analysisID == "" {
		changeID = ""
	}
	if analysisID != "" && changeID == "" || verificationID != "" && analysisID == "" {
		return ErrInvalidLocalFinalDiagnosticProjection
	}
	at := time.Now().UTC()
	deterministic, verified, err := publication.BuildFinalDiagnosticParts(ctx, p.artifacts, scope, analysisID, changeID, verificationID, at)
	if err != nil {
		// A run refused for its route may be finalized after its evidence
		// retention lapsed. The refusal is in the journal, so it still gets
		// its failed result; the expired parts are reported unavailable.
		if _, refused := finalContextRefusal(state); !refused || state.Status() != controlplane.ReviewRunFailed || verificationID != "" || !errors.Is(err, artifact.ErrArtifactExpired) {
			return err
		}
		deterministic, verified = diagnostics.Set{}, diagnostics.Set{}
	}
	outcome := diagnostics.FinalOutcomeFailed
	switch state.Status() {
	case controlplane.ReviewRunCanceled:
		outcome = diagnostics.FinalOutcomeCanceled
	case controlplane.ReviewRunFailed:
		if verificationID == "" {
			verificationTask, found := plan.Task("verification")
			if !found {
				return ErrInvalidLocalFinalDiagnosticProjection
			}
			runtime, found := state.Task(verificationTask.Key())
			if !found {
				return ErrInvalidLocalFinalDiagnosticProjection
			}
			if runtime.Status() == controlplane.TaskRuntimeFailed {
				outcome = diagnostics.FinalOutcomeInconclusive
			} else if runtime.Status() == controlplane.TaskRuntimeSkipped {
				contextTask, found := plan.Task("context")
				if !found {
					return ErrInvalidLocalFinalDiagnosticProjection
				}
				contextState, found := state.Task(contextTask.Key())
				if !found {
					return ErrInvalidLocalFinalDiagnosticProjection
				}
				if contextState.Status() == controlplane.TaskRuntimeFailed && contextState.OutputIdentity() != "" {
					valid, err := p.validContextAbstention(ctx, state, contextTask, analysisID, changeID, contextState.OutputIdentity(), at)
					if err != nil {
						return err
					}
					if valid {
						outcome = diagnostics.FinalOutcomeAbstained
					}
				}
			}
			if outcome == diagnostics.FinalOutcomeFailed {
				candidates, found := state.Task("candidates")
				contextState, contextFound := state.Task("context")
				if found && candidates.Status() == controlplane.TaskRuntimeFailed || contextFound && contextState.Status() == controlplane.TaskRuntimeSucceeded && runtime.Status() == controlplane.TaskRuntimeSkipped {
					outcome = diagnostics.FinalOutcomeInconclusive
				}
			}
		}
	case controlplane.ReviewRunSucceeded:
		if verified.Identity() == "" || verificationID == "" {
			return ErrInvalidLocalFinalDiagnosticProjection
		}
		outcome = diagnostics.FinalOutcomeCompleted
	default:
		return ErrInvalidLocalFinalDiagnosticProjection
	}
	snapshot, head := "", ""
	if deterministic.Identity() != "" {
		snapshot, head = deterministic.SnapshotIdentity(), deterministic.HeadRevision()
	}
	result, err := diagnostics.NewFinalReviewSet(scope, snapshot, head, outcome, deterministic, verified)
	if err != nil {
		return err
	}
	if refusal, refused := finalContextRefusal(state); refused && outcome == diagnostics.FinalOutcomeFailed {
		if result, err = result.WithContextRefusal(refusal); err != nil {
			return err
		}
	}
	_, err = p.destination.PutDiagnosticSet(ctx, result)
	return err
}

func (p *LocalFinalDiagnosticProjector) validContextAbstention(ctx context.Context, state controlplane.ReviewRunState, task controlplane.TaskDefinition, analysisID, changeID, outputID string, at time.Time) (bool, error) {
	if analysisID == "" || changeID == "" {
		return false, nil
	}
	value, err := p.artifacts.Get(ctx, state.Plan().Scope(), outputID, at)
	if err != nil {
		return false, err
	}
	if value.Validate() != nil || value.Identity() != outputID || value.Kind() != artifact.KindDeterministicEvidence || value.Origin() != artifact.OriginDeterministicTool || value.Scope().Identity() != state.Plan().Scope().Identity() || value.MediaType() != "application/json" {
		return false, ErrInvalidLocalFinalDiagnosticProjection
	}
	// This is a prepared refusal artifact, not an arbitrary failed task output.
	// Validate the scoped plan/task binding and exact canonical payload before
	// distinguishing abstention from transport or policy failure.
	var body struct {
		Contract             string `json:"contract"`
		SchemaVersion        int    `json:"schema_version"`
		ReviewScopeIdentity  string `json:"review_scope_identity"`
		PlanIdentity         string `json:"plan_identity"`
		TaskIdentity         string `json:"task_identity"`
		HeadSnapshotIdentity string `json:"head_snapshot_identity"`
		Reason               string `json:"reason"`
		Failure              string `json:"failure"`
		SourceCoverage       struct {
			Analyzed int `json:"analyzed"`
			Selected int `json:"selected"`
			Omitted  int `json:"omitted"`
		} `json:"source_coverage"`
		SourceOmissions []struct {
			Path      string `json:"path"`
			StartLine int    `json:"start_line"`
			EndLine   int    `json:"end_line"`
			Reason    string `json:"reason"`
			Count     uint32 `json:"count"`
		} `json:"source_omissions"`
	}
	payload := value.Payload()
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&body) != nil || decoder.Decode(new(any)) != io.EOF {
		return false, ErrInvalidLocalFinalDiagnosticProjection
	}
	canonical, err := json.Marshal(body)
	if err != nil || !bytes.Equal(payload, canonical) || body.Contract != "open-trestle/context-abstention" || body.SchemaVersion != 1 || body.ReviewScopeIdentity != state.Plan().Scope().Identity() || body.PlanIdentity != state.Plan().Identity() || body.TaskIdentity != task.Identity() || body.Failure != "policy" && body.Failure != "resource_limit" || body.SourceCoverage.Selected != 0 || body.SourceCoverage.Analyzed != body.SourceCoverage.Omitted || body.SourceCoverage.Omitted < 0 {
		return false, ErrInvalidLocalFinalDiagnosticProjection
	}
	runtime, _ := state.Task(task.Key())
	if body.Failure != runtime.Failure().String() || len(body.SourceOmissions) > 16384 || body.SourceCoverage.Omitted > 65536 || (body.SourceCoverage.Omitted == 0) != (body.Reason == "no_source_changes") {
		return false, ErrInvalidLocalFinalDiagnosticProjection
	}
	omitted := uint64(0)
	var previous struct {
		path       string
		start, end int
		reason     string
	}
	for _, item := range body.SourceOmissions {
		if item.Path == "" || item.Reason == "" || item.Count == 0 || item.Count > 32768 || item.StartLine < 0 || item.EndLine < item.StartLine {
			return false, ErrInvalidLocalFinalDiagnosticProjection
		}
		if previous.path != "" && (item.Path < previous.path || item.Path == previous.path && (item.StartLine < previous.start || item.StartLine == previous.start && (item.EndLine < previous.end || item.EndLine == previous.end && item.Reason <= previous.reason))) {
			return false, ErrInvalidLocalFinalDiagnosticProjection
		}
		previous.path, previous.start, previous.end, previous.reason = item.Path, item.StartLine, item.EndLine, item.Reason
		omitted += uint64(item.Count)
	}
	if omitted != uint64(body.SourceCoverage.Omitted) {
		return false, ErrInvalidLocalFinalDiagnosticProjection
	}
	switch body.Reason {
	case "all_sources_omitted", "packet_budget_zero_selection", "unsupported_language", "no_source_changes":
	default:
		return false, ErrInvalidLocalFinalDiagnosticProjection
	}
	headState, found := state.Task("source-head")
	if !found || headState.Status() != controlplane.TaskRuntimeSucceeded {
		return false, ErrInvalidLocalFinalDiagnosticProjection
	}
	headArtifact, err := p.artifacts.Get(ctx, state.Plan().Scope(), headState.OutputIdentity(), at)
	if err != nil {
		return false, err
	}
	head, err := sourcehandler.ParseSnapshotArtifact(headArtifact)
	if err != nil || head.Identity() != body.HeadSnapshotIdentity {
		return false, ErrInvalidLocalFinalDiagnosticProjection
	}
	provenance := value.Provenance()
	hasAnalysis, hasChange, hasHead := false, false, false
	for _, identity := range provenance {
		hasAnalysis = hasAnalysis || identity == analysisID
		hasChange = hasChange || identity == changeID
		hasHead = hasHead || identity == headState.OutputIdentity()
	}
	if !hasAnalysis || !hasChange || !hasHead {
		return false, ErrInvalidLocalFinalDiagnosticProjection
	}
	return true, nil
}

func localFinalNil(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan:
		return v.IsNil()
	}
	return false
}

// An existing V7 is authoritative only if its disposition agrees with the
// current terminal state. Artifact identities are checked on the first write.
func localFinalOutcomeMatchesState(outcome diagnostics.FinalOutcome, state controlplane.ReviewRunState) bool {
	switch state.Status() {
	case controlplane.ReviewRunCanceled:
		return outcome == diagnostics.FinalOutcomeCanceled
	case controlplane.ReviewRunSucceeded:
		verification, found := state.Task("verification")
		return found && verification.Status() == controlplane.TaskRuntimeSucceeded && outcome == diagnostics.FinalOutcomeCompleted
	case controlplane.ReviewRunFailed:
		verification, found := state.Task("verification")
		if !found {
			return false
		}
		if verification.Status() == controlplane.TaskRuntimeFailed && verification.OutputIdentity() == "" {
			return outcome == diagnostics.FinalOutcomeInconclusive
		}
		candidates, found := state.Task("candidates")
		if found && candidates.Status() == controlplane.TaskRuntimeFailed {
			return outcome == diagnostics.FinalOutcomeInconclusive
		}
		contextState, found := state.Task("context")
		if !found {
			return false
		}
		if outcome == diagnostics.FinalOutcomeAbstained {
			return verification.Status() == controlplane.TaskRuntimeSkipped && contextState.Status() == controlplane.TaskRuntimeFailed && contextState.OutputIdentity() != ""
		}
		if verification.Status() == controlplane.TaskRuntimeSkipped && contextState.Status() == controlplane.TaskRuntimeSucceeded {
			return outcome == diagnostics.FinalOutcomeInconclusive
		}
		return outcome == diagnostics.FinalOutcomeFailed
	}
	return false
}

// finalContextRefusal copies the context task's recorded route refusal, if any.
func finalContextRefusal(state controlplane.ReviewRunState) (diagnostics.ContextRefusal, bool) {
	task, found := state.Task("context")
	if !found || task.Status() != controlplane.TaskRuntimeFailed || task.OutputIdentity() != "" {
		return diagnostics.ContextRefusal{}, false
	}
	switch task.FailureReason() {
	case controlplane.TaskFailureReasonRouteContextInsufficient:
		shortfall, _ := task.ContextShortfall()
		return diagnostics.ContextRefusal{Reason: diagnostics.ContextRefusalRouteContextInsufficient, RequiredTokens: shortfall.RequiredTokens, EstimatedInputTokens: shortfall.EstimatedInputTokens, MaxOutputTokens: shortfall.MaxOutputTokens, DeclaredContextTokens: shortfall.DeclaredContextTokens}, true
	case controlplane.TaskFailureReasonNoEligibleRoute:
		return diagnostics.ContextRefusal{Reason: diagnostics.ContextRefusalNoEligibleRoute}, true
	default:
		return diagnostics.ContextRefusal{}, false
	}
}
