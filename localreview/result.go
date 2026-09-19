package localreview

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/diagnostics"
	modelhandler "github.com/georgejieh/open-trestle/handlers/model"
	sourcehandler "github.com/georgejieh/open-trestle/handlers/source"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/internal/scm"
	"github.com/georgejieh/open-trestle/runtimecatalog"
	"io"
	"strings"
)

const (
	MaxResultJSONBytes = 256 << 10
	MaxResultTextBytes = 64 << 10
)

var ErrInvalidResult = errors.New("local review result unavailable or exceeds output bounds")

type taskResult struct {
	Key         string `json:"key"`
	Status      string `json:"status"`
	Attempts    uint8  `json:"attempts"`
	MaxAttempts uint8  `json:"max_attempts"`
	Output      string `json:"output_identity"`
}
type auditResult struct {
	Kind    string `json:"kind"`
	Subject string `json:"subject_identity"`
}
type resultWire struct {
	Contract               string                   `json:"contract"`
	Version                int                      `json:"schema_version"`
	Status                 string                   `json:"status"`
	CI                     string                   `json:"ci_disposition"`
	RunStatus              string                   `json:"run_status"`
	Failure                string                   `json:"failure"`
	Run                    string                   `json:"review_run_id"`
	Scope                  string                   `json:"scope_identity"`
	Request                string                   `json:"request_identity"`
	Plan                   string                   `json:"plan_identity"`
	Output                 string                   `json:"output_identity"`
	Repository             string                   `json:"repository_identity"`
	Base                   string                   `json:"base_revision_identity"`
	Head                   string                   `json:"head_revision_identity"`
	Inventory              string                   `json:"inventory_identity"`
	Policy                 string                   `json:"runtime_policy_identity"`
	Context                string                   `json:"context_identity"`
	GenerationRequest      string                   `json:"generation_request_identity"`
	VerificationRequest    string                   `json:"verification_request_identity"`
	VerificationContext    string                   `json:"verification_context_identity"`
	CandidateBatch         string                   `json:"candidate_batch_identity"`
	CandidateIDs           []string                 `json:"candidate_ids"`
	Readiness              string                   `json:"readiness_identity"`
	GenerationRoute        string                   `json:"generation_route_record_identity"`
	VerificationRoute      string                   `json:"verification_route_record_identity"`
	Independence           string                   `json:"independence"`
	Limitations            []string                 `json:"limitations"`
	ComprehensiveClearance bool                     `json:"comprehensive_clearance"`
	UsageKnown             bool                     `json:"usage_known"`
	ActualCostMicroUSD     uint64                   `json:"actual_cost_micro_usd"`
	LeaseRenewals          uint64                   `json:"lease_renewals"`
	Tasks                  []taskResult             `json:"tasks"`
	Audit                  []auditResult            `json:"audit"`
	Diagnostics            json.RawMessage          `json:"diagnostics"`
	Investigation          *investigationResultWire `json:"investigation,omitempty"`
}

// Result is a sealed, bounded projection, never source or provider configuration.
type Result struct {
	wire           resultWire
	diagnostics    diagnostics.Set
	valid          bool
	sealedJSON     []byte
	sealedText     []byte
	diagnosticOnly bool
}

func emptyResult(status string) Result {
	result, _ := emptyResultWithObjectStoreProfile(status, scm.LocalGitObjectStoreProfileLooseOnly)
	return result
}

func emptyResultWithObjectStoreProfile(status string, profile scm.LocalGitObjectStoreProfile) (Result, error) {
	ci := "inconclusive"
	if status == "refused" || status == "findings" {
		ci = "blocked"
	}
	if status == "failed" {
		ci = "error"
	}
	if profile == "" {
		profile = scm.LocalGitObjectStoreProfileLooseOnly
	}
	sourceLimitation := ""
	switch profile {
	case scm.LocalGitObjectStoreProfileLooseOnly:
		sourceLimitation = "loose_git_objects_only"
	case scm.LocalGitObjectStoreProfileLooseAndPackIndexV1:
		sourceLimitation = "loose_and_pack_index_v1_subset"
	default:
		return Result{}, ErrInvalidResult
	}
	return Result{wire: resultWire{Contract: "open-trestle/local-git-model-review-result", Version: 1, Status: status, CI: ci, RunStatus: "not_opened", Limitations: []string{sourceLimitation, "empty_memory_index", "bounded_source_context", "no_publication", "ephemeral_state_no_resume"}, CandidateIDs: []string{}, Tasks: []taskResult{}, Audit: []auditResult{}, Diagnostics: json.RawMessage("null")}, valid: true}, nil
}

func (s *Session) emptyResult(status string) Result {
	profile := scm.LocalGitObjectStoreProfileLooseOnly
	if s != nil {
		profile = s.options.ObjectStoreProfile
	}
	result, err := emptyResultWithObjectStoreProfile(status, profile)
	if err != nil {
		return Result{}
	}
	if s != nil && s.options.RetainedMemoryInput != nil {
		limitations := make([]string, 0, len(result.wire.Limitations)+1)
		for _, limitation := range result.wire.Limitations {
			if limitation == "empty_memory_index" {
				limitations = append(limitations, "retained_input_advisory_not_all_records_selected", "retained_input_read_only")
			} else {
				limitations = append(limitations, limitation)
			}
		}
		result.wire.Limitations = limitations
	}
	return result
}

// NewUnstartedResult describes only a refused/unavailable host operation. It
// cannot assert a journal, model call, finding, or successful clearance.
func NewUnstartedResult(status string) (Result, error) {
	switch status {
	case "refused", "incomplete", "canceled", "failed":
		return emptyResult(status), nil
	}
	return Result{}, ErrInvalidResult
}

func NewUnstartedResultWithObjectStoreProfile(status string, profile scm.LocalGitObjectStoreProfile) (Result, error) {
	switch status {
	case "refused", "incomplete", "canceled", "failed":
		return emptyResultWithObjectStoreProfile(status, profile)
	}
	return Result{}, ErrInvalidResult
}
func (s *Session) unstarted(p runtimecatalog.PreparedReviewRun, status string) Result {
	result := s.emptyResult(status)
	w := &result.wire
	w.Run = p.Plan().Scope().ReviewRunID()
	w.Scope = p.Plan().Scope().Identity()
	w.Request = p.RequestIdentity()
	w.Plan = p.Plan().Identity()
	w.Repository = s.options.Repository.Identity()
	w.Inventory = s.options.Inventory.Identity()
	w.Policy = s.options.Policy.Identity()
	if s.investigation != nil {
		w.Version = 2
		w.Investigation = &investigationResultWire{Profile: s.investigation.profile.Identity(), Policy: s.investigation.profile.Policy().Identity(), Turns: []investigationTurnWire{}}
	}
	inputs := p.Inputs()
	if len(inputs) == 2 {
		base, e1 := sourcehandler.ParseInput(inputs[0].Payload())
		head, e2 := sourcehandler.ParseInput(inputs[1].Payload())
		if e1 == nil && e2 == nil {
			w.Base = base.Revision().Identity()
			w.Head = head.Revision().Identity()
		}
	}
	return result
}
func (s *Session) readResult(ctx context.Context, p runtimecatalog.PreparedReviewRun, state controlplane.ReviewRunState) (Result, error) {
	if state.Validate() != nil || state.Plan().Identity() != p.Plan().Identity() || state.Status() == controlplane.ReviewRunActive {
		return Result{}, ErrInvalidResult
	}
	result := s.unstarted(p, "incomplete")
	w := &result.wire
	w.RunStatus = state.Status().String()
	w.Output = state.OutputIdentity()
	w.Failure = state.Failure().String()
	sourceFailed := false
	for _, definition := range p.Plan().Tasks() {
		task, ok := state.Task(definition.Key())
		if !ok {
			return Result{}, ErrInvalidResult
		}
		w.Tasks = append(w.Tasks, taskResult{task.Key(), task.Status().String(), task.Attempts(), definition.MaxAttempts(), task.OutputIdentity()})
		if definition.Kind() == controlplane.TaskAcquireSource && task.Status() == controlplane.TaskRuntimeFailed {
			sourceFailed = true
		}
	}
	if state.Status() == controlplane.ReviewRunCanceled {
		w.Status = "canceled"
	} else if state.Status() == controlplane.ReviewRunFailed {
		switch {
		case state.Failure() == controlplane.RunFailurePolicy || state.Failure() == controlplane.RunFailureResourceLimit:
			w.Status = "refused"
			w.CI = "blocked"
		case sourceFailed:
			w.Status = "incomplete"
		default:
			w.Status = "failed"
			w.CI = "error"
		}
	}
	if s.investigation != nil {
		diagnostic := result
		diagnostic.wire.Limitations = append(append([]string{}, w.Limitations...), "execution_readback_incomplete", "unknown_final_usage")
		s.rememberInvestigationResult(diagnostic)
	}
	auditLimit, maximumAudit := uint16(32), 16
	if s.investigation != nil {
		auditLimit, maximumAudit = 1000, 1000
	}
	events, err := s.ledger.Read(ctx, p.Plan().Scope(), 0, auditLimit)
	if err != nil || len(events) > maximumAudit {
		return Result{}, ErrInvalidResult
	}
	head, exists, err := s.ledger.Head(ctx, p.Plan().Scope())
	if err != nil || exists && (len(events) == 0 || events[len(events)-1].Identity() != head.Identity()) {
		return Result{}, ErrInvalidResult
	}
	if s.investigation != nil && exists != (len(events) != 0) {
		return Result{}, ErrInvalidResult
	}
	claims := 0
	previousAudit := ""
	for index, event := range events {
		if s.investigation != nil && (event.Sequence() != uint64(index+1) || event.PreviousIdentity() != previousAudit) {
			return Result{}, ErrInvalidResult
		}
		previousAudit = event.Identity()
		if event.Validate() != nil || event.Scope().Identity() != w.Scope || strings.HasPrefix(event.Kind().String(), "publication_") {
			return Result{}, ErrInvalidResult
		}
		w.Audit = append(w.Audit, auditResult{event.Kind().String(), event.SubjectIdentity()})
		if event.Kind() == audit.EventRouteAttemptClaimed {
			claims++
		}
	}
	if s.investigation != nil {
		diagnostic := result
		diagnostic.wire.Limitations = append(append([]string{}, w.Limitations...), "execution_readback_incomplete", "unknown_final_usage")
		s.rememberInvestigationResult(diagnostic)
	}
	// The production journal caps renewals. Read fixed pages, not an unbounded
	// resident event list or a new lease counter independent of the journal.
	after := uint64(0)
	for page := 0; page < 12; page++ {
		events, err := s.journal.Read(ctx, p.Plan().Scope(), after, 1000)
		if err != nil {
			return Result{}, ErrInvalidResult
		}
		for _, event := range events {
			if event.Validate() != nil {
				return Result{}, ErrInvalidResult
			}
			if event.Kind() == controlplane.RunEventTaskLeaseRenewed {
				w.LeaseRenewals++
			}
			after = event.Sequence()
		}
		if len(events) < 1000 {
			break
		}
		if page == 11 {
			return Result{}, ErrInvalidResult
		}
	}
	get := func(id string) (artifact.Artifact, error) {
		value, err := s.store.Get(ctx, p.Plan().Scope(), id, s.options.Clock.Now())
		if err != nil || value.Validate() != nil || value.Scope().Identity() != w.Scope || value.Protection() != artifact.ProtectionProcessPrivate || value.Classification() != s.classification {
			return artifact.Artifact{}, ErrInvalidResult
		}
		return value, nil
	}
	taskOutput := func(key string) (artifact.Artifact, bool, error) {
		task, ok := state.Task(key)
		if !ok {
			return artifact.Artifact{}, false, ErrInvalidResult
		}
		if task.Status() != controlplane.TaskRuntimeSucceeded {
			return artifact.Artifact{}, false, nil
		}
		value, err := get(task.OutputIdentity())
		return value, true, err
	}
	var verification modelhandler.VerificationResult
	var verificationArtifact artifact.Artifact
	var hasVerification bool
	if s.investigation != nil {
		if state.Status() != controlplane.ReviewRunSucceeded {
			s.retainInvestigationDiagnostics(ctx, p, &result)
			s.rememberInvestigationResult(fitInvestigationDiagnostics(result))
		}
		view, readErr := s.activeInvestigation.ReadResult(ctx)
		if readErr != nil {
			if state.Status() == controlplane.ReviewRunSucceeded {
				w.Status, w.CI = "failed", "error"
			}
			w.Limitations = append(w.Limitations, "investigation_readback_unavailable", "unknown_final_usage")
			return result, nil
		}
		if view.PlanIdentity() != w.Plan || view.ScopeIdentity() != w.Scope || view.RunStatus() != state.Status() || view.OutputIdentity() != w.Output {
			return Result{}, ErrInvalidResult
		}
		if err := s.projectInvestigation(&result, p, state, view, events); err != nil {
			return Result{}, err
		}
		verification, hasVerification = view.Verification()
		verificationArtifact = view.VerificationArtifact()
	} else {
		inputArtifact, hasContext, err := taskOutput("context")
		if err != nil {
			return Result{}, err
		}
		var contextArtifact artifact.Artifact
		if hasContext {
			input, err := modelhandler.ParseGenerationInput(inputArtifact.Payload())
			if err != nil {
				return Result{}, ErrInvalidResult
			}
			contextArtifact, err = get(input.ContextArtifactIdentity())
			if err != nil {
				return Result{}, err
			}
			if inputArtifact.Kind() != artifact.KindTaskInput || inputArtifact.Origin() != artifact.OriginHost || input.ReviewScopeIdentity() != w.Scope || contextArtifact.Kind() != artifact.KindContextPacket || contextArtifact.Origin() != artifact.OriginHost || contextArtifact.PayloadDigest() != input.ContextIdentity() {
				return Result{}, ErrInvalidResult
			}
			w.Context = input.ContextIdentity()
			w.GenerationRequest = input.Authorization().RequestIdentity()
			w.GenerationRoute = input.Authorization().RouteRecordIdentity()
		}
		generationArtifact, hasGeneration, err := taskOutput("candidates")
		if err != nil {
			return Result{}, err
		}
		var generation modelhandler.GenerationResult
		knownExecutions := 0
		knownCost := uint64(0)
		if hasGeneration {
			if !hasContext {
				return Result{}, ErrInvalidResult
			}
			generation, err = modelhandler.ParseGenerationResultArtifact(generationArtifact, inputArtifact, contextArtifact)
			if err != nil {
				return Result{}, ErrInvalidResult
			}
			w.CandidateBatch = generation.Candidates().Identity()
			for _, candidate := range generation.Candidates().Findings() {
				w.CandidateIDs = append(w.CandidateIDs, candidate.Identity())
			}
			cost := generation.RouteExecution().Reconciliation().ActualCost()
			if cost.IsKnown() {
				if knownCost > ^uint64(0)-cost.TotalCostMicroUSD() {
					return Result{}, ErrInvalidResult
				}
				knownExecutions++
				knownCost += cost.TotalCostMicroUSD()
			}
		}
		verificationArtifact, hasVerification, err = taskOutput("verification")
		if err != nil {
			return Result{}, err
		}
		if hasVerification {
			if !hasGeneration {
				return Result{}, ErrInvalidResult
			}
			verification, err = modelhandler.ParseVerificationResultArtifact(verificationArtifact, generationArtifact, inputArtifact, contextArtifact)
			if err != nil {
				return Result{}, ErrInvalidResult
			}
			w.VerificationContext = verification.VerificationContext().Identity()
			w.VerificationRequest = verification.RouteExecution().Authorization().RequestIdentity()
			w.VerificationRoute = verification.RouteExecution().Authorization().RouteRecordIdentity()
			w.Independence = verification.RouteIndependence().Level().String()
			cost := verification.RouteExecution().Reconciliation().ActualCost()
			if cost.IsKnown() {
				if knownCost > ^uint64(0)-cost.TotalCostMicroUSD() {
					return Result{}, ErrInvalidResult
				}
				knownExecutions++
				knownCost += cost.TotalCostMicroUSD()
			}
		}
		w.UsageKnown = claims == knownExecutions
		if w.UsageKnown {
			w.ActualCostMicroUSD = knownCost
		} else {
			w.Limitations = append(w.Limitations, "unknown_final_usage")
		}
	}
	readinessArtifact, hasReadiness, err := taskOutput("readiness")
	if err != nil {
		return Result{}, err
	}
	if hasReadiness && state.Status() == controlplane.ReviewRunSucceeded {
		if !hasVerification || readinessArtifact.Kind() != artifact.KindPublicationPlan || readinessArtifact.Origin() != artifact.OriginPolicy || readinessArtifact.Identity() != w.Output {
			return Result{}, ErrInvalidResult
		}
		readiness, err := review.EvaluatePublicationReadiness(s.options.Policy.Publication(), verification.IndependentReceipt(), verification.VerifiedFindings())
		if err != nil {
			return Result{}, ErrInvalidResult
		}
		// Read only the actual readiness artifact and check against the same core
		// contract. This does not create a second review or publication algorithm.
		var recorded struct {
			Contract             string `json:"contract"`
			Version              int    `json:"schema_version"`
			Readiness            string `json:"readiness_identity"`
			VerificationArtifact string `json:"verification_artifact_identity"`
			VerificationResult   string `json:"verification_result_identity"`
			Policy               string `json:"publication_policy_identity"`
			Status               string `json:"status"`
		}
		if json.Unmarshal(readinessArtifact.Payload(), &recorded) != nil || recorded.Contract != "open-trestle/publication-readiness-result" || recorded.Version != 1 || recorded.Readiness != readiness.Identity() || recorded.VerificationArtifact != verificationArtifact.Identity() || recorded.VerificationResult != verification.Identity() || recorded.Policy != s.options.Policy.Publication().Identity() || recorded.Status != readiness.Status().String() {
			return Result{}, ErrInvalidResult
		}
		set, err := s.diagnostics.GetDiagnosticSet(ctx, p.Plan().Scope())
		if err != nil || set.Validate() != nil || set.Scope().Identity() != w.Scope || set.VerificationContextIdentity() != w.VerificationContext || set.VerifiedSetIdentity() != verification.VerifiedFindings().Identity() {
			return Result{}, ErrInvalidResult
		}
		headInput, err := sourcehandler.ParseInput(p.Inputs()[1].Payload())
		if err != nil || set.HeadRevision() != headInput.Revision().Digest() || set.SnapshotIdentity() != verification.VerificationContext().SnapshotIdentity() {
			return Result{}, ErrInvalidResult
		}
		encoded, err := diagnostics.EncodeSet(set)
		if err != nil {
			return Result{}, ErrInvalidResult
		}
		w.Diagnostics = encoded
		result.diagnostics = set
		w.Readiness = recorded.Readiness
		if state.Status() != controlplane.ReviewRunSucceeded {
			return Result{}, ErrInvalidResult
		}
		switch {
		case len(readiness.InlineFindings())+readiness.SummaryOnlyCount() > 0:
			w.Status = "findings"
			w.CI = "blocked"
		case set.SourceOmittedCount() > 0 || set.InconclusiveCount() > 0:
			w.Status = "incomplete"
		case set.CandidateCount() == 0:
			w.Status = "no_candidates"
		default:
			w.Status = "incomplete"
		}
	}
	if state.Status() == controlplane.ReviewRunSucceeded && !hasReadiness {
		return Result{}, ErrInvalidResult
	}
	if s.investigation != nil {
		result = fitInvestigationDiagnostics(result)
	}
	if _, err := EncodeResult(result); err != nil {
		return Result{}, err
	}
	return result, nil
}

// FailureResult is a payload-free fallback when safe terminal readback or closure
// failed after execution admission. It must not claim that work never started.
func (s *Session) FailureResult() Result {
	if s != nil && s.investigation != nil {
		s.mu.Lock()
		result := s.lastInvestigationResult
		s.mu.Unlock()
		if result.valid {
			result.sealedJSON, result.sealedText = nil, nil
			result.wire.Status, result.wire.CI = "failed", "error"
			result.wire.Limitations = append(append([]string{}, result.wire.Limitations...), "execution_or_closure_failed")
			return fitInvestigationDiagnostics(result)
		}
		result = s.emptyResult("failed")
		result.wire.Version = 2
		result.wire.RunStatus = "unknown"
		result.wire.Limitations = append(result.wire.Limitations, "execution_state_unavailable", "unknown_final_usage")
		result.wire.Investigation = &investigationResultWire{Profile: s.investigation.profile.Identity(), Policy: s.investigation.profile.Policy().Identity(), Turns: []investigationTurnWire{}}
		return result
	}
	result := s.emptyResult("failed")
	result.wire.RunStatus = "unknown"
	result.wire.Limitations = append(result.wire.Limitations, "execution_state_unavailable", "unknown_final_usage")
	return result
}
func (r Result) CIDisposition() string {
	if !r.valid {
		return "error"
	}
	return r.wire.CI
}
func (r Result) ExitCode() int {
	if !r.valid {
		return 1
	}
	switch r.wire.CI {
	case "blocked":
		return 4
	case "inconclusive":
		return 3
	default:
		return 1
	}
}
func EncodeResult(r Result) ([]byte, error) {
	if !r.valid || r.wire.ComprehensiveClearance {
		return nil, ErrInvalidResult
	}
	if r.sealedJSON != nil {
		return append([]byte(nil), r.sealedJSON...), nil
	}
	value, err := json.Marshal(r.wire)
	if err != nil || len(value)+1 > MaxResultJSONBytes {
		return nil, ErrInvalidResult
	}
	return append(value, '\n'), nil
}
func RenderResult(writer io.Writer, r Result) error {
	if nilValue(writer) || !r.valid {
		return ErrInvalidResult
	}
	if r.sealedText != nil {
		n, err := writer.Write(append([]byte(nil), r.sealedText...))
		if err == nil && n != len(r.sealedText) {
			err = io.ErrShortWrite
		}
		return err
	}
	var buffer bytes.Buffer
	fmt.Fprintf(&buffer, "status: %s\nci: %s\nrun: %s\n", r.wire.Status, r.wire.CI, r.wire.RunStatus)
	for _, finding := range r.diagnostics.Findings() {
		fmt.Fprintf(&buffer, "finding: %s %s\nsource: %s:%d-%d\n", finding.Severity().String(), finding.Title(), finding.Path(), finding.StartLine(), finding.EndLine())
	}
	fmt.Fprintf(&buffer, "limitations: %s\ncomprehensive clearance: false\n", strings.Join(r.wire.Limitations, ", "))
	if buffer.Len() > MaxResultTextBytes {
		return ErrInvalidResult
	}
	n, err := writer.Write(buffer.Bytes())
	if err == nil && n != buffer.Len() {
		err = io.ErrShortWrite
	}
	return err
}
func (r Result) String() string   { return "local model review result" }
func (r Result) GoString() string { return "localreview.Result{<redacted>}" }
