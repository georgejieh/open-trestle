package localreview

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/georgejieh/open-trestle/agentprofile"
	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/diagnostics"
	modelhandler "github.com/georgejieh/open-trestle/handlers/model"
	sourcehandler "github.com/georgejieh/open-trestle/handlers/source"
	"github.com/georgejieh/open-trestle/internal/gateway"
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
	FailureDetail          string                   `json:"failure_detail,omitempty"` // observed refinement of Failure; see failure_summary.go
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
	Specialist             *specialistResultWire    `json:"specialist,omitempty"`
	Guidance               []findingGuidanceWire    `json:"finding_guidance,omitempty"`
	// InstructionContextOmitted counts repository instruction files not supplied
	// as advisory context (changed in the head, truncated, oversized,
	// unauthorized, or over budget). They are not changed sources and never make
	// a review incomplete. Omitted when zero.
	InstructionContextOmitted uint32 `json:"instruction_context_omitted,omitempty"`
	// RepositoryContextAnchorOmitted counts model proposals dropped at admission
	// because they were located in repository instruction context rather than
	// reviewed code. Omitted when zero.
	RepositoryContextAnchorOmitted int `json:"repository_context_anchor_candidates_omitted,omitempty"`
	// AgentConfigurationSources counts generation-context sources whose path
	// names repository AI material (agent instruction files, skills, prompts,
	// agent tool configuration). InstructionLikeSources counts sources whose
	// content looks like instructions to a model, such as role markers or
	// override phrases. Both are attention signals for people: such material is
	// reviewed as code and the flags never suppress review. Omitted when zero.
	AgentConfigurationSources int `json:"agent_configuration_sources,omitempty"`
	InstructionLikeSources    int `json:"instruction_like_sources,omitempty"`
	// StyleAdvice is the optional style advice of schema version 5, encoded
	// inline.
	StyleAdvice
}

// Limitations naming advisory-context accounting that does not affect status.
const (
	instructionContextOmittedLimitation      = "instruction_context_omitted"
	repositoryContextAnchorOmittedLimitation = "repository_context_anchor_candidates_omitted"
)

// findingGuidanceWire carries one verified finding's advisory category and
// optional fix guidance, keyed by the diagnostic finding's source identity (the
// verified finding identity). It appears only in schema version 4 results. The
// verifier checked the finding's claim, not this guidance: the category is the
// generator's advisory label and the fix is unverified model text that nothing
// applies.
type findingGuidanceWire struct {
	FindingIdentity string `json:"finding_identity"`
	Category        string `json:"category"`
	Fix             string `json:"fix,omitempty"`
	FixAuthority    string `json:"fix_authority,omitempty"`
}

const guidanceResultVersion = 4

// FixAuthority labels every model fix-guidance string: unverified model text
// that nothing applies. Exporters reuse it rather than restating the label.
const FixAuthority = "unverified_model_guidance"

// withFindingGuidance adds the category and fix of every categorized verified
// finding in diagnostic order. A result with guidance is schema version 4; it
// keeps a specialist block when one is bound.
func withFindingGuidance(result Result, findings review.VerifiedFindingSet) (Result, error) {
	byIdentity := make(map[string]review.VerifiedFinding, len(findings.Findings()))
	for _, finding := range findings.Findings() {
		byIdentity[finding.Identity()] = finding
	}
	var guidance []findingGuidanceWire
	for _, diagnostic := range result.diagnostics.Findings() {
		finding, ok := byIdentity[diagnostic.SourceIdentity()]
		if !ok {
			return Result{}, ErrInvalidResult
		}
		if finding.Category() == "" {
			continue
		}
		value := findingGuidanceWire{FindingIdentity: finding.Identity(), Category: finding.Category().String(), Fix: finding.Fix()}
		if value.Fix != "" {
			value.FixAuthority = FixAuthority
		}
		guidance = append(guidance, value)
	}
	if len(guidance) > 0 {
		result.wire.Version = guidanceResultVersion
		result.wire.Guidance = guidance
	}
	return result, nil
}

// StyleAdvice is the style advice of a result (schema version 5) or review set:
// a fixed recommendation for each changed language that has a style detector
// but no style declared by the base tree, and the languages withheld because a
// base style configuration file that could declare their style was not read
// (over 64 KiB, not valid UTF-8, or beyond 256 files). ConfigurationUnread
// counts those files. The text is Open Trestle's fixed table
// (agentprofile.RecommendedStyle), not model output. Style advice never blocks:
// it is not a finding and never changes status, CI disposition, exit code,
// coverage or clearance. Unavailable alone marks a recorded change model, its
// snapshots or a base style configuration file that could not be read back, so
// no advice could be derived. Version 5 keeps a specialist block and finding
// guidance. Every field is omitted when empty.
type StyleAdvice struct {
	Recommendations     []StyleRecommendation `json:"style_recommendations,omitempty"`
	Withheld            []StyleWithheld       `json:"style_withheld,omitempty"`
	ConfigurationUnread int                   `json:"style_configuration_unread,omitempty"`
	Unavailable         bool                  `json:"style_advice_unavailable,omitempty"`
}

// StyleRecommendation suggests the standard style for one changed language.
type StyleRecommendation struct {
	Language       string `json:"language"`
	ChangedFiles   int    `json:"changed_files"`
	Recommendation string `json:"recommendation"`
}

// StyleWithheld is a changed language whose declared style is unknown.
type StyleWithheld struct {
	Language     string `json:"language"`
	ChangedFiles int    `json:"changed_files"`
}

func (a StyleAdvice) empty() bool {
	return len(a.Recommendations) == 0 && len(a.Withheld) == 0 && a.ConfigurationUnread == 0 && !a.Unavailable
}

const styleResultVersion = 5

// newStyleAdvice projects agentprofile advice with the unread file count.
func newStyleAdvice(advice agentprofile.StyleAdvice, unread int) StyleAdvice {
	value := StyleAdvice{ConfigurationUnread: unread}
	for _, recommendation := range advice.Recommendations {
		_, standard, _ := agentprofile.RecommendedStyle(recommendation.Language)
		value.Recommendations = append(value.Recommendations, StyleRecommendation{Language: string(recommendation.Language), ChangedFiles: recommendation.ChangedFiles, Recommendation: standard})
	}
	for _, withheld := range advice.Withheld {
		value.Withheld = append(value.Withheld, StyleWithheld{Language: string(withheld.Language), ChangedFiles: withheld.ChangedFiles})
	}
	return value
}

// withStyleAdvice adds style advice to a direct review result. A result with
// advice is schema version 5; one without keeps its version.
func withStyleAdvice(result Result, advice StyleAdvice) Result {
	if advice.empty() {
		return result
	}
	result.wire.Version = styleResultVersion
	result.wire.StyleAdvice = advice
	return result
}

// StyleAdvice returns a copy of the style advice the result carries. It is empty
// unless the result is schema version 5.
func (r Result) StyleAdvice() StyleAdvice {
	if !r.valid {
		return StyleAdvice{}
	}
	advice := r.wire.StyleAdvice
	advice.Recommendations = append([]StyleRecommendation(nil), advice.Recommendations...)
	advice.Withheld = append([]StyleWithheld(nil), advice.Withheld...)
	return advice
}

// Lines returns the newline-terminated text lines that describe the advice:
// one per recommendation, one per withheld language, and one for unread files.
func (a StyleAdvice) Lines() []string {
	var lines []string
	files := func(count int) string {
		if count == 1 {
			return "1 changed file"
		}
		return fmt.Sprintf("%d changed files", count)
	}
	for _, value := range a.Recommendations {
		name, _, _ := agentprofile.RecommendedStyle(agentprofile.Language(value.Language))
		lines = append(lines, fmt.Sprintf("style: no declared %s style for %s; consider %s, and commit its configuration\n", name, files(value.ChangedFiles), value.Recommendation))
	}
	for _, value := range a.Withheld {
		name, _, _ := agentprofile.RecommendedStyle(agentprofile.Language(value.Language))
		lines = append(lines, fmt.Sprintf("style: declared %s style unknown for %s; a base style configuration file that may declare it was not read, so no recommendation is made\n", name, files(value.ChangedFiles)))
	}
	if a.ConfigurationUnread > 0 {
		subject := "file was"
		if a.ConfigurationUnread != 1 {
			subject = "files were"
		}
		lines = append(lines, fmt.Sprintf("style: %d base style configuration %s not read (over 64 KiB, not valid UTF-8, or beyond 256 files)\n", a.ConfigurationUnread, subject))
	}
	if a.Unavailable {
		lines = append(lines, "style: advice unavailable; the recorded change or base style configuration could not be read back\n")
	}
	return lines
}

// specialistResultWire identifies the packaged profile bound into generation.
// It appears only in schema version 3 results.
type specialistResultWire struct {
	ProfileID       string `json:"profile_id"`
	ProfileIdentity string `json:"profile_identity"`
	CatalogIdentity string `json:"catalog_identity"`
}

const specialistResultVersion = 3

func withSpecialist(result Result, specialist review.ContextSpecialist) Result {
	if specialist.IsZero() {
		return result
	}
	result.wire.Version = specialistResultVersion
	result.wire.Specialist = &specialistResultWire{ProfileID: specialist.ProfileID(), ProfileIdentity: specialist.ProfileIdentity(), CatalogIdentity: specialist.CatalogIdentity()}
	return result
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

// NewUnstartedSpecialistResult is NewUnstartedResultWithObjectStoreProfile for a
// request that selected a packaged specialist profile. A zero specialist yields
// the same result as NewUnstartedResultWithObjectStoreProfile.
func NewUnstartedSpecialistResult(status string, profile scm.LocalGitObjectStoreProfile, specialist review.ContextSpecialist) (Result, error) {
	if !specialist.IsZero() && specialist.Validate() != nil {
		return Result{}, ErrInvalidResult
	}
	result, err := NewUnstartedResultWithObjectStoreProfile(status, profile)
	if err != nil {
		return Result{}, err
	}
	return withSpecialist(result, specialist), nil
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
	result = withSpecialist(result, s.specialist)
	w = &result.wire
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
	// A run that failed before it recorded its change model reviewed nothing and
	// carries no style advice, as it carries no findings. An investigation result
	// takes the advice now, so every retained diagnostic carries it; a direct
	// result takes it last, after finding guidance chose version 4.
	var style StyleAdvice
	if task, ok := state.Task("change"); ok && task.Status() == controlplane.TaskRuntimeSucceeded {
		style = s.styleAdvice(ctx, p.Plan().Scope(), task.OutputIdentity())
	}
	if s.investigation != nil {
		result = withStyleAdvice(result, style)
	}
	if state.Status() == controlplane.ReviewRunFailed && s.routeFailures != nil && s.routeFailures.saw(gateway.RouteFailureOutputExhausted) {
		w.FailureDetail = FailureDetailModelOutputExhausted
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
			// The reported specialist must be the one actually bound into the
			// recorded generation context, not only the session option.
			recorded, hasSpecialist, err := review.RecordedContextSpecialist(contextArtifact.Payload())
			if err != nil || hasSpecialist == s.specialist.IsZero() || hasSpecialist && recorded != s.specialist {
				return Result{}, ErrInvalidResult
			}
			agentConfiguration, instructionLike, err := review.ContextRiskSourceCounts(contextArtifact.Payload())
			if err != nil {
				return Result{}, ErrInvalidResult
			}
			w.AgentConfigurationSources, w.InstructionLikeSources = agentConfiguration, instructionLike
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
			if dropped := generation.Candidates().RepositoryContextAnchorOmittedCount(); dropped > 0 {
				w.RepositoryContextAnchorOmitted = dropped
				w.Limitations = append(w.Limitations, repositoryContextAnchorOmittedLimitation)
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
			verification, err = modelhandler.ParseStoredVerificationResultArtifact(ctx, s.store, s.options.Clock.Now(), verificationArtifact, generationArtifact, inputArtifact, contextArtifact)
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
	if hasVerification {
		if omitted := verification.VerificationContext().SourceCoverage().InstructionContextOmittedCount(); omitted > 0 {
			w.InstructionContextOmitted = omitted
			w.Limitations = append(append([]string{}, w.Limitations...), instructionContextOmittedLimitation)
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
		// Read only the actual readiness artifact and check against the same core
		// contract. This does not create a second review or publication algorithm.
		var recorded struct {
			Contract             string          `json:"contract"`
			Version              int             `json:"schema_version"`
			Readiness            string          `json:"readiness_identity"`
			VerificationArtifact string          `json:"verification_artifact_identity"`
			VerificationResult   string          `json:"verification_result_identity"`
			Policy               string          `json:"publication_policy_identity"`
			Status               string          `json:"status"`
			ContentScan          json.RawMessage `json:"content_scan"`
		}
		if json.Unmarshal(readinessArtifact.Payload(), &recorded) != nil || recorded.Contract != "open-trestle/publication-readiness-result" || recorded.Version != 2 {
			return Result{}, ErrInvalidResult
		}
		selection, err := review.SelectPublicationFindings(s.options.Policy.Publication(), verification.IndependentReceipt(), verification.VerifiedFindings())
		if err != nil {
			return Result{}, ErrInvalidResult
		}
		var contentScan review.PublicationContentScanReceipt
		if selection.Status() == review.PublicationAdvisoryReady {
			contentScan, err = review.ParsePublicationContentScanReceipt(recorded.ContentScan)
			if err != nil {
				return Result{}, ErrInvalidResult
			}
		} else if !bytes.Equal(recorded.ContentScan, []byte("null")) {
			return Result{}, ErrInvalidResult
		}
		readiness, err := review.EvaluatePublicationReadiness(s.options.Policy.Publication(), verification.IndependentReceipt(), verification.VerifiedFindings(), verification.VerificationContext(), selection, contentScan)
		if err != nil || recorded.Readiness != readiness.Identity() || recorded.VerificationArtifact != verificationArtifact.Identity() || recorded.VerificationResult != verification.Identity() || recorded.Policy != s.options.Policy.Publication().Identity() || recorded.Status != readiness.Status().String() {
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
		if s.investigation == nil {
			if result, err = withFindingGuidance(result, verification.VerifiedFindings()); err != nil {
				return Result{}, err
			}
			w = &result.wire
		}
		w.Readiness = recorded.Readiness
		if state.Status() != controlplane.ReviewRunSucceeded {
			return Result{}, ErrInvalidResult
		}
		w.Status, w.CI = localReadinessDisposition(uint32(set.VerifiedCount()), set.SourceOmittedCount(), uint32(set.InconclusiveCount()), uint32(set.CandidateCount()))
	}
	if state.Status() == controlplane.ReviewRunSucceeded && !hasReadiness {
		return Result{}, ErrInvalidResult
	}
	if s.investigation == nil {
		result = withStyleAdvice(result, style)
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
	if s != nil {
		result = withSpecialist(result, s.specialist)
	}
	result.wire.RunStatus = "unknown"
	result.wire.Limitations = append(result.wire.Limitations, "execution_state_unavailable", "unknown_final_usage")
	return result
}
func localReadinessDisposition(verified, omitted, inconclusive, candidates uint32) (string, string) {
	if verified > 0 {
		return "findings", "blocked"
	}
	if omitted > 0 || inconclusive > 0 {
		return "incomplete", "inconclusive"
	}
	if candidates == 0 {
		return "no_candidates", "inconclusive"
	}
	return "incomplete", "inconclusive"
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
	if hasBaseSideFinding(r.diagnostics) {
		return ErrBaseSideFindingUnsupported
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
	if class, task, detail, hint := r.failureSummary(); class != "" {
		fmt.Fprintf(&buffer, "failure: %s\n", FailureLine(class, task, detail))
		if hint != "" {
			fmt.Fprintf(&buffer, "hint: %s\n", hint)
		}
	}
	if r.wire.Specialist != nil {
		fmt.Fprintf(&buffer, "specialist profile: %s\n", r.wire.Specialist.ProfileID)
	}
	guidance := make(map[string]findingGuidanceWire, len(r.wire.Guidance))
	for _, value := range r.wire.Guidance {
		guidance[value.FindingIdentity] = value
	}
	for _, finding := range r.diagnostics.Findings() {
		fmt.Fprintf(&buffer, "finding: %s %s\nsource: %s:%d-%d\nmessage: %s\nevidence: %s\n", finding.Severity().String(), finding.Title(), finding.Path(), finding.StartLine(), finding.EndLine(), finding.Message(), strings.Join(finding.EvidenceIDs(), ", "))
		if value, ok := guidance[finding.SourceIdentity()]; ok {
			fmt.Fprintf(&buffer, "category: %s\n", value.Category)
			if value.Fix != "" {
				// Fix text is unverified model guidance; it is printed, never applied.
				fmt.Fprintf(&buffer, "fix: %s\n", value.Fix)
			}
		}
	}
	if r.diagnostics.VerifiedSetIdentity() != "" {
		fmt.Fprintf(&buffer, "coverage: candidates=%d verified=%d rejected=%d inconclusive=%d\n", r.diagnostics.CandidateCount(), r.diagnostics.VerifiedCount(), r.diagnostics.RejectedCount(), r.diagnostics.InconclusiveCount())
	}
	if r.diagnostics.VerificationContextIdentity() != "" {
		fmt.Fprintf(&buffer, "source coverage: analyzed=%d selected=%d omitted=%d\n", r.diagnostics.SourceAnalyzedCount(), r.diagnostics.SourceSelectedCount(), r.diagnostics.SourceOmittedCount())
		for _, omission := range r.diagnostics.OmissionSummaries() {
			fmt.Fprintf(&buffer, "source omission: %s=%d\n", omission.Reason().String(), omission.Count())
		}
	}
	if r.wire.InstructionContextOmitted > 0 {
		fmt.Fprintf(&buffer, "instruction context omitted: %d (advisory repository instructions; not source coverage)\n", r.wire.InstructionContextOmitted)
	}
	if r.wire.RepositoryContextAnchorOmitted > 0 {
		fmt.Fprintf(&buffer, "candidates omitted: %d located in repository instruction context\n", r.wire.RepositoryContextAnchorOmitted)
	}
	if r.wire.AgentConfigurationSources > 0 || r.wire.InstructionLikeSources > 0 {
		// Reviewed AI material is untrusted data and is reviewed as code.
		fmt.Fprintf(&buffer, "ai material in review context: agent_configuration=%d instruction_like=%d (reviewed as code, never followed)\n", r.wire.AgentConfigurationSources, r.wire.InstructionLikeSources)
	}
	for _, line := range r.wire.StyleAdvice.Lines() {
		buffer.WriteString(line)
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
