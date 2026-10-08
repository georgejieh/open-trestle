package context

import (
	"bytes"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/internal/review"
)

var ErrInvalidContextAbstention = errors.New("invalid context abstention")

// contextAbstentionWire carries metadata only. No source bytes, model request, or finding.
type contextAbstentionWire struct {
	Contract             string                      `json:"contract"`
	SchemaVersion        int                         `json:"schema_version"`
	ReviewScopeIdentity  string                      `json:"review_scope_identity"`
	PlanIdentity         string                      `json:"plan_identity"`
	TaskIdentity         string                      `json:"task_identity"`
	HeadSnapshotIdentity string                      `json:"head_snapshot_identity"`
	Reason               string                      `json:"reason"`
	Failure              string                      `json:"failure"`
	SourceCoverage       contextAbstentionCoverage   `json:"source_coverage"`
	SourceOmissions      []contextAbstentionOmission `json:"source_omissions"`
}
type contextAbstentionCoverage struct {
	Analyzed int `json:"analyzed"`
	Selected int `json:"selected"`
	Omitted  int `json:"omitted"`
}
type contextAbstentionOmission struct {
	Path      string `json:"path"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
	Reason    string `json:"reason"`
	Count     uint32 `json:"count"`
}

func newContextAbstentionArtifact(request controlplane.TaskExecutionRequest, analysis, memory, change, head artifact.Artifact, headIdentity string, omissions []review.ContextSourceOmission, reason string, failure controlplane.RunFailure, at, expires time.Time) (artifact.Artifact, error) {
	if request.Validate() != nil || request.Task().Kind() != controlplane.TaskAssembleContext || !validDigest(headIdentity) || (reason != "all_sources_omitted" && reason != "packet_budget_zero_selection" && reason != "unsupported_language" && reason != "no_source_changes") || (failure != controlplane.RunFailurePolicy && failure != controlplane.RunFailureResourceLimit) || analysis.Scope().Identity() != request.Plan().Scope().Identity() || memory.Scope().Identity() != request.Plan().Scope().Identity() || change.Scope().Identity() != request.Plan().Scope().Identity() || head.Scope().Identity() != request.Plan().Scope().Identity() || analysis.Identity() == "" || memory.Identity() == "" || change.Identity() == "" || head.Identity() == "" {
		return artifact.Artifact{}, ErrInvalidContextAbstention
	}
	encodedOmissions, total, err := canonicalContextAbstentionOmissions(omissions)
	if err != nil || (total == 0) != (reason == "no_source_changes") {
		return artifact.Artifact{}, ErrInvalidContextAbstention
	}
	wire := contextAbstentionWire{Contract: "open-trestle/context-abstention", SchemaVersion: 1, ReviewScopeIdentity: request.Plan().Scope().Identity(), PlanIdentity: request.Plan().Identity(), TaskIdentity: request.Task().Identity(), HeadSnapshotIdentity: headIdentity, Reason: reason, Failure: failure.String(), SourceCoverage: contextAbstentionCoverage{Analyzed: total, Selected: 0, Omitted: total}, SourceOmissions: encodedOmissions}
	payload, err := json.Marshal(wire)
	if err != nil || len(payload) > 8<<20 {
		return artifact.Artifact{}, ErrInvalidContextAbstention
	}
	provenance := []string{analysis.Identity(), memory.Identity(), change.Identity(), head.Identity()}
	sort.Strings(provenance)
	result, err := artifact.New(request.Plan().Scope(), artifact.KindDeterministicEvidence, "application/json", analysis.Classification(), artifact.OriginDeterministicTool, analysis.Protection(), provenance, payload, at, expires)
	if err != nil {
		return artifact.Artifact{}, err
	}
	if validateContextAbstentionArtifact(result, request) != nil {
		return artifact.Artifact{}, ErrInvalidContextAbstention
	}
	return result, nil
}

func canonicalContextAbstentionOmissions(omissions []review.ContextSourceOmission) ([]contextAbstentionOmission, int, error) {
	if len(omissions) > 16384 {
		return nil, 0, ErrInvalidContextAbstention
	}
	values := make([]contextAbstentionOmission, len(omissions))
	for i, o := range omissions {
		if o.Validate() != nil {
			return nil, 0, ErrInvalidContextAbstention
		}
		values[i] = contextAbstentionOmission{Path: o.Path(), StartLine: o.StartLine(), EndLine: o.EndLine(), Reason: o.Reason(), Count: o.Count()}
	}
	sort.Slice(values, func(i, j int) bool { return contextAbstentionOmissionLess(values[i], values[j]) })
	compact := values[:0]
	total := 0
	for _, value := range values {
		if len(compact) > 0 && !contextAbstentionOmissionLess(compact[len(compact)-1], value) {
			if compact[len(compact)-1].Count > 32768-value.Count {
				return nil, 0, ErrInvalidContextAbstention
			}
			compact[len(compact)-1].Count += value.Count
		} else {
			compact = append(compact, value)
		}
		total += int(value.Count)
		if total > 65536 {
			return nil, 0, ErrInvalidContextAbstention
		}
	}
	return compact, total, nil
}
func contextAbstentionOmissionLess(a, b contextAbstentionOmission) bool {
	if a.Path != b.Path {
		return a.Path < b.Path
	}
	if a.StartLine != b.StartLine {
		return a.StartLine < b.StartLine
	}
	if a.EndLine != b.EndLine {
		return a.EndLine < b.EndLine
	}
	return a.Reason < b.Reason
}

// validateContextAbstentionArtifact refuses a wrong kind, scope, payload, task, or noncanonical count.
func validateContextAbstentionArtifact(value artifact.Artifact, request controlplane.TaskExecutionRequest) error {
	if request.Validate() != nil {
		return ErrInvalidContextAbstention
	}
	return validateContextAbstentionForTask(value, request.Plan(), request.Task())
}

func validateContextAbstentionForTask(value artifact.Artifact, plan controlplane.ReviewRunPlan, task controlplane.TaskDefinition) error {
	if value.Validate() != nil || plan.Validate() != nil || task.Validate() != nil || value.Kind() != artifact.KindDeterministicEvidence || value.Origin() != artifact.OriginDeterministicTool || value.Scope().Identity() != plan.Scope().Identity() || task.Kind() != controlplane.TaskAssembleContext {
		return ErrInvalidContextAbstention
	}
	payload := value.Payload()
	if len(payload) > 8<<20 {
		return ErrInvalidContextAbstention
	}
	var wire contextAbstentionWire
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&wire) != nil {
		return ErrInvalidContextAbstention
	}
	canonical, err := json.Marshal(wire)
	if err != nil || !bytes.Equal(payload, canonical) || wire.Contract != "open-trestle/context-abstention" || wire.SchemaVersion != 1 || wire.ReviewScopeIdentity != plan.Scope().Identity() || wire.PlanIdentity != plan.Identity() || wire.TaskIdentity != task.Identity() || !validDigest(wire.HeadSnapshotIdentity) || wire.SourceCoverage.Selected != 0 || wire.SourceCoverage.Analyzed != wire.SourceCoverage.Omitted || wire.SourceCoverage.Omitted < 0 || wire.SourceCoverage.Omitted > 65536 || len(wire.SourceOmissions) > 16384 || (wire.SourceCoverage.Omitted == 0) != (wire.Reason == "no_source_changes") {
		return ErrInvalidContextAbstention
	}
	if (wire.Reason != "all_sources_omitted" && wire.Reason != "packet_budget_zero_selection" && wire.Reason != "unsupported_language" && wire.Reason != "no_source_changes") || (wire.Failure != controlplane.RunFailurePolicy.String() && wire.Failure != controlplane.RunFailureResourceLimit.String()) {
		return ErrInvalidContextAbstention
	}
	total := 0
	var previous contextAbstentionOmission
	for i, o := range wire.SourceOmissions {
		if _, err := review.NewCountedContextSourceOmission(o.Path, o.StartLine, o.EndLine, o.Reason, o.Count); err != nil || i > 0 && !contextAbstentionOmissionLess(previous, o) {
			return ErrInvalidContextAbstention
		}
		total += int(o.Count)
		previous = o
	}
	if total != wire.SourceCoverage.Omitted {
		return ErrInvalidContextAbstention
	}
	return nil
}
