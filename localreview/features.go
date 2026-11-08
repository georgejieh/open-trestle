package localreview

import (
	"context"
	"errors"

	"github.com/georgejieh/open-trestle/agentprofile"
	"github.com/georgejieh/open-trestle/controlplane"
	analysishandler "github.com/georgejieh/open-trestle/handlers/analysis"
	changehandler "github.com/georgejieh/open-trestle/handlers/change"
	"github.com/georgejieh/open-trestle/runtimecatalog"
)

// ErrChangeFeaturesUnavailable means the run did not record a change model and
// deterministic analysis that specialist routing can be derived from.
var ErrChangeFeaturesUnavailable = errors.New("local review change features unavailable")

// ChangeFeatures derives agent-profile router input from the change-model and
// deterministic-analysis artifacts this session already recorded for prepared.
// It is read-only: it replays the run journal and reads stored artifacts, and
// starts no task, model call or source read. It is available only for a direct
// (non-investigation) run whose change and analysis tasks succeeded, and only
// while the session is open and idle.
//
// The change model records changed head-line ranges, not deleted-line counts,
// so AddedLines is the number of changed head lines and DeletedLines is zero.
// No repository configuration file or change description is inspected.
func (s *Session) ChangeFeatures(ctx context.Context, prepared runtimecatalog.PreparedReviewRun) (agentprofile.ChangeFeatures, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || prepared.Validate() != nil {
		return agentprofile.ChangeFeatures{}, ErrChangeFeaturesUnavailable
	}
	s.mu.Lock()
	unavailable := s.closing || s.closed || s.active || s.investigation != nil || !s.issued[prepared.RequestIdentity()]
	s.mu.Unlock()
	if unavailable {
		return agentprofile.ChangeFeatures{}, ErrChangeFeaturesUnavailable
	}
	scope := prepared.Plan().Scope()
	plan, state, err := s.coordinator.Resume(ctx, scope)
	if err != nil || plan.Identity() != prepared.Plan().Identity() {
		return agentprofile.ChangeFeatures{}, ErrChangeFeaturesUnavailable
	}
	now := s.options.Clock.Now()
	output := func(key string) (string, bool) {
		task, ok := state.Task(key)
		if !ok || task.Status() != controlplane.TaskRuntimeSucceeded {
			return "", false
		}
		return task.OutputIdentity(), true
	}
	changeID, hasChange := output("change")
	analysisID, hasAnalysis := output("analysis")
	if !hasChange || !hasAnalysis {
		return agentprofile.ChangeFeatures{}, ErrChangeFeaturesUnavailable
	}
	changeArtifact, err := s.store.Get(ctx, scope, changeID, now)
	if err != nil {
		return agentprofile.ChangeFeatures{}, ErrChangeFeaturesUnavailable
	}
	baseID, headID, err := changehandler.ResultArtifactReferences(changeArtifact)
	if err != nil {
		return agentprofile.ChangeFeatures{}, ErrChangeFeaturesUnavailable
	}
	baseArtifact, err := s.store.Get(ctx, scope, baseID, now)
	if err != nil {
		return agentprofile.ChangeFeatures{}, ErrChangeFeaturesUnavailable
	}
	headArtifact, err := s.store.Get(ctx, scope, headID, now)
	if err != nil {
		return agentprofile.ChangeFeatures{}, ErrChangeFeaturesUnavailable
	}
	change, err := changehandler.ParseResultArtifact(changeArtifact, baseArtifact, headArtifact)
	if err != nil {
		return agentprofile.ChangeFeatures{}, ErrChangeFeaturesUnavailable
	}
	analysisArtifact, err := s.store.Get(ctx, scope, analysisID, now)
	if err != nil {
		return agentprofile.ChangeFeatures{}, ErrChangeFeaturesUnavailable
	}
	analysis, err := analysishandler.ParseResultArtifact(analysisArtifact, changeArtifact, baseArtifact, headArtifact)
	if err != nil || analysis.ChangeIdentity() != change.Identity() {
		return agentprofile.ChangeFeatures{}, ErrChangeFeaturesUnavailable
	}
	files := make([]agentprofile.ChangedFileSpec, 0, len(change.Entries()))
	for _, entry := range change.Entries() {
		var added uint64
		for _, lines := range entry.Ranges() {
			if lines.EndLine() >= lines.StartLine() && lines.StartLine() > 0 {
				added += uint64(lines.EndLine() - lines.StartLine() + 1)
			}
		}
		if added > 1<<24 {
			added = 1 << 24
		}
		files = append(files, agentprofile.ChangedFileSpec{Path: entry.Path(), AddedLines: uint32(added)})
	}
	changeIdentity := change.Identity()
	if !lowerHexDigest(changeIdentity) {
		changeIdentity = ""
	}
	features, err := agentprofile.ChangeFeaturesFromFileSpecs(changeIdentity, files, analysis.SemanticImpact(), agentprofile.AnalysisHints{})
	if err != nil {
		return agentprofile.ChangeFeatures{}, ErrChangeFeaturesUnavailable
	}
	return features, nil
}

func lowerHexDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for index := 0; index < len(value); index++ {
		if c := value[index]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
