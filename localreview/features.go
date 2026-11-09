package localreview

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/agentprofile"
	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	analysishandler "github.com/georgejieh/open-trestle/handlers/analysis"
	changehandler "github.com/georgejieh/open-trestle/handlers/change"
	sourcehandler "github.com/georgejieh/open-trestle/handlers/source"
	"github.com/georgejieh/open-trestle/internal/evidence"
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
// Declared style comes from the base tree's root-level style configuration
// files (see baseStyleConfigFiles). No change description is inspected.
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
	recorded, err := s.readRecordedChange(ctx, scope, changeID, now)
	if err != nil {
		return agentprofile.ChangeFeatures{}, ErrChangeFeaturesUnavailable
	}
	change, baseArtifact := recorded.change, recorded.base
	analysisArtifact, err := s.store.Get(ctx, scope, analysisID, now)
	if err != nil {
		return agentprofile.ChangeFeatures{}, ErrChangeFeaturesUnavailable
	}
	analysis, err := analysishandler.ParseResultArtifact(analysisArtifact, recorded.artifact, recorded.base, recorded.head)
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
	configFiles, _, err := s.baseStyleConfigFiles(ctx, scope, baseArtifact, now)
	if err != nil {
		return agentprofile.ChangeFeatures{}, ErrChangeFeaturesUnavailable
	}
	features, err := agentprofile.ChangeFeaturesFromFileSpecs(changeIdentity, files, analysis.SemanticImpact(), agentprofile.AnalysisHints{ConfigFiles: configFiles})
	if err != nil {
		return agentprofile.ChangeFeatures{}, ErrChangeFeaturesUnavailable
	}
	return features, nil
}

// recordedChange is a change model this session recorded, with the base and
// head snapshot artifacts it binds.
type recordedChange struct {
	change               changehandler.Result
	artifact, base, head artifact.Artifact
}

func (s *Session) readRecordedChange(ctx context.Context, scope audit.ReviewScope, changeID string, at time.Time) (recordedChange, error) {
	changeArtifact, err := s.store.Get(ctx, scope, changeID, at)
	if err != nil {
		return recordedChange{}, err
	}
	baseID, headID, err := changehandler.ResultArtifactReferences(changeArtifact)
	if err != nil {
		return recordedChange{}, err
	}
	baseArtifact, err := s.store.Get(ctx, scope, baseID, at)
	if err != nil {
		return recordedChange{}, err
	}
	headArtifact, err := s.store.Get(ctx, scope, headID, at)
	if err != nil {
		return recordedChange{}, err
	}
	change, err := changehandler.ParseResultArtifact(changeArtifact, baseArtifact, headArtifact)
	if err != nil {
		return recordedChange{}, err
	}
	return recordedChange{change: change, artifact: changeArtifact, base: baseArtifact, head: headArtifact}, nil
}

// styleAdvice derives a direct review's style advice from its recorded change
// model and the style its base tree declares (see baseStyleConfigFiles).
// Removed files are not counted. A language that an unread base style
// configuration file could govern is withheld, because its declared style is
// unknown; every other language is still recommended. changeID is the change
// task's recorded output. When that change model, its snapshots or a base style
// configuration file cannot be read back, the advice is explicitly unavailable,
// never silently absent. It never affects the review's status.
func (s *Session) styleAdvice(ctx context.Context, scope audit.ReviewScope, changeID string) StyleAdvice {
	unavailable := StyleAdvice{Unavailable: true}
	now := s.options.Clock.Now()
	recorded, err := s.readRecordedChange(ctx, scope, changeID, now)
	if err != nil {
		return unavailable
	}
	configFiles, unread, err := s.baseStyleConfigFiles(ctx, scope, recorded.base, now)
	if err != nil {
		return unavailable
	}
	paths := make([]string, 0, len(recorded.change.Entries()))
	for _, entry := range recorded.change.Entries() {
		if entry.Kind() != string(evidence.RepositoryFileDeltaRemoved) {
			paths = append(paths, entry.Path())
		}
	}
	advice, err := agentprofile.RecommendStyles(paths, configFiles, unread)
	if err != nil {
		return unavailable
	}
	return newStyleAdvice(advice, len(unread))
}

// baseStyleConfigFiles reads the style configuration files that declare the
// style a change is reviewed against. They come from the base tree (the
// default-branch side), never the head: a change's author controls the head, so
// a head edit to a style configuration must not decide which style that same
// change is reviewed against; the edit is reviewed as code. As for repository
// instruction files, only root-level files are read, and only names that
// declared-style detection recognizes. Content comes from the base file
// artifacts the source task already recorded, so there is no new Git read.
//
// A file larger than agentprofile.MaxConfigFileBytes, not valid UTF-8, or
// beyond the first agentprofile.MaxConfigFiles readable files (in path order) is
// skipped whole, never truncated, and its path is returned as unread, in path
// order.
func (s *Session) baseStyleConfigFiles(ctx context.Context, scope audit.ReviewScope, baseArtifact artifact.Artifact, at time.Time) (files []agentprofile.ConfigFile, unread []string, err error) {
	base, err := sourcehandler.ParseSnapshotArtifact(baseArtifact)
	if err != nil {
		return nil, nil, err
	}
	for _, reference := range styleConfigCandidates(base.Files()) {
		if len(files) == agentprofile.MaxConfigFiles || reference.SizeBytes() > agentprofile.MaxConfigFileBytes {
			unread = append(unread, reference.Path())
			continue
		}
		value, err := s.store.Get(ctx, scope, reference.ArtifactIdentity(), at)
		if err != nil {
			return nil, nil, err
		}
		file, err := sourcehandler.ParseFileArtifact(value, base, reference)
		if err != nil {
			return nil, nil, err
		}
		content := file.Content()
		if utf8.Valid(content) {
			files = append(files, agentprofile.ConfigFile{Path: reference.Path(), Content: string(content)})
		} else {
			unread = append(unread, reference.Path())
		}
		clear(content)
	}
	return files, unread, nil
}

// styleConfigCandidates returns the root-level snapshot files whose names
// declared-style detection recognizes, in snapshot (path) order. Nested copies,
// such as a subproject's own configuration, are never read.
func styleConfigCandidates(files []sourcehandler.FileReference) []sourcehandler.FileReference {
	var candidates []sourcehandler.FileReference
	for _, reference := range files {
		if !strings.Contains(reference.Path(), "/") && agentprofile.IsStyleConfigFile(reference.Path()) {
			candidates = append(candidates, reference)
		}
	}
	return candidates
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
