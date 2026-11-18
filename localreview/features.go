package localreview

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/agentprofile"
	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	analysishandler "github.com/georgejieh/open-trestle/handlers/analysis"
	changehandler "github.com/georgejieh/open-trestle/handlers/change"
	modelhandler "github.com/georgejieh/open-trestle/handlers/model"
	sourcehandler "github.com/georgejieh/open-trestle/handlers/source"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/runtimecatalog"
	"github.com/georgejieh/open-trestle/semanticimpact"
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
// files (see baseStyleConfigFiles). Files are added in path order while the
// change-features document stays within agentprofile.MaxChangeFeaturesBytes; a
// file that does not fit is skipped whole. unreadStyleConfig lists, in path
// order, every recognized base style configuration file that was not supplied:
// over a file bound, not valid UTF-8, or beyond the document bound. Intent is
// declared when the run's generation context carried commit messages; only
// that presence is recorded, never their text.
func (s *Session) ChangeFeatures(ctx context.Context, prepared runtimecatalog.PreparedReviewRun) (features agentprofile.ChangeFeatures, unreadStyleConfig []string, err error) {
	if s == nil || ctx == nil || ctx.Err() != nil || prepared.Validate() != nil {
		return agentprofile.ChangeFeatures{}, nil, ErrChangeFeaturesUnavailable
	}
	s.mu.Lock()
	unavailable := s.closing || s.closed || s.active || s.investigation != nil || !s.issued[prepared.RequestIdentity()]
	s.mu.Unlock()
	if unavailable {
		return agentprofile.ChangeFeatures{}, nil, ErrChangeFeaturesUnavailable
	}
	scope := prepared.Plan().Scope()
	plan, state, err := s.coordinator.Resume(ctx, scope)
	if err != nil || plan.Identity() != prepared.Plan().Identity() {
		return agentprofile.ChangeFeatures{}, nil, ErrChangeFeaturesUnavailable
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
		return agentprofile.ChangeFeatures{}, nil, ErrChangeFeaturesUnavailable
	}
	recorded, err := s.readRecordedChange(ctx, scope, changeID, now)
	if err != nil {
		return agentprofile.ChangeFeatures{}, nil, ErrChangeFeaturesUnavailable
	}
	input, err := s.readRoutingInput(ctx, scope, recorded, analysisID, now)
	if err != nil {
		return agentprofile.ChangeFeatures{}, nil, ErrChangeFeaturesUnavailable
	}
	if contextID, hasContext := output("context"); hasContext {
		if payload, ok := s.recordedContextPayload(ctx, scope, contextID, now); ok {
			input.intent = recordedIntent(payload)
			if manifest, err := review.ContextManifestOf(payload); err == nil && manifest.Present {
				input.fanOut = uint32(min(manifest.Dependents, 1<<24))
			}
		}
	}
	configFiles, unread, err := s.baseStyleConfigFiles(ctx, scope, recorded.base, now)
	if err != nil {
		return agentprofile.ChangeFeatures{}, nil, ErrChangeFeaturesUnavailable
	}
	fitted, skipped, err := input.fitConfigFiles(configFiles)
	if err != nil {
		return agentprofile.ChangeFeatures{}, nil, ErrChangeFeaturesUnavailable
	}
	features, err = input.features(fitted)
	if err != nil {
		return agentprofile.ChangeFeatures{}, nil, ErrChangeFeaturesUnavailable
	}
	return features, mergeUnread(unread, skipped), nil
}

// routingInput is what routing's change features derive from: the recorded
// change model's changed files and the analysis's semantic-impact profile.
type routingInput struct {
	changeIdentity string
	files          []agentprofile.ChangedFileSpec
	impact         semanticimpact.Profile
	// intent is whether the run's context carried commit messages.
	intent agentprofile.IntentSpec
	// fanOut counts the direct dependents of the changed definitions that
	// the run's context manifest records.
	fanOut uint32
}

// readRoutingInput reads the recorded analysis for a recorded change.
func (s *Session) readRoutingInput(ctx context.Context, scope audit.ReviewScope, recorded recordedChange, analysisID string, at time.Time) (routingInput, error) {
	analysisArtifact, err := s.store.Get(ctx, scope, analysisID, at)
	if err != nil {
		return routingInput{}, err
	}
	analysis, err := analysishandler.ParseResultArtifact(analysisArtifact, recorded.artifact, recorded.base, recorded.head)
	if err != nil {
		return routingInput{}, err
	}
	if analysis.ChangeIdentity() != recorded.change.Identity() {
		return routingInput{}, ErrChangeFeaturesUnavailable
	}
	input := routingInput{changeIdentity: recorded.change.Identity(), impact: analysis.SemanticImpact()}
	if !lowerHexDigest(input.changeIdentity) {
		input.changeIdentity = ""
	}
	for _, entry := range recorded.change.Entries() {
		var added uint64
		for _, lines := range entry.Ranges() {
			if lines.EndLine() >= lines.StartLine() && lines.StartLine() > 0 {
				added += uint64(lines.EndLine() - lines.StartLine() + 1)
			}
		}
		if added > 1<<24 {
			added = 1 << 24
		}
		input.files = append(input.files, agentprofile.ChangedFileSpec{Path: entry.Path(), AddedLines: uint32(added)})
	}
	return input, nil
}

func (r routingInput) features(configFiles []agentprofile.ConfigFile) (agentprofile.ChangeFeatures, error) {
	return agentprofile.ChangeFeaturesFromFileSpecs(r.changeIdentity, r.files, r.impact, agentprofile.AnalysisHints{ConfigFiles: configFiles, Intent: r.intent, ReferenceFanOut: r.fanOut})
}

// recordedContextPayload reads the run's recorded generation context
// through the context task's output.
func (s *Session) recordedContextPayload(ctx context.Context, scope audit.ReviewScope, contextOutput string, at time.Time) ([]byte, bool) {
	inputArtifact, err := s.store.Get(ctx, scope, contextOutput, at)
	if err != nil {
		return nil, false
	}
	input, err := modelhandler.ParseGenerationInput(inputArtifact.Payload())
	if err != nil {
		return nil, false
	}
	contextArtifact, err := s.store.Get(ctx, scope, input.ContextArtifactIdentity(), at)
	if err != nil || contextArtifact.Kind() != artifact.KindContextPacket || contextArtifact.PayloadDigest() != input.ContextIdentity() {
		return nil, false
	}
	return contextArtifact.Payload(), true
}

// recordedIntent reports whether a recorded generation context carried a
// stated intent with at least one commit: declared change intent for the
// drift_auditor's intent condition. It reads presence, never the text.
func recordedIntent(payload []byte) agentprofile.IntentSpec {
	summary, err := review.ContextStatedIntent(payload)
	if err != nil || !summary.Present || summary.Commits+summary.CommitsOmitted == 0 {
		return agentprofile.IntentSpec{}
	}
	return agentprofile.IntentSpec{DescriptionPresent: true}
}

// fitConfigFiles returns the configuration files routing's change-features
// document carries, in path order, and the paths of those it skips. It fails
// when routing has no features at all.
func (r routingInput) fitConfigFiles(configFiles []agentprofile.ConfigFile) ([]agentprofile.ConfigFile, []string, error) {
	withoutConfig, err := r.features(nil)
	if err != nil {
		return nil, nil, err
	}
	fitted, skipped := agentprofile.FitConfigFiles(withoutConfig, configFiles)
	return fitted, skipped, nil
}

// mergeUnread returns every unread path in path order.
func mergeUnread(unread, skipped []string) []string {
	merged := append(append([]string(nil), unread...), skipped...)
	sort.Strings(merged)
	return merged
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
// task's recorded output and analysisID the analysis task's, or empty when no
// analysis was recorded. When routing has change features, the advice uses
// exactly the configuration files routing's document carries, so a file
// routing skips is unread here too; without them, every readable file is used.
// When the change model, its snapshots, the analysis or a base style
// configuration file cannot be read back, the advice is explicitly
// unavailable, never silently absent. It never affects the review's status.
func (s *Session) styleAdvice(ctx context.Context, scope audit.ReviewScope, changeID, analysisID string) StyleAdvice {
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
	if analysisID != "" {
		input, err := s.readRoutingInput(ctx, scope, recorded, analysisID, now)
		if err != nil {
			return unavailable
		}
		if fitted, skipped, err := input.fitConfigFiles(configFiles); err == nil {
			configFiles, unread = fitted, mergeUnread(unread, skipped)
		}
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
	return advice.Record(len(unread))
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
