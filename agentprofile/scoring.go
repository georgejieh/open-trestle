package agentprofile

// This file is the single tuning surface for routing difficulty. Owners tune
// difficultyWeights (how much each signal contributes) and
// profileTierThresholds (where each profile switches tier). Every change here
// changes profile identities and therefore the catalog identity, so a tuned
// router is always distinguishable from the packaged one.
//
// Scoring is integer-only and deterministic:
//
//	points(signal) = min(Cap, (Observed / Divisor) * Points)
//	score          = sum(points)
//
// Integer division floors, so a signal contributes nothing until Observed
// reaches Divisor.

// DifficultySignal identifies one explainable scoring input.
type DifficultySignal string

// Difficulty signals in breakdown order.
const (
	DifficultyChangedLines     DifficultySignal = "changed_lines"
	DifficultyChangedFiles     DifficultySignal = "changed_files"
	DifficultyLanguages        DifficultySignal = "languages"
	DifficultyPublicAPIChanges DifficultySignal = "public_api_changes"
	DifficultyReferenceFanOut  DifficultySignal = "reference_fan_out"
	DifficultySecurityPaths    DifficultySignal = "security_sensitive_signals"
	DifficultyConcurrency      DifficultySignal = "concurrency"
	DifficultyTestAbsence      DifficultySignal = "test_absence"
	DifficultyCoverageGap      DifficultySignal = "coverage_gap"
)

type difficultyWeight struct {
	signal  DifficultySignal
	divisor uint64
	points  uint64
	cap     uint64
	meaning string
}

// difficultyWeights is the scoring table. Observed values are measured over
// the files that activated the profile (its scope), except public API
// changes, reference fan-out, and coverage gaps, which are change-wide.
var difficultyWeights = []difficultyWeight{
	{DifficultyChangedLines, 25, 1, 20, "added plus deleted lines in scope; 1 point per 25 lines"},
	{DifficultyChangedFiles, 1, 2, 16, "files in scope beyond the first; 2 points each"},
	{DifficultyLanguages, 1, 4, 8, "distinct languages in scope beyond the first; 4 points each"},
	{DifficultyPublicAPIChanges, 1, 5, 20, "changed exported declarations (change-wide); 5 points each"},
	{DifficultyReferenceFanOut, 4, 1, 15, "references to changed declarations (change-wide); 1 point per 4"},
	{DifficultySecurityPaths, 1, 6, 18, "distinct security signal kinds in scope (auth, crypto, http, exec, sql, webhook, ...); 6 points each"},
	{DifficultyConcurrency, 1, 4, 12, "files in scope with a concurrency signal; 4 points each"},
	{DifficultyTestAbsence, 1, 6, 6, "1 when scope has source changes and the change touches no test file"},
	{DifficultyCoverageGap, 20, 1, 10, "uncovered changed lines (change-wide); 1 point per 20; 0 when coverage is unknown"},
}

// maxDifficultyScore is the sum of all caps.
const maxDifficultyScore = 125

// defaultTierThresholds applies to profiles without an override.
var defaultTierThresholds = TierThresholds{Standard: 15, Deep: 45}

// profileTierThresholds declares where each model-calling profile switches
// tier. Lower thresholds escalate sooner.
var profileTierThresholds = map[ProfileID]TierThresholds{
	ProfileBackend:          defaultTierThresholds,
	ProfileBugHunter:        {Standard: 12, Deep: 40},
	ProfileDriftAuditor:     {Standard: 20, Deep: 60},
	ProfileFrontend:         defaultTierThresholds,
	ProfileKnowledgeGraph:   {Standard: 25, Deep: 70},
	ProfileSecurityProbe:    {Standard: 8, Deep: 30},
	ProfileStyleConformance: {Standard: 30, Deep: 80},
	ProfileTestAuthor:       defaultTierThresholds,
}

// DifficultyContribution is one explainable row of a difficulty score.
type DifficultyContribution struct {
	Signal   DifficultySignal
	Observed uint64
	Points   uint64
	Cap      uint64
	Note     string
}

// Difficulty is a profile's score with its per-signal breakdown.
type Difficulty struct {
	Score         uint64
	Contributions []DifficultyContribution
}

// scopeMeasures are the raw observations for one profile scope.
type scopeMeasures struct {
	changedLines     uint64
	files            uint64
	languages        uint64
	securityKinds    uint64
	concurrencyFiles uint64
	scopeHasSource   bool
}

// scoreDifficulty computes the explainable difficulty for one profile scope.
func scoreDifficulty(scope []changedFile, features ChangeFeatures) Difficulty {
	measures := measureScope(scope)
	testAbsent := uint64(0)
	if measures.scopeHasSource && !features.hasClass(FileClassTest) {
		testAbsent = 1
	}
	observed := map[DifficultySignal]uint64{
		DifficultyChangedLines:     measures.changedLines,
		DifficultyChangedFiles:     saturatingSub(measures.files, 1),
		DifficultyLanguages:        saturatingSub(measures.languages, 1),
		DifficultyPublicAPIChanges: uint64(features.publicAPIChanges),
		DifficultyReferenceFanOut:  uint64(features.referenceFanOut),
		DifficultySecurityPaths:    measures.securityKinds,
		DifficultyConcurrency:      measures.concurrencyFiles,
		DifficultyTestAbsence:      testAbsent,
		DifficultyCoverageGap:      uint64(features.uncoveredChangedLines),
	}
	difficulty := Difficulty{Contributions: make([]DifficultyContribution, 0, len(difficultyWeights))}
	for _, weight := range difficultyWeights {
		value := observed[weight.signal]
		points := (value / weight.divisor) * weight.points
		if points > weight.cap {
			points = weight.cap
		}
		note := weight.meaning
		if weight.signal == DifficultyCoverageGap && !features.coverageKnown {
			value, points, note = 0, 0, "coverage unknown; contributes 0 points"
		}
		difficulty.Score += points
		difficulty.Contributions = append(difficulty.Contributions, DifficultyContribution{
			Signal: weight.signal, Observed: value, Points: points, Cap: weight.cap, Note: note,
		})
	}
	return difficulty
}

func measureScope(scope []changedFile) scopeMeasures {
	var measures scopeMeasures
	languages := map[Language]struct{}{}
	security := map[Signal]struct{}{}
	for _, file := range scope {
		measures.files++
		measures.changedLines += uint64(file.added) + uint64(file.deleted)
		if file.hasLanguage {
			languages[file.language] = struct{}{}
		}
		if file.class == FileClassSource {
			measures.scopeHasSource = true
		}
		for _, signal := range file.signals {
			if signal.IsSecurity() {
				security[signal] = struct{}{}
			}
			if signal == SignalConcurrency {
				measures.concurrencyFiles++
			}
		}
	}
	measures.languages = uint64(len(languages))
	measures.securityKinds = uint64(len(security))
	return measures
}

func saturatingSub(value, subtract uint64) uint64 {
	if value < subtract {
		return 0
	}
	return value - subtract
}

// tierForScore maps a score to a tier using the declared thresholds.
func tierForScore(score uint64, thresholds TierThresholds) Tier {
	switch {
	case score >= uint64(thresholds.Deep):
		return TierDeep
	case score >= uint64(thresholds.Standard):
		return TierStandard
	default:
		return TierLight
	}
}
