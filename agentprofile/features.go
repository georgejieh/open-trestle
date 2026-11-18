package agentprofile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/semanticimpact"
)

// Change-features wire contract and bounds.
const (
	ChangeFeaturesSchema  = "open-trestle/agent-profile-change-features"
	ChangeFeaturesVersion = 1

	// MaxChangeFeaturesBytes bounds one encoded change-features document.
	MaxChangeFeaturesBytes = 1 << 20

	// MaxConfigFiles bounds the configuration files one document carries for
	// declared-style detection, and MaxConfigFileBytes bounds each file's content.
	MaxConfigFiles     = 256
	MaxConfigFileBytes = 64 << 10

	maxFeatureFiles          = 4096
	maxFileSignals           = 16
	maxChangedLinesPerFile   = 1 << 24
	maxPublicAPIChanges      = 1 << 20
	maxReferenceFanOut       = 1 << 24
	maxUncoveredChangedLines = 1 << 28
	maxLinkedDocPaths        = 64
	maxSemanticGapPaths      = 4096
)

var (
	// ErrInvalidChangeFeatures identifies a malformed, oversized, or non-canonical change-features input.
	ErrInvalidChangeFeatures = errors.New("invalid change features")
	// ErrChangeFeaturesTooLarge identifies an encoded change-features document beyond MaxChangeFeaturesBytes.
	ErrChangeFeaturesTooLarge = errors.New("change features too large")
)

// deterministicSemanticLanguages lists languages the existing deterministic
// semantic analyzers (semanticimpact.AnalyzeGo, internal/analysis Go impact)
// cover. Source files in any other language are knowledge-graph gaps.
var deterministicSemanticLanguages = map[Language]struct{}{LanguageGo: {}}

// ChangedFileSpec is caller input for one changed file.
type ChangedFileSpec struct {
	Path         string
	AddedLines   uint32
	DeletedLines uint32
	// Signals carries analyzer-derived signals; path-derived signals are added deterministically.
	Signals []Signal
}

// CoverageSpec reports measured coverage of changed lines.
type CoverageSpec struct {
	UncoveredChangedLines uint32
}

// IntentSpec reports whether change intent was declared. It carries presence, never content.
type IntentSpec struct {
	DescriptionPresent bool
	LinkedDocPaths     []string
}

// ConfigFile is one repository configuration file used for declared-style detection.
// Content is optional and bounded; only exact, documented markers are inspected.
type ConfigFile struct {
	Path    string
	Content string
}

// ChangeFeaturesSpec is caller input for NewChangeFeatures.
type ChangeFeaturesSpec struct {
	Files            []ChangedFileSpec
	PublicAPIChanges uint32
	ReferenceFanOut  uint32
	// Coverage is nil when coverage was not measured; the router then records coverage as unknown.
	Coverage *CoverageSpec
	Intent   IntentSpec
	// ConfigFiles lists the repository configuration files that declare the
	// change's style. Local review supplies the base tree's root-level files.
	ConfigFiles []ConfigFile
	// SemanticGapPaths lists changed paths the deterministic analyzers could not cover.
	SemanticGapPaths []string
	// ChangeIdentity and SemanticProfileIdentity optionally bind provenance (lowercase SHA-256 hex).
	ChangeIdentity          string
	SemanticProfileIdentity string
}

type changedFile struct {
	path        string
	language    Language
	hasLanguage bool
	class       FileClass
	added       uint32
	deleted     uint32
	signals     []Signal
}

// ChangeFeatures is the immutable, content-identified router input for one change.
type ChangeFeatures struct {
	identity                string
	files                   []changedFile
	publicAPIChanges        uint32
	referenceFanOut         uint32
	coverageKnown           bool
	uncoveredChangedLines   uint32
	descriptionPresent      bool
	linkedDocPaths          []string
	configFiles             []ConfigFile
	styleIntents            []StyleIntent
	semanticGapPaths        []string
	changeIdentity          string
	semanticProfileIdentity string
}

// NewChangeFeatures validates and canonicalizes router input.
func NewChangeFeatures(spec ChangeFeaturesSpec) (ChangeFeatures, error) {
	invalid := func(detail string) (ChangeFeatures, error) {
		return ChangeFeatures{}, fmt.Errorf("%w: %s", ErrInvalidChangeFeatures, detail)
	}
	if len(spec.Files) == 0 || len(spec.Files) > maxFeatureFiles {
		return invalid("file count must be between 1 and 4096")
	}
	if spec.PublicAPIChanges > maxPublicAPIChanges || spec.ReferenceFanOut > maxReferenceFanOut {
		return invalid("public API or reference counts exceed bounds")
	}
	if spec.Coverage != nil && spec.Coverage.UncoveredChangedLines > maxUncoveredChangedLines {
		return invalid("uncovered changed lines exceed bound")
	}
	if !optionalDigest(spec.ChangeIdentity) || !optionalDigest(spec.SemanticProfileIdentity) {
		return invalid("provenance identities must be lowercase SHA-256 hex")
	}
	features := ChangeFeatures{
		publicAPIChanges:        spec.PublicAPIChanges,
		referenceFanOut:         spec.ReferenceFanOut,
		descriptionPresent:      spec.Intent.DescriptionPresent,
		changeIdentity:          spec.ChangeIdentity,
		semanticProfileIdentity: spec.SemanticProfileIdentity,
	}
	if spec.Coverage != nil {
		features.coverageKnown = true
		features.uncoveredChangedLines = spec.Coverage.UncoveredChangedLines
	}
	seen := make(map[string]struct{}, len(spec.Files))
	for _, file := range spec.Files {
		if !validRepositoryPath(file.Path) {
			return invalid("file path is not a clean relative repository path")
		}
		if _, exists := seen[file.Path]; exists {
			return invalid("duplicate file path")
		}
		seen[file.Path] = struct{}{}
		if file.AddedLines > maxChangedLinesPerFile || file.DeletedLines > maxChangedLinesPerFile {
			return invalid("changed line count exceeds bound")
		}
		if len(file.Signals) > maxFileSignals {
			return invalid("too many file signals")
		}
		language, hasLanguage := languageForPath(file.Path)
		class := classifyPath(file.Path, language, hasLanguage)
		set := map[Signal]struct{}{}
		for _, signal := range file.Signals {
			if !validSignal(signal) {
				return invalid("unknown file signal")
			}
			if _, duplicate := set[signal]; duplicate {
				return invalid("duplicate file signal")
			}
			set[signal] = struct{}{}
		}
		for _, signal := range pathSignals(file.Path, class) {
			set[signal] = struct{}{}
		}
		features.files = append(features.files, changedFile{
			path: strings.Clone(file.Path), language: language, hasLanguage: hasLanguage, class: class,
			added: file.AddedLines, deleted: file.DeletedLines, signals: sortedSignals(set),
		})
	}
	sort.Slice(features.files, func(i, j int) bool { return features.files[i].path < features.files[j].path })
	var err error
	if features.linkedDocPaths, err = canonicalPaths(spec.Intent.LinkedDocPaths, maxLinkedDocPaths); err != nil {
		return invalid("linked doc paths: " + err.Error())
	}
	if features.semanticGapPaths, err = canonicalPaths(spec.SemanticGapPaths, maxSemanticGapPaths); err != nil {
		return invalid("semantic gap paths: " + err.Error())
	}
	for _, gap := range features.semanticGapPaths {
		if _, changed := seen[gap]; !changed {
			return invalid("semantic gap path is not a changed file")
		}
	}
	if len(spec.ConfigFiles) > MaxConfigFiles {
		return invalid("too many config files")
	}
	configSeen := make(map[string]struct{}, len(spec.ConfigFiles))
	for _, config := range spec.ConfigFiles {
		if !validRepositoryPath(config.Path) {
			return invalid("config path is not a clean relative repository path")
		}
		if _, exists := configSeen[config.Path]; exists {
			return invalid("duplicate config path")
		}
		configSeen[config.Path] = struct{}{}
		if len(config.Content) > MaxConfigFileBytes || !utf8.ValidString(config.Content) {
			return invalid("config content must be valid UTF-8 within 64 KiB")
		}
		features.configFiles = append(features.configFiles, ConfigFile{Path: strings.Clone(config.Path), Content: strings.Clone(config.Content)})
	}
	sort.Slice(features.configFiles, func(i, j int) bool { return features.configFiles[i].Path < features.configFiles[j].Path })
	features.styleIntents = detectStyleIntents(features.configFiles)
	encoded, err := json.Marshal(features.wire())
	if err != nil {
		return invalid("features do not encode")
	}
	if len(encoded) > MaxChangeFeaturesBytes {
		return ChangeFeatures{}, ErrChangeFeaturesTooLarge
	}
	digest := sha256.Sum256(encoded)
	features.identity = hex.EncodeToString(digest[:])
	return features, nil
}

// FitConfigFiles selects, in the given order, the candidate configuration files
// that fit beside features in one change-features document of at most
// MaxChangeFeaturesBytes, and returns the paths of the rest. A file that does
// not fit is skipped whole, never truncated, and a later smaller file may still
// fit. features must carry no configuration files. Adding the fitted files to
// the spec that built features yields a document within the bound.
func FitConfigFiles(features ChangeFeatures, candidates []ConfigFile) (fitted []ConfigFile, skipped []string) {
	encoded, err := json.Marshal(features.wire())
	if err != nil || len(features.configFiles) != 0 {
		for _, candidate := range candidates {
			skipped = append(skipped, candidate.Path)
		}
		return nil, skipped
	}
	// The config_files member costs its key and brackets once, and each entry
	// its encoding plus a separating comma.
	used, member := len(encoded), len(`,"config_files":[]`)
	for _, candidate := range candidates {
		entry, err := json.Marshal(configFileWire{Path: candidate.Path, Content: candidate.Content})
		cost := len(entry) + 1
		if len(fitted) == 0 {
			cost = len(entry) + member
		}
		if err != nil || used+cost > MaxChangeFeaturesBytes {
			skipped = append(skipped, candidate.Path)
			continue
		}
		fitted, used = append(fitted, candidate), used+cost
	}
	return fitted, skipped
}

func canonicalPaths(values []string, maximum int) ([]string, error) {
	if len(values) > maximum {
		return nil, errors.New("too many paths")
	}
	if len(values) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !validRepositoryPath(value) {
			return nil, errors.New("path is not a clean relative repository path")
		}
		if _, exists := seen[value]; exists {
			return nil, errors.New("duplicate path")
		}
		seen[value] = struct{}{}
		out = append(out, strings.Clone(value))
	}
	sort.Strings(out)
	return out, nil
}

func optionalDigest(value string) bool {
	return value == "" || validDigest(value)
}

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

// Identity returns the SHA-256 identity of the canonical features document.
func (f ChangeFeatures) Identity() string { return f.identity }

// StyleIntents returns the declared style intents detected from config files.
func (f ChangeFeatures) StyleIntents() []StyleIntent {
	return append([]StyleIntent(nil), f.styleIntents...)
}

// String returns a redacted description.
func (f ChangeFeatures) String() string { return "agent profile change features" }

// GoString returns a redacted Go-syntax description.
func (f ChangeFeatures) GoString() string { return "agentprofile.ChangeFeatures{<redacted>}" }

// Validate verifies the content-derived identity.
func (f ChangeFeatures) Validate() error {
	if f.identity == "" || f.identity != deriveIdentity(f.wire()) {
		return ErrInvalidChangeFeatures
	}
	return nil
}

func (f ChangeFeatures) hasSourceFile() bool {
	for _, file := range f.files {
		if file.class == FileClassSource {
			return true
		}
	}
	return false
}

func (f ChangeFeatures) hasClass(class FileClass) bool {
	for _, file := range f.files {
		if file.class == class {
			return true
		}
	}
	return false
}

// semanticGapLanguages lists changed source languages lacking deterministic semantic coverage,
// plus a sentinel for explicit analyzer gap paths.
func (f ChangeFeatures) semanticGaps() []string {
	set := map[string]struct{}{}
	for _, file := range f.files {
		if file.class != FileClassSource {
			continue
		}
		if _, supported := deterministicSemanticLanguages[file.language]; !supported {
			set["unsupported_language:"+string(file.language)] = struct{}{}
		}
	}
	for _, gap := range f.semanticGapPaths {
		set["analyzer_gap:"+gap] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

// Wire encoding.

type changedFileWire struct {
	Path         string   `json:"path"`
	AddedLines   uint32   `json:"added_lines"`
	DeletedLines uint32   `json:"deleted_lines"`
	Signals      []string `json:"signals,omitempty"`
}

type coverageWire struct {
	UncoveredChangedLines uint32 `json:"uncovered_changed_lines"`
}

type intentWire struct {
	DescriptionPresent bool     `json:"description_present"`
	LinkedDocPaths     []string `json:"linked_doc_paths,omitempty"`
}

type configFileWire struct {
	Path    string `json:"path"`
	Content string `json:"content,omitempty"`
}

type changeFeaturesWire struct {
	Schema                  string            `json:"schema"`
	Version                 int               `json:"version"`
	Files                   []changedFileWire `json:"files"`
	PublicAPIChanges        uint32            `json:"public_api_changes"`
	ReferenceFanOut         uint32            `json:"reference_fan_out"`
	Coverage                *coverageWire     `json:"coverage,omitempty"`
	Intent                  intentWire        `json:"intent"`
	ConfigFiles             []configFileWire  `json:"config_files,omitempty"`
	SemanticGapPaths        []string          `json:"semantic_gap_paths,omitempty"`
	ChangeIdentity          string            `json:"change_identity,omitempty"`
	SemanticProfileIdentity string            `json:"semantic_profile_identity,omitempty"`
}

// wire returns the canonical form. File signals include path-derived signals,
// so re-parsing the canonical form is idempotent.
func (f ChangeFeatures) wire() changeFeaturesWire {
	wire := changeFeaturesWire{
		Schema: ChangeFeaturesSchema, Version: ChangeFeaturesVersion,
		PublicAPIChanges: f.publicAPIChanges, ReferenceFanOut: f.referenceFanOut,
		Intent:                  intentWire{DescriptionPresent: f.descriptionPresent, LinkedDocPaths: f.linkedDocPaths},
		SemanticGapPaths:        f.semanticGapPaths,
		ChangeIdentity:          f.changeIdentity,
		SemanticProfileIdentity: f.semanticProfileIdentity,
	}
	if f.coverageKnown {
		wire.Coverage = &coverageWire{UncoveredChangedLines: f.uncoveredChangedLines}
	}
	for _, file := range f.files {
		entry := changedFileWire{Path: file.path, AddedLines: file.added, DeletedLines: file.deleted}
		for _, signal := range file.signals {
			entry.Signals = append(entry.Signals, string(signal))
		}
		wire.Files = append(wire.Files, entry)
	}
	for _, config := range f.configFiles {
		wire.ConfigFiles = append(wire.ConfigFiles, configFileWire{Path: config.Path, Content: config.Content})
	}
	return wire
}

// MarshalJSON encodes the canonical features document.
func (f ChangeFeatures) MarshalJSON() ([]byte, error) {
	if err := f.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(f.wire())
}

// ParseChangeFeatures strictly decodes one versioned change-features document.
func ParseChangeFeatures(encoded []byte) (ChangeFeatures, error) {
	if len(encoded) > MaxChangeFeaturesBytes {
		return ChangeFeatures{}, ErrChangeFeaturesTooLarge
	}
	var wire changeFeaturesWire
	if err := decodeStrictJSON(encoded, &wire); err != nil {
		return ChangeFeatures{}, fmt.Errorf("%w: %v", ErrInvalidChangeFeatures, err)
	}
	if wire.Schema != ChangeFeaturesSchema || wire.Version != ChangeFeaturesVersion {
		return ChangeFeatures{}, fmt.Errorf("%w: unsupported schema or version", ErrInvalidChangeFeatures)
	}
	spec := ChangeFeaturesSpec{
		PublicAPIChanges: wire.PublicAPIChanges, ReferenceFanOut: wire.ReferenceFanOut,
		Intent:                  IntentSpec{DescriptionPresent: wire.Intent.DescriptionPresent, LinkedDocPaths: wire.Intent.LinkedDocPaths},
		SemanticGapPaths:        wire.SemanticGapPaths,
		ChangeIdentity:          wire.ChangeIdentity,
		SemanticProfileIdentity: wire.SemanticProfileIdentity,
	}
	if wire.Coverage != nil {
		spec.Coverage = &CoverageSpec{UncoveredChangedLines: wire.Coverage.UncoveredChangedLines}
	}
	if len(wire.Files) > maxFeatureFiles || len(wire.ConfigFiles) > MaxConfigFiles {
		return ChangeFeatures{}, fmt.Errorf("%w: too many entries", ErrInvalidChangeFeatures)
	}
	for _, file := range wire.Files {
		if len(file.Signals) > maxFileSignals {
			return ChangeFeatures{}, fmt.Errorf("%w: too many file signals", ErrInvalidChangeFeatures)
		}
		entry := ChangedFileSpec{Path: file.Path, AddedLines: file.AddedLines, DeletedLines: file.DeletedLines}
		for _, token := range file.Signals {
			signal, err := ParseSignal(token)
			if err != nil {
				return ChangeFeatures{}, fmt.Errorf("%w: %v", ErrInvalidChangeFeatures, err)
			}
			entry.Signals = append(entry.Signals, signal)
		}
		spec.Files = append(spec.Files, entry)
	}
	for _, config := range wire.ConfigFiles {
		spec.ConfigFiles = append(spec.ConfigFiles, ConfigFile{Path: config.Path, Content: config.Content})
	}
	return NewChangeFeatures(spec)
}

// AnalysisHints supplies router inputs that the existing deterministic analyzers do not produce.
type AnalysisHints struct {
	Coverage    *CoverageSpec
	Intent      IntentSpec
	ConfigFiles []ConfigFile
	// FileSignals adds analyzer-derived signals per changed path (for example concurrency).
	FileSignals map[string][]Signal
	// ReferenceFanOut counts the direct dependents of the changed definitions,
	// from the repository index.
	ReferenceFanOut uint32
}

// ChangeFeaturesFromSemanticImpact derives router input from existing deterministic evidence:
// changed line counts from the canonical evidence.Change line maps, and public API changes,
// reference fan-out, and coverage gaps from a semanticimpact.Profile computed for the same change.
// The caller is responsible for supplying a profile computed for this change; both identities are
// recorded as provenance in the features identity.
func ChangeFeaturesFromSemanticImpact(change evidence.Change, impact semanticimpact.Profile, hints AnalysisHints) (ChangeFeatures, error) {
	fileChanges := change.FileChanges()
	lineMaps := change.LineMaps()
	if len(fileChanges) == 0 || len(fileChanges) != len(lineMaps) || !validDigest(change.Identity()) {
		return ChangeFeatures{}, fmt.Errorf("%w: change is not canonical", ErrInvalidChangeFeatures)
	}
	files := make([]ChangedFileSpec, 0, len(fileChanges))
	for index, fileChange := range fileChanges {
		var added, deleted uint64
		for _, hunk := range lineMaps[index].Hunks() {
			switch hunk.Kind() {
			case evidence.HunkKindAddition:
				added += uint64(hunk.HeadLineCount())
			case evidence.HunkKindDeletion:
				deleted += uint64(hunk.BaseLineCount())
			case evidence.HunkKindModification:
				added += uint64(hunk.HeadLineCount())
				deleted += uint64(hunk.BaseLineCount())
			}
		}
		if added > maxChangedLinesPerFile || deleted > maxChangedLinesPerFile {
			return ChangeFeatures{}, fmt.Errorf("%w: changed line count exceeds bound", ErrInvalidChangeFeatures)
		}
		files = append(files, ChangedFileSpec{Path: fileChange.Path(), AddedLines: uint32(added), DeletedLines: uint32(deleted)})
	}
	return changeFeaturesFromImpact(change.Identity(), files, impact, hints)
}

// ChangeFeaturesFromFileSpecs is ChangeFeaturesFromSemanticImpact for a caller that
// already holds per-file changed line counts (for example a recorded change-model
// artifact) rather than an evidence.Change. changeIdentity is optional provenance
// (lowercase SHA-256 hex or empty). File signals in files are kept; path-derived,
// hint and public-API signals are added exactly as ChangeFeaturesFromSemanticImpact adds them.
func ChangeFeaturesFromFileSpecs(changeIdentity string, files []ChangedFileSpec, impact semanticimpact.Profile, hints AnalysisHints) (ChangeFeatures, error) {
	if len(files) == 0 || !optionalDigest(changeIdentity) {
		return ChangeFeatures{}, fmt.Errorf("%w: change is not canonical", ErrInvalidChangeFeatures)
	}
	return changeFeaturesFromImpact(changeIdentity, files, impact, hints)
}

func changeFeaturesFromImpact(changeIdentity string, files []ChangedFileSpec, impact semanticimpact.Profile, hints AnalysisHints) (ChangeFeatures, error) {
	publicAPIPaths := map[string]struct{}{}
	publicAPIChanges := impact.PublicAPIChanges()
	for _, declaration := range publicAPIChanges {
		publicAPIPaths[declaration.Path()] = struct{}{}
	}
	changed := make(map[string]struct{}, len(files))
	spec := ChangeFeaturesSpec{
		Coverage: hints.Coverage, Intent: hints.Intent, ConfigFiles: hints.ConfigFiles,
		ChangeIdentity: changeIdentity,
	}
	if validDigest(impact.Identity()) {
		spec.SemanticProfileIdentity = impact.Identity()
	}
	for _, file := range files {
		entry := ChangedFileSpec{Path: file.Path, AddedLines: file.AddedLines, DeletedLines: file.DeletedLines}
		entry.Signals = append(append(entry.Signals, file.Signals...), hints.FileSignals[file.Path]...)
		if _, ok := publicAPIPaths[file.Path]; ok && !containsSignal(entry.Signals, SignalPublicAPI) {
			entry.Signals = append(entry.Signals, SignalPublicAPI)
		}
		changed[file.Path] = struct{}{}
		spec.Files = append(spec.Files, entry)
	}
	for hintPath := range hints.FileSignals {
		if _, ok := changed[hintPath]; !ok {
			return ChangeFeatures{}, fmt.Errorf("%w: file signal hint for unchanged path", ErrInvalidChangeFeatures)
		}
	}
	gapSet := map[string]struct{}{}
	for _, gap := range impact.Gaps() {
		if _, ok := changed[gap.Path()]; ok {
			gapSet[gap.Path()] = struct{}{}
		}
	}
	for gapPath := range gapSet {
		spec.SemanticGapPaths = append(spec.SemanticGapPaths, gapPath)
	}
	if len(publicAPIChanges) > maxPublicAPIChanges || hints.ReferenceFanOut > maxReferenceFanOut {
		return ChangeFeatures{}, fmt.Errorf("%w: semantic profile exceeds bounds", ErrInvalidChangeFeatures)
	}
	spec.PublicAPIChanges = uint32(len(publicAPIChanges))
	spec.ReferenceFanOut = hints.ReferenceFanOut
	return NewChangeFeatures(spec)
}

func containsSignal(signals []Signal, target Signal) bool {
	for _, signal := range signals {
		if signal == target {
			return true
		}
	}
	return false
}

func deriveIdentity(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
