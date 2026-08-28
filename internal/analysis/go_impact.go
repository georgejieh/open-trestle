package analysis

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"sort"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

const (
	goChangeImpactResolver        = "go-stdlib-enclosing-symbols"
	goChangeImpactResolverVersion = "1"
)

// GoImpactOutcome identifies one changed file's Go analysis coverage.
type GoImpactOutcome string

const (
	// GoImpactOutcomeAnalyzed indicates that positive head Hunks were analyzed.
	GoImpactOutcomeAnalyzed GoImpactOutcome = "analyzed"
	// GoImpactOutcomeNotApplicable indicates that no head-side range exists.
	GoImpactOutcomeNotApplicable GoImpactOutcome = "not_applicable"
	// GoImpactOutcomeUnsupported indicates that the file language is unsupported.
	GoImpactOutcomeUnsupported GoImpactOutcome = "unsupported"
)

// GoImpactReason explains one coverage outcome.
type GoImpactReason string

const (
	// GoImpactReasonNone indicates successful analysis without an exclusion.
	GoImpactReasonNone GoImpactReason = "none"
	// GoImpactReasonNoPositiveHeadHunks indicates a deletion-only file.
	GoImpactReasonNoPositiveHeadHunks GoImpactReason = "no_positive_head_hunks"
	// GoImpactReasonUnsupportedLanguage indicates a non-Go file.
	GoImpactReasonUnsupportedLanguage GoImpactReason = "unsupported_language"
)

// GoImpactFileCoverage records Go resolver coverage for one changed file.
type GoImpactFileCoverage struct {
	path        string
	outcome     GoImpactOutcome
	reason      GoImpactReason
	symbolCount int
}

// GoChangeImpactReceipt records complete Go v1 execution over one exact Change.
type GoChangeImpactReceipt struct {
	identity        string
	changeIdentity  string
	profileIdentity string
	resolverVersion string
	files           []GoImpactFileCoverage
}

// BuildGoChangeImpactProfile resolves one Change and records exact Go coverage.
func BuildGoChangeImpactProfile(change evidence.Change, headContents map[string][]byte) (ChangeImpactProfile, GoChangeImpactReceipt, error) {
	symbols, err := ResolveGoChangeSymbols(change, headContents)
	if err != nil {
		return ChangeImpactProfile{}, GoChangeImpactReceipt{}, fmt.Errorf("resolve Go Change symbols: %w", err)
	}
	profile, err := NewChangeImpactProfile(change, symbols)
	if err != nil {
		return ChangeImpactProfile{}, GoChangeImpactReceipt{}, fmt.Errorf("create Change impact profile: %w", err)
	}
	receipt, err := newGoChangeImpactReceipt(change, profile, goChangeImpactResolverVersion)
	if err != nil {
		return ChangeImpactProfile{}, GoChangeImpactReceipt{}, err
	}
	return profile, receipt, nil
}

func newGoChangeImpactReceipt(change evidence.Change, profile ChangeImpactProfile, resolverVersion string) (GoChangeImpactReceipt, error) {
	canonicalChange, err := evidence.NewChange(change.FileChanges(), change.LineMaps())
	if err != nil || canonicalChange.Identity() != change.Identity() {
		return GoChangeImpactReceipt{}, fmt.Errorf("change is not canonical")
	}
	profileSymbols, err := validateGoImpactProfile(canonicalChange, profile)
	if err != nil {
		return GoChangeImpactReceipt{}, err
	}
	if resolverVersion == "" || len(resolverVersion) > 32 {
		return GoChangeImpactReceipt{}, fmt.Errorf("resolver version is invalid")
	}
	counts := make(map[string]int, len(profileSymbols))
	for _, symbol := range profileSymbols {
		counts[symbol.Path()]++
	}
	fileChanges := canonicalChange.FileChanges()
	lineMaps := canonicalChange.LineMaps()
	files := make([]GoImpactFileCoverage, len(fileChanges))
	total := 0
	for i, fileChange := range fileChanges {
		coverage := GoImpactFileCoverage{path: fileChange.Path()}
		symbolCount := counts[fileChange.Path()]
		switch {
		case path.Ext(fileChange.Path()) != ".go":
			if symbolCount != 0 {
				return GoChangeImpactReceipt{}, fmt.Errorf("unsupported file %q has Go Symbols", fileChange.Path())
			}
			coverage.outcome = GoImpactOutcomeUnsupported
			coverage.reason = GoImpactReasonUnsupportedLanguage
		case hasPositiveHeadHunk(lineMaps[i]):
			coverage.outcome = GoImpactOutcomeAnalyzed
			coverage.reason = GoImpactReasonNone
			coverage.symbolCount = symbolCount
			total += symbolCount
		default:
			if symbolCount != 0 {
				return GoChangeImpactReceipt{}, fmt.Errorf("deletion-only file %q has head Symbols", fileChange.Path())
			}
			coverage.outcome = GoImpactOutcomeNotApplicable
			coverage.reason = GoImpactReasonNoPositiveHeadHunks
		}
		files[i] = coverage
	}
	if total != len(profileSymbols) {
		return GoChangeImpactReceipt{}, fmt.Errorf("profile Symbols do not match Go coverage")
	}

	wireFiles := make([]goImpactFileWire, len(files))
	for i, file := range files {
		wireFiles[i] = goImpactFileWire{
			Path:        file.path,
			Outcome:     file.outcome,
			Reason:      file.reason,
			SymbolCount: file.symbolCount,
		}
	}
	preimage := struct {
		Contract        string             `json:"contract"`
		SchemaVersion   int                `json:"schema_version"`
		Resolver        string             `json:"resolver"`
		ResolverVersion string             `json:"resolver_version"`
		ChangeIdentity  string             `json:"change_identity"`
		ProfileIdentity string             `json:"profile_identity"`
		Files           []goImpactFileWire `json:"files"`
	}{
		Contract:        "open-trestle/go-change-impact-receipt",
		SchemaVersion:   1,
		Resolver:        goChangeImpactResolver,
		ResolverVersion: resolverVersion,
		ChangeIdentity:  canonicalChange.Identity(),
		ProfileIdentity: profile.Identity(),
		Files:           wireFiles,
	}
	encoded, err := json.Marshal(preimage)
	if err != nil {
		return GoChangeImpactReceipt{}, fmt.Errorf("encode Go Change impact receipt identity: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return GoChangeImpactReceipt{
		identity:        hex.EncodeToString(digest[:]),
		changeIdentity:  canonicalChange.Identity(),
		profileIdentity: profile.Identity(),
		resolverVersion: resolverVersion,
		files:           files,
	}, nil
}

func validateGoImpactProfile(change evidence.Change, profile ChangeImpactProfile) ([]Symbol, error) {
	if !isSHA256Identity(profile.Identity()) || profile.ChangeIdentity() != change.Identity() {
		return nil, fmt.Errorf("profile does not match Change")
	}
	if len(profile.symbols) > maxChangeImpactSymbols {
		return nil, fmt.Errorf("profile exceeds %d Symbols", maxChangeImpactSymbols)
	}
	symbols := profile.Symbols()
	fileChanges := change.FileChanges()
	lineMaps := change.LineMaps()
	bindings := make(map[string]changeImpactBinding, len(fileChanges))
	for i, fileChange := range fileChanges {
		bindings[fileChange.Path()] = changeImpactBinding{fileChange: fileChange, lineMap: lineMaps[i]}
	}
	if len(profile.symbolsByIdentity) != len(symbols) {
		return nil, fmt.Errorf("profile identity index is not canonical")
	}
	wireSymbols := make([]changeImpactSymbolWire, len(symbols))
	for i, symbol := range symbols {
		if i > 0 {
			if symbol.Identity() == symbols[i-1].Identity() || changeImpactSymbolLess(symbol, symbols[i-1]) {
				return nil, fmt.Errorf("profile Symbols are not canonical")
			}
		}
		binding, ok := bindings[symbol.Path()]
		if !ok || symbol.FileChangeIdentity() != binding.fileChange.Identity() || symbol.LineMapIdentity() != binding.lineMap.Identity() {
			return nil, fmt.Errorf("profile Symbol %d does not match Change", i)
		}
		canonical, err := NewSymbol(binding.lineMap, symbol.Language(), symbol.Kind(), symbol.QualifiedName(), symbol.SourceRange())
		if err != nil || canonical.Identity() != symbol.Identity() {
			return nil, fmt.Errorf("profile Symbol %d is not canonical", i)
		}
		indexedPosition, ok := profile.symbolsByIdentity[symbol.Identity()]
		if !ok || indexedPosition != i {
			return nil, fmt.Errorf("profile Symbol index is not canonical")
		}
		wireSymbols[i] = changeImpactSymbolWire{Path: symbol.Path(), SymbolIdentity: symbol.Identity()}
	}
	preimage := struct {
		Contract       string                   `json:"contract"`
		SchemaVersion  int                      `json:"schema_version"`
		ChangeIdentity string                   `json:"change_identity"`
		Symbols        []changeImpactSymbolWire `json:"symbols"`
	}{
		Contract:       "open-trestle/change-impact-profile",
		SchemaVersion:  1,
		ChangeIdentity: change.Identity(),
		Symbols:        wireSymbols,
	}
	encoded, err := json.Marshal(preimage)
	if err != nil {
		return nil, fmt.Errorf("encode profile identity validation: %w", err)
	}
	digest := sha256.Sum256(encoded)
	if profile.Identity() != hex.EncodeToString(digest[:]) {
		return nil, fmt.Errorf("profile identity does not match Symbols")
	}
	return symbols, nil
}

func hasPositiveHeadHunk(lineMap evidence.LineMap) bool {
	for _, hunk := range lineMap.Hunks() {
		if hunk.HeadLineCount() > 0 {
			return true
		}
	}
	return false
}

type goImpactFileWire struct {
	Path        string          `json:"path"`
	Outcome     GoImpactOutcome `json:"outcome"`
	Reason      GoImpactReason  `json:"reason"`
	SymbolCount int             `json:"symbol_count"`
}

// Identity returns the versioned canonical SHA-256 identity.
func (r GoChangeImpactReceipt) Identity() string {
	return r.identity
}

// ChangeIdentity returns the exact analyzed Change identity.
func (r GoChangeImpactReceipt) ChangeIdentity() string {
	return r.changeIdentity
}

// ProfileIdentity returns the exact resulting profile identity.
func (r GoChangeImpactReceipt) ProfileIdentity() string {
	return r.profileIdentity
}

// ResolverVersion returns the pinned Go resolver version.
func (r GoChangeImpactReceipt) ResolverVersion() string {
	return r.resolverVersion
}

// Files returns coverage entries in canonical Change path order.
func (r GoChangeImpactReceipt) Files() []GoImpactFileCoverage {
	result := make([]GoImpactFileCoverage, len(r.files))
	copy(result, r.files)
	return result
}

// File returns coverage for one exact changed path.
func (r GoChangeImpactReceipt) File(path string) (GoImpactFileCoverage, bool) {
	index := sort.Search(len(r.files), func(i int) bool {
		return r.files[i].path >= path
	})
	if index == len(r.files) || r.files[index].path != path {
		return GoImpactFileCoverage{}, false
	}
	return r.files[index], true
}

// Path returns the exact changed file path.
func (c GoImpactFileCoverage) Path() string {
	return c.path
}

// Outcome returns the file's Go analysis coverage outcome.
func (c GoImpactFileCoverage) Outcome() GoImpactOutcome {
	return c.outcome
}

// Reason returns the reason for the coverage outcome.
func (c GoImpactFileCoverage) Reason() GoImpactReason {
	return c.reason
}

// SymbolCount returns the number of profile Symbols for the file.
func (c GoImpactFileCoverage) SymbolCount() int {
	return c.symbolCount
}
