package agentprofile

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/georgejieh/open-trestle/internal/provider"
)

// Catalog contract.
const (
	CatalogContract = "open-trestle/agent-profile-catalog"
	// CatalogVersion is the packaged catalog version. Bump it when any profile, skill, or scoring row changes.
	CatalogVersion = 1
)

var (
	// ErrInvalidCatalog identifies a catalog that violates the catalog contract.
	ErrInvalidCatalog = errors.New("invalid agent profile catalog")
	// ErrInvalidCatalogIdentity identifies catalog content inconsistent with its identity.
	ErrInvalidCatalogIdentity = errors.New("invalid agent profile catalog identity")
)

//go:embed skills/*.md
var skillFiles embed.FS

// Catalog is an immutable, content-identified set of profiles in profile-ID order.
type Catalog struct {
	identity string
	version  uint32
	profiles []Profile
}

// NewCatalog validates a profile set. IDs must be unique and the orchestrator must be present.
func NewCatalog(version uint32, profiles []Profile) (Catalog, error) {
	if version == 0 {
		return Catalog{}, fmt.Errorf("%w: version must be positive", ErrInvalidCatalog)
	}
	if len(profiles) == 0 || len(profiles) > len(knownProfileIDs) {
		return Catalog{}, fmt.Errorf("%w: profile count out of range", ErrInvalidCatalog)
	}
	sorted := append([]Profile(nil), profiles...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].id < sorted[j].id })
	hasOrchestrator := false
	for index, profile := range sorted {
		if err := profile.Validate(); err != nil {
			return Catalog{}, fmt.Errorf("%w: %s: %w", ErrInvalidCatalog, profile.id, err)
		}
		if index > 0 && sorted[index-1].id == profile.id {
			return Catalog{}, fmt.Errorf("%w: duplicate profile %s", ErrInvalidCatalog, profile.id)
		}
		if profile.id == ProfileOrchestrator {
			hasOrchestrator = true
		}
	}
	if !hasOrchestrator {
		return Catalog{}, fmt.Errorf("%w: orchestrator profile is required", ErrInvalidCatalog)
	}
	catalog := Catalog{version: version, profiles: sorted}
	catalog.identity = deriveIdentity(catalog.identityWire())
	return catalog, nil
}

// DefaultCatalog returns the packaged, embedded catalog.
func DefaultCatalog() (Catalog, error) {
	specs, err := packagedProfileSpecs()
	if err != nil {
		return Catalog{}, err
	}
	profiles := make([]Profile, 0, len(specs))
	for _, spec := range specs {
		profile, err := NewProfile(spec)
		if err != nil {
			return Catalog{}, err
		}
		profiles = append(profiles, profile)
	}
	return NewCatalog(CatalogVersion, profiles)
}

// Identity returns the SHA-256 catalog identity over profile identities and the scoring table.
func (c Catalog) Identity() string { return c.identity }

// Version returns the catalog version.
func (c Catalog) Version() uint32 { return c.version }

// Profiles returns the profiles in profile-ID order.
func (c Catalog) Profiles() []Profile { return append([]Profile(nil), c.profiles...) }

// Profile returns one profile by ID.
func (c Catalog) Profile(id ProfileID) (Profile, bool) {
	for _, profile := range c.profiles {
		if profile.id == id {
			return profile, true
		}
	}
	return Profile{}, false
}

// String returns a redacted description.
func (c Catalog) String() string { return "agent profile catalog" }

// GoString returns a redacted Go-syntax description.
func (c Catalog) GoString() string { return "agentprofile.Catalog{<redacted>}" }

// Validate verifies every profile and the catalog identity.
func (c Catalog) Validate() error {
	for _, profile := range c.profiles {
		if err := profile.Validate(); err != nil {
			return err
		}
	}
	if c.identity == "" || c.identity != deriveIdentity(c.identityWire()) {
		return ErrInvalidCatalogIdentity
	}
	return nil
}

type scoringRowWire struct {
	Signal  string `json:"signal"`
	Divisor uint64 `json:"divisor"`
	Points  uint64 `json:"points"`
	Cap     uint64 `json:"cap"`
	Meaning string `json:"meaning"`
}

type catalogIdentityWire struct {
	Contract   string           `json:"contract"`
	Version    uint32           `json:"version"`
	Scoring    []scoringRowWire `json:"scoring"`
	Profiles   []string         `json:"profiles"`
	MaxScore   uint64           `json:"max_difficulty_score"`
	Semantic   []string         `json:"deterministic_semantic_languages"`
	Assignment string           `json:"assignments_schema"`
}

func scoringWire() []scoringRowWire {
	rows := make([]scoringRowWire, 0, len(difficultyWeights))
	for _, weight := range difficultyWeights {
		rows = append(rows, scoringRowWire{Signal: string(weight.signal), Divisor: weight.divisor, Points: weight.points, Cap: weight.cap, Meaning: weight.meaning})
	}
	return rows
}

func semanticLanguagesWire() []string {
	out := make([]string, 0, len(deterministicSemanticLanguages))
	for language := range deterministicSemanticLanguages {
		out = append(out, string(language))
	}
	sort.Strings(out)
	return out
}

func (c Catalog) identityWire() catalogIdentityWire {
	wire := catalogIdentityWire{
		Contract: CatalogContract, Version: c.version, Scoring: scoringWire(), MaxScore: maxDifficultyScore,
		Semantic: semanticLanguagesWire(), Assignment: AssignmentsSchema,
	}
	for _, profile := range c.profiles {
		wire.Profiles = append(wire.Profiles, profile.identity)
	}
	return wire
}

// MarshalJSON encodes the full catalog, including skill markdown and the scoring table.
func (c Catalog) MarshalJSON() ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Contract           string           `json:"contract"`
		Version            uint32           `json:"version"`
		Identity           string           `json:"identity"`
		MaxDifficultyScore uint64           `json:"max_difficulty_score"`
		Scoring            []scoringRowWire `json:"scoring"`
		SemanticLanguages  []string         `json:"deterministic_semantic_languages"`
		Profiles           []Profile        `json:"profiles"`
	}{
		Contract: CatalogContract, Version: c.version, Identity: c.identity, MaxDifficultyScore: maxDifficultyScore,
		Scoring: scoringWire(), SemanticLanguages: semanticLanguagesWire(), Profiles: c.profiles,
	})
}

// Packaged declarations.

var (
	reviewTiers = map[Tier]TierSpec{
		TierLight:    {MinContextTokens: 24576, MinOutputTokens: 4096, InputTokenBudget: 16384, OutputTokenBudget: 4096},
		TierStandard: {MinContextTokens: 81920, MinOutputTokens: 8192, InputTokenBudget: 65536, OutputTokenBudget: 8192},
		TierDeep:     {MinContextTokens: 196608, MinOutputTokens: 16384, InputTokenBudget: 163840, OutputTokenBudget: 16384},
	}
	compactTiers = map[Tier]TierSpec{
		TierLight:    {MinContextTokens: 16384, MinOutputTokens: 2048, InputTokenBudget: 12288, OutputTokenBudget: 2048},
		TierStandard: {MinContextTokens: 49152, MinOutputTokens: 4096, InputTokenBudget: 40960, OutputTokenBudget: 4096},
		TierDeep:     {MinContextTokens: 131072, MinOutputTokens: 8192, InputTokenBudget: 114688, OutputTokenBudget: 8192},
	}
	structuredOutput = []provider.ModelFeature{provider.ModelFeatureStructuredOutput}
)

func packagedProfileSpecs() ([]ProfileSpec, error) {
	specs := []ProfileSpec{
		{
			ID: ProfileOrchestrator, Version: 1, Priority: 100, ModelCall: ModelCallNone,
			Purpose:    "Deterministic router: activates profiles, scores difficulty, selects tiers and exact routes, and records omissions. Makes no model call.",
			Activation: Activation{Conditions: []Condition{ConditionAlways}},
		},
		{
			ID: ProfileKnowledgeGraph, Version: 2, Priority: 60, ModelCall: ModelCallGapOnly,
			Purpose:          "Plan only: routing plans include it, but no review run dispatches it, so it does not build or extend a graph yet. Intended to keep the repository symbol and dependency graph from deterministic analysis, using a model only for coverage gaps such as unsupported languages.",
			Activation:       Activation{FileClasses: []FileClass{FileClassSource}},
			RequiredFeatures: structuredOutput, Tiers: compactTiers,
		},
		{
			ID: ProfileSecurityProbe, Version: 2, Priority: 90, ModelCall: ModelCallRequired,
			Purpose: "Static, read-only security probe: attack-surface reconnaissance, vulnerability hypotheses, and evidence from changed code. Never executes or dynamically validates.",
			Activation: Activation{
				PathGlobs: []string{"**/*.key", "**/*.pem", "**/.env", "**/.env.*"},
				Signals: []Signal{SignalAuth, SignalCIConfig, SignalCrypto, SignalDependencyManifest, SignalDeserialization,
					SignalExec, SignalHTTP, SignalSecrets, SignalSQL, SignalWebhook},
			},
			RequiredFeatures: structuredOutput, Tiers: reviewTiers,
		},
		{
			ID: ProfileFrontend, Version: 2, Priority: 70, ModelCall: ModelCallRequired,
			Purpose: "Front-end review: interface design, accessibility, motion and reduced motion, web layout, and JavaScript, TypeScript, and React correctness.",
			Activation: Activation{Languages: []Language{
				LanguageCSS, LanguageHTML, LanguageJavaScript, LanguageSvelte, LanguageTypeScript, LanguageVue,
			}},
			RequiredFeatures: structuredOutput, Tiers: reviewTiers,
		},
		{
			ID: ProfileBackend, Version: 1, Priority: 70, ModelCall: ModelCallRequired,
			Purpose: "Back-end review: API contracts, persistence, concurrency, resource lifetime, and error handling.",
			Activation: Activation{
				Languages: []Language{LanguageC, LanguageCPP, LanguageCSharp, LanguageGo, LanguageJava, LanguageKotlin,
					LanguagePHP, LanguagePython, LanguageRuby, LanguageRust, LanguageScala, LanguageSQL},
				Signals: []Signal{SignalConcurrency, SignalPersistence, SignalSQL},
			},
			RequiredFeatures: structuredOutput, Tiers: reviewTiers,
		},
		{
			ID: ProfileTestAuthor, Version: 1, Priority: 50, ModelCall: ModelCallRequired,
			Purpose:          "Proposes focused unit and regression tests for changed code and its callers as candidate artifacts; never executes them.",
			Activation:       Activation{FileClasses: []FileClass{FileClassSource}},
			RequiredFeatures: structuredOutput, Tiers: reviewTiers,
		},
		{
			ID: ProfileStyleConformance, Version: 2, Priority: 20, ModelCall: ModelCallRequired,
			Purpose:          "Checks changed code against the repository's declared style intent, detected from config files. Its guidance covers gofmt and Effective Go, PEP 8 with Black and Google Python style, Google C++ with clang-format, and Prettier, ESLint and EditorConfig; other declared styles, such as rustfmt and RuboCop, get no style-specific guidance.",
			Activation:       Activation{Conditions: []Condition{ConditionDeclaredStyleMatches}},
			RequiredFeatures: structuredOutput, Tiers: compactTiers,
		},
		{
			ID: ProfileBugHunter, Version: 2, Priority: 80, ModelCall: ModelCallRequired,
			Purpose:          "Hunts logic and edge-case defects in changed code: boundaries, nil and empty values, error paths, state, and arithmetic.",
			Activation:       Activation{FileClasses: []FileClass{FileClassSource}},
			RequiredFeatures: structuredOutput, Tiers: reviewTiers,
		},
		{
			ID: ProfileDriftAuditor, Version: 1, Priority: 40, ModelCall: ModelCallRequired,
			Purpose:          "Diffs declared change intent (description and linked docs) against code, and docs against code, reporting drift.",
			Activation:       Activation{Conditions: []Condition{ConditionDocsAndCodeChanged, ConditionIntentDeclared}},
			RequiredFeatures: structuredOutput, Tiers: compactTiers,
		},
	}
	for index := range specs {
		skill, err := skillFiles.ReadFile("skills/" + string(specs[index].ID) + ".md")
		if err != nil {
			return nil, fmt.Errorf("%w: missing skill for %s", ErrInvalidCatalog, specs[index].ID)
		}
		specs[index].Skill = string(skill)
		if specs[index].ModelCall != ModelCallNone {
			specs[index].Thresholds = profileTierThresholds[specs[index].ID]
		}
	}
	return specs, nil
}
