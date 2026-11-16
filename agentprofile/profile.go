package agentprofile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/internal/provider"
)

// Profile bounds.
const (
	maxProfileVersion      = 1 << 16
	maxProfilePurposeBytes = 512
	maxSkillBytes          = 64 << 10
	maxActivationEntries   = 64
	maxTierTokens          = 1 << 30
)

var (
	// ErrInvalidProfile identifies a profile declaration that violates the catalog contract.
	ErrInvalidProfile = errors.New("invalid agent profile")
	// ErrInvalidProfileIdentity identifies profile content inconsistent with its identity.
	ErrInvalidProfileIdentity = errors.New("invalid agent profile identity")
)

// Activation declares when a profile applies. Predicates are OR-combined; a
// file matches when any path glob, language, file class, or signal matches.
// Vendor and generated files never activate a profile.
type Activation struct {
	PathGlobs   []string
	Languages   []Language
	FileClasses []FileClass
	Signals     []Signal
	Conditions  []Condition
}

// TierSpec declares per-tier model capacity requirements and the token budget.
type TierSpec struct {
	// MinContextTokens is the minimum route context window; it must cover the input and output budgets.
	MinContextTokens uint32
	// MinOutputTokens is the minimum route output capacity; it must cover the output budget.
	MinOutputTokens uint32
	// InputTokenBudget bounds the context packet sent to the profile at this tier.
	InputTokenBudget uint32
	// OutputTokenBudget is the max_output_tokens requested at this tier.
	OutputTokenBudget uint32
}

// TierThresholds maps a difficulty score to a tier: score < Standard is light,
// Standard <= score < Deep is standard, and score >= Deep is deep.
type TierThresholds struct {
	Standard uint32
	Deep     uint32
}

// ProfileSpec is the declaration input for NewProfile.
type ProfileSpec struct {
	ID               ProfileID
	Version          uint32
	Purpose          string
	Priority         uint8
	ModelCall        ModelCall
	Activation       Activation
	RequiredFeatures []provider.ModelFeature
	Tiers            map[Tier]TierSpec
	Thresholds       TierThresholds
	Skill            string
}

// Authority is the fixed authority of every packaged profile. It is not
// configurable: no profile can be granted tool execution, dynamic validation,
// network access, publication, or source mutation through this package.
type Authority struct{}

// CandidatesOnly reports that profile output is a candidate set, never a finding.
func (Authority) CandidatesOnly() bool { return true }

// RequiresIndependentVerification reports that candidates need a separate verifier route.
func (Authority) RequiresIndependentVerification() bool { return true }

// ToolExecution reports whether the profile may execute tools or repository commands.
func (Authority) ToolExecution() bool { return false }

// DynamicValidation reports whether the profile may run dynamic validation; it requires the separate
// governed-execution authorization described in docs/architecture.md, which this layer cannot grant.
func (Authority) DynamicValidation() bool { return false }

// NetworkAccess reports whether the profile may reach the network outside gateway dispatch.
func (Authority) NetworkAccess() bool { return false }

// Publication reports whether the profile may publish results.
func (Authority) Publication() bool { return false }

// SourceMutation reports whether the profile may modify source.
func (Authority) SourceMutation() bool { return false }

// Profile is an immutable, validated, content-identified specialist declaration.
type Profile struct {
	identity         string
	id               ProfileID
	version          uint32
	purpose          string
	priority         uint8
	modelCall        ModelCall
	activation       Activation
	requiredFeatures []provider.ModelFeature
	tiers            map[Tier]TierSpec
	thresholds       TierThresholds
	skill            string
	skillDigest      string
}

// NewProfile validates and freezes one profile declaration.
func NewProfile(spec ProfileSpec) (Profile, error) {
	invalid := func(detail string) (Profile, error) {
		return Profile{}, fmt.Errorf("%w: %s: %s", ErrInvalidProfile, spec.ID, detail)
	}
	if _, err := ParseProfileID(string(spec.ID)); err != nil {
		return Profile{}, fmt.Errorf("%w: %w", ErrInvalidProfile, err)
	}
	if spec.Version == 0 || spec.Version > maxProfileVersion {
		return invalid("version must be between 1 and 65536")
	}
	if !validText(spec.Purpose, maxProfilePurposeBytes) {
		return invalid("purpose must be printable text within 512 bytes")
	}
	if spec.Priority == 0 || spec.Priority > 100 {
		return invalid("priority must be between 1 and 100")
	}
	if !spec.ModelCall.valid() {
		return invalid("unknown model call mode")
	}
	if (spec.ID == ProfileOrchestrator) != (spec.ModelCall == ModelCallNone) {
		return invalid("only the orchestrator is model-free, and it must be")
	}
	if err := validateActivation(spec.Activation); err != nil {
		return invalid(err.Error())
	}
	if _, err := provider.NewModelRequirements(0, 0, spec.RequiredFeatures); err != nil {
		return invalid("required features: " + err.Error())
	}
	features := append([]provider.ModelFeature(nil), spec.RequiredFeatures...)
	sort.Slice(features, func(i, j int) bool { return features[i] < features[j] })
	if spec.ModelCall == ModelCallNone {
		if len(spec.Tiers) != 0 || spec.Thresholds != (TierThresholds{}) || len(features) != 0 {
			return invalid("a model-free profile declares no tiers, thresholds, or model features")
		}
	} else {
		if err := validateTiers(spec.Tiers); err != nil {
			return invalid(err.Error())
		}
		if spec.Thresholds.Standard == 0 || spec.Thresholds.Standard >= spec.Thresholds.Deep || spec.Thresholds.Deep > maxDifficultyScore {
			return invalid("thresholds must satisfy 0 < standard < deep <= max difficulty score")
		}
	}
	if err := validateSkill(spec.Skill); err != nil {
		return invalid(err.Error())
	}
	profile := Profile{
		id: spec.ID, version: spec.Version, purpose: strings.Clone(spec.Purpose), priority: spec.Priority,
		modelCall: spec.ModelCall, activation: cloneActivation(spec.Activation), requiredFeatures: features,
		thresholds: spec.Thresholds, skill: strings.Clone(spec.Skill), skillDigest: digestString(spec.Skill),
	}
	if len(spec.Tiers) > 0 {
		profile.tiers = make(map[Tier]TierSpec, len(spec.Tiers))
		for tier, tierSpec := range spec.Tiers {
			profile.tiers[tier] = tierSpec
		}
	}
	profile.identity = deriveIdentity(profile.identityWire())
	return profile, nil
}

func validText(value string, maximum int) bool {
	if strings.TrimSpace(value) == "" || len(value) > maximum || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if !unicode.IsPrint(character) {
			return false
		}
	}
	return true
}

func validateSkill(skill string) error {
	if len(skill) == 0 || len(skill) > maxSkillBytes || !utf8.ValidString(skill) || !strings.HasPrefix(skill, "# ") {
		return errors.New("skill must be UTF-8 markdown within 64 KiB starting with a level-one heading")
	}
	if strings.ContainsRune(skill, 0) {
		return errors.New("skill contains NUL")
	}
	return nil
}

func validateActivation(activation Activation) error {
	total := len(activation.PathGlobs) + len(activation.Languages) + len(activation.FileClasses) + len(activation.Signals) + len(activation.Conditions)
	if total == 0 {
		return errors.New("activation requires at least one predicate")
	}
	if total > maxActivationEntries {
		return errors.New("too many activation predicates")
	}
	seen := map[string]struct{}{}
	check := func(kind, value string, valid bool) error {
		if !valid {
			return fmt.Errorf("invalid activation %s %q", kind, value)
		}
		key := kind + ":" + value
		if _, exists := seen[key]; exists {
			return fmt.Errorf("duplicate activation %s %q", kind, value)
		}
		seen[key] = struct{}{}
		return nil
	}
	for _, glob := range activation.PathGlobs {
		if err := check("glob", glob, validateGlob(glob) == nil); err != nil {
			return err
		}
	}
	for _, language := range activation.Languages {
		if err := check("language", string(language), validLanguage(language)); err != nil {
			return err
		}
	}
	for _, class := range activation.FileClasses {
		valid := validFileClass(class) && class != FileClassVendor && class != FileClassGenerated
		if err := check("file class", string(class), valid); err != nil {
			return err
		}
	}
	for _, signal := range activation.Signals {
		if err := check("signal", string(signal), validSignal(signal)); err != nil {
			return err
		}
	}
	for _, condition := range activation.Conditions {
		if err := check("condition", string(condition), validCondition(condition)); err != nil {
			return err
		}
	}
	return nil
}

func validateTiers(tiers map[Tier]TierSpec) error {
	if len(tiers) != len(Tiers()) {
		return errors.New("every tier (light, standard, deep) must be declared")
	}
	var previous TierSpec
	for index, tier := range Tiers() {
		spec, ok := tiers[tier]
		if !ok {
			return fmt.Errorf("tier %s is missing", tier)
		}
		if spec.InputTokenBudget == 0 || spec.OutputTokenBudget == 0 {
			return fmt.Errorf("tier %s budgets must be positive", tier)
		}
		if spec.MinContextTokens > maxTierTokens || spec.MinOutputTokens > maxTierTokens ||
			uint64(spec.InputTokenBudget)+uint64(spec.OutputTokenBudget) > maxTierTokens {
			return fmt.Errorf("tier %s exceeds token bounds", tier)
		}
		if spec.MinOutputTokens < spec.OutputTokenBudget {
			return fmt.Errorf("tier %s min output tokens must cover the output budget", tier)
		}
		if uint64(spec.MinContextTokens) < uint64(spec.InputTokenBudget)+uint64(spec.OutputTokenBudget) {
			return fmt.Errorf("tier %s min context tokens must cover input plus output budget", tier)
		}
		if index > 0 && (spec.MinContextTokens < previous.MinContextTokens || spec.MinOutputTokens < previous.MinOutputTokens ||
			spec.InputTokenBudget < previous.InputTokenBudget || spec.OutputTokenBudget < previous.OutputTokenBudget) {
			return fmt.Errorf("tier %s must not be smaller than the previous tier", tier)
		}
		previous = spec
	}
	return nil
}

func cloneActivation(activation Activation) Activation {
	clone := Activation{
		PathGlobs:   append([]string(nil), activation.PathGlobs...),
		Languages:   append([]Language(nil), activation.Languages...),
		FileClasses: append([]FileClass(nil), activation.FileClasses...),
		Signals:     append([]Signal(nil), activation.Signals...),
		Conditions:  append([]Condition(nil), activation.Conditions...),
	}
	sort.Strings(clone.PathGlobs)
	sort.Slice(clone.Languages, func(i, j int) bool { return clone.Languages[i] < clone.Languages[j] })
	sort.Slice(clone.FileClasses, func(i, j int) bool { return clone.FileClasses[i] < clone.FileClasses[j] })
	sort.Slice(clone.Signals, func(i, j int) bool { return clone.Signals[i] < clone.Signals[j] })
	sort.Slice(clone.Conditions, func(i, j int) bool { return clone.Conditions[i] < clone.Conditions[j] })
	return clone
}

func digestString(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

// Identity returns the SHA-256 identity of the canonical profile declaration.
func (p Profile) Identity() string { return p.identity }

// ID returns the profile identifier.
func (p Profile) ID() ProfileID { return p.id }

// Version returns the profile declaration version.
func (p Profile) Version() uint32 { return p.version }

// Purpose returns the one-line profile purpose.
func (p Profile) Purpose() string { return p.purpose }

// Priority returns the budget priority; higher priorities are kept first under a token cap.
func (p Profile) Priority() uint8 { return p.priority }

// ModelCall returns when the profile needs a model.
func (p Profile) ModelCall() ModelCall { return p.modelCall }

// Activation returns a defensive copy of the activation predicates.
func (p Profile) Activation() Activation { return cloneActivation(p.activation) }

// RequiredFeatures returns the required model features in canonical order.
func (p Profile) RequiredFeatures() []provider.ModelFeature {
	return append([]provider.ModelFeature(nil), p.requiredFeatures...)
}

// TierSpec returns the declared tier requirements and budget.
func (p Profile) TierSpec(tier Tier) (TierSpec, bool) {
	spec, ok := p.tiers[tier]
	return spec, ok
}

// Thresholds returns the score-to-tier thresholds.
func (p Profile) Thresholds() TierThresholds { return p.thresholds }

// Skill returns the embedded instruction markdown.
func (p Profile) Skill() string { return p.skill }

// SkillDigest returns the SHA-256 digest of the skill markdown.
func (p Profile) SkillDigest() string { return p.skillDigest }

// Authority returns the fixed candidate-only authority.
func (p Profile) Authority() Authority { return Authority{} }

// Requirements returns the provider-neutral model requirements for one tier.
func (p Profile) Requirements(tier Tier) (provider.ModelRequirements, error) {
	spec, ok := p.tiers[tier]
	if !ok {
		return provider.ModelRequirements{}, fmt.Errorf("%w: %s has no tier %s", ErrInvalidProfile, p.id, tier)
	}
	return provider.NewModelRequirements(uint64(spec.MinContextTokens), uint64(spec.MinOutputTokens), p.requiredFeatures)
}

// String returns a redacted description.
func (p Profile) String() string { return "agent profile" }

// GoString returns a redacted Go-syntax description.
func (p Profile) GoString() string { return "agentprofile.Profile{<redacted>}" }

// Validate verifies the content-derived identity.
func (p Profile) Validate() error {
	if p.identity == "" || p.identity != deriveIdentity(p.identityWire()) || p.skillDigest != digestString(p.skill) {
		return ErrInvalidProfileIdentity
	}
	return nil
}

// Wire encoding.

type tierSpecWire struct {
	Tier              string `json:"tier"`
	MinContextTokens  uint32 `json:"min_context_tokens"`
	MinOutputTokens   uint32 `json:"min_output_tokens"`
	InputTokenBudget  uint32 `json:"input_token_budget"`
	OutputTokenBudget uint32 `json:"output_token_budget"`
}

type activationWire struct {
	PathGlobs   []string `json:"path_globs"`
	Languages   []string `json:"languages"`
	FileClasses []string `json:"file_classes"`
	Signals     []string `json:"signals"`
	Conditions  []string `json:"conditions"`
}

type thresholdsWire struct {
	Standard uint32 `json:"standard"`
	Deep     uint32 `json:"deep"`
}

type authorityWire struct {
	CandidatesOnly                  bool `json:"candidates_only"`
	RequiresIndependentVerification bool `json:"requires_independent_verification"`
	ToolExecution                   bool `json:"tool_execution"`
	DynamicValidation               bool `json:"dynamic_validation"`
	NetworkAccess                   bool `json:"network_access"`
	Publication                     bool `json:"publication"`
	SourceMutation                  bool `json:"source_mutation"`
}

func (a Authority) wire() authorityWire {
	return authorityWire{
		CandidatesOnly: a.CandidatesOnly(), RequiresIndependentVerification: a.RequiresIndependentVerification(),
		ToolExecution: a.ToolExecution(), DynamicValidation: a.DynamicValidation(), NetworkAccess: a.NetworkAccess(),
		Publication: a.Publication(), SourceMutation: a.SourceMutation(),
	}
}

type profileIdentityWire struct {
	Contract         string         `json:"contract"`
	ID               string         `json:"id"`
	Version          uint32         `json:"version"`
	Purpose          string         `json:"purpose"`
	Priority         uint8          `json:"priority"`
	ModelCall        string         `json:"model_call"`
	Activation       activationWire `json:"activation"`
	RequiredFeatures []string       `json:"required_features"`
	Tiers            []tierSpecWire `json:"tiers"`
	Thresholds       thresholdsWire `json:"thresholds"`
	Authority        authorityWire  `json:"authority"`
	SkillDigest      string         `json:"skill_sha256"`
}

func (p Profile) identityWire() profileIdentityWire {
	wire := profileIdentityWire{
		Contract: "open-trestle/agent-profile", ID: string(p.id), Version: p.version, Purpose: p.purpose,
		Priority: p.priority, ModelCall: string(p.modelCall), Thresholds: thresholdsWire(p.thresholds),
		Authority: Authority{}.wire(), SkillDigest: p.skillDigest,
		Activation: activationWire{
			PathGlobs: nonNilStrings(p.activation.PathGlobs), Languages: stringsOf(p.activation.Languages),
			FileClasses: stringsOf(p.activation.FileClasses), Signals: stringsOf(p.activation.Signals),
			Conditions: stringsOf(p.activation.Conditions),
		},
		RequiredFeatures: []string{},
		Tiers:            []tierSpecWire{},
	}
	for _, feature := range p.requiredFeatures {
		wire.RequiredFeatures = append(wire.RequiredFeatures, feature.String())
	}
	for _, tier := range Tiers() {
		if spec, ok := p.tiers[tier]; ok {
			wire.Tiers = append(wire.Tiers, tierSpecWire{
				Tier: string(tier), MinContextTokens: spec.MinContextTokens, MinOutputTokens: spec.MinOutputTokens,
				InputTokenBudget: spec.InputTokenBudget, OutputTokenBudget: spec.OutputTokenBudget,
			})
		}
	}
	return wire
}

type profileWire struct {
	Identity string `json:"identity"`
	profileIdentityWire
	SkillBytes int    `json:"skill_bytes"`
	Skill      string `json:"skill"`
}

// MarshalJSON encodes the profile including its skill markdown.
func (p Profile) MarshalJSON() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(profileWire{Identity: p.identity, profileIdentityWire: p.identityWire(), SkillBytes: len(p.skill), Skill: p.skill})
}

func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func stringsOf[T ~string](values []T) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, string(value))
	}
	return out
}
