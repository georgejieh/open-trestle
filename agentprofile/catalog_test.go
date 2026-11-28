package agentprofile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/provider"
)

// Golden identities. A change here means a profile, skill, scoring row, or
// catalog contract changed; bump CatalogVersion or the profile version and
// update these deliberately.
const (
	goldenCatalogIdentity = "e106e7d5503e6cbaed154f82f500b04c20ce31591f5e253766872eb169e637a6"
)

func TestProfileDefaultCatalogValidatesAllNineProfiles(t *testing.T) {
	catalog := mustCatalog(t)
	if err := catalog.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	profiles := catalog.Profiles()
	if len(profiles) != len(knownProfileIDs) {
		t.Fatalf("profiles = %d, want %d", len(profiles), len(knownProfileIDs))
	}
	for index, profile := range profiles {
		if profile.ID() != knownProfileIDs[index] {
			t.Fatalf("profile %d = %s, want %s (canonical order)", index, profile.ID(), knownProfileIDs[index])
		}
		if !strings.HasPrefix(profile.Skill(), "# ") || len(profile.Skill()) < 600 || profile.SkillDigest() != digestString(profile.Skill()) {
			t.Fatalf("%s skill is missing, too short, or misdigested", profile.ID())
		}
		authority := profile.Authority()
		if !authority.CandidatesOnly() || !authority.RequiresIndependentVerification() || authority.ToolExecution() ||
			authority.DynamicValidation() || authority.NetworkAccess() || authority.Publication() || authority.SourceMutation() {
			t.Fatalf("%s authority is not candidate-only", profile.ID())
		}
		if profile.ID() == ProfileOrchestrator {
			if profile.ModelCall() != ModelCallNone {
				t.Fatal("orchestrator must be model-free")
			}
			continue
		}
		for _, tier := range Tiers() {
			requirements, err := profile.Requirements(tier)
			if err != nil || !requirements.Requires(provider.ModelFeatureStructuredOutput) {
				t.Fatalf("%s %s requirements = %v, %v", profile.ID(), tier, requirements, err)
			}
		}
	}
}

func TestProfileCatalogIdentityGolden(t *testing.T) {
	first, second := mustCatalog(t), mustCatalog(t)
	if first.Identity() != second.Identity() || !validDigest(first.Identity()) {
		t.Fatalf("catalog identity unstable: %q vs %q", first.Identity(), second.Identity())
	}
	if first.Identity() != goldenCatalogIdentity {
		t.Fatalf("catalog identity = %s, want golden %s", first.Identity(), goldenCatalogIdentity)
	}
	reordered, err := NewCatalog(CatalogVersion, reverseProfiles(first.Profiles()))
	if err != nil || reordered.Identity() != first.Identity() {
		t.Fatalf("catalog identity depends on input order: %v", err)
	}
	bumped, err := NewCatalog(CatalogVersion+1, first.Profiles())
	if err != nil || bumped.Identity() == first.Identity() {
		t.Fatalf("catalog version is not bound into identity: %v", err)
	}
}

func TestProfileIdentityChangesWithSkillAndThresholds(t *testing.T) {
	specs, err := packagedProfileSpecs()
	if err != nil {
		t.Fatal(err)
	}
	var spec ProfileSpec
	for _, candidate := range specs {
		if candidate.ID == ProfileBugHunter {
			spec = candidate
		}
	}
	base, err := NewProfile(spec)
	if err != nil {
		t.Fatal(err)
	}
	edited := spec
	edited.Skill += "\nextra line\n"
	withSkill, err := NewProfile(edited)
	if err != nil || withSkill.Identity() == base.Identity() {
		t.Fatalf("skill content is not bound into identity: %v", err)
	}
	edited = spec
	edited.Thresholds.Deep++
	withThreshold, err := NewProfile(edited)
	if err != nil || withThreshold.Identity() == base.Identity() {
		t.Fatalf("thresholds are not bound into identity: %v", err)
	}
}

func reverseProfiles(profiles []Profile) []Profile {
	out := make([]Profile, len(profiles))
	for index, profile := range profiles {
		out[len(profiles)-1-index] = profile
	}
	return out
}

func validSpec(t *testing.T) ProfileSpec {
	t.Helper()
	return ProfileSpec{
		ID: ProfileBugHunter, Version: 1, Purpose: "Find bugs.", Priority: 50, ModelCall: ModelCallRequired,
		Activation:       Activation{FileClasses: []FileClass{FileClassSource}},
		RequiredFeatures: []provider.ModelFeature{provider.ModelFeatureStructuredOutput},
		Tiers:            cloneTierSpecs(reviewTiers), Thresholds: TierThresholds{Standard: 10, Deep: 20},
		Skill: "# Bug hunter\n\nChecklist.\n",
	}
}

func cloneTierSpecs(in map[Tier]TierSpec) map[Tier]TierSpec {
	out := make(map[Tier]TierSpec, len(in))
	for tier, spec := range in {
		out[tier] = spec
	}
	return out
}

func TestProfileNewProfileRejectsInvalidDeclarations(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*ProfileSpec)
	}{
		{"unknown id", func(s *ProfileSpec) { s.ID = "linter" }},
		{"zero version", func(s *ProfileSpec) { s.Version = 0 }},
		{"empty purpose", func(s *ProfileSpec) { s.Purpose = "  " }},
		{"control character purpose", func(s *ProfileSpec) { s.Purpose = "a\x07b" }},
		{"zero priority", func(s *ProfileSpec) { s.Priority = 0 }},
		{"priority above 100", func(s *ProfileSpec) { s.Priority = 101 }},
		{"unknown model call", func(s *ProfileSpec) { s.ModelCall = "sometimes" }},
		{"model-free non-orchestrator", func(s *ProfileSpec) { s.ModelCall = ModelCallNone }},
		{"orchestrator with model", func(s *ProfileSpec) { s.ID = ProfileOrchestrator }},
		{"empty activation", func(s *ProfileSpec) { s.Activation = Activation{} }},
		{"bad glob", func(s *ProfileSpec) { s.Activation.PathGlobs = []string{"src/[a"} }},
		{"absolute glob", func(s *ProfileSpec) { s.Activation.PathGlobs = []string{"/etc/*"} }},
		{"partial double star", func(s *ProfileSpec) { s.Activation.PathGlobs = []string{"src/a**"} }},
		{"vendor activation", func(s *ProfileSpec) { s.Activation.FileClasses = []FileClass{FileClassVendor} }},
		{"unknown language", func(s *ProfileSpec) { s.Activation.Languages = []Language{"cobol"} }},
		{"duplicate language", func(s *ProfileSpec) { s.Activation.Languages = []Language{LanguageGo, LanguageGo} }},
		{"unknown signal", func(s *ProfileSpec) { s.Activation.Signals = []Signal{"magic"} }},
		{"unknown condition", func(s *ProfileSpec) { s.Activation.Conditions = []Condition{"sometimes"} }},
		{"duplicate feature", func(s *ProfileSpec) {
			s.RequiredFeatures = []provider.ModelFeature{provider.ModelFeatureVision, provider.ModelFeatureVision}
		}},
		{"unknown feature", func(s *ProfileSpec) { s.RequiredFeatures = []provider.ModelFeature{99} }},
		{"missing tier", func(s *ProfileSpec) { delete(s.Tiers, TierDeep) }},
		{"zero budget", func(s *ProfileSpec) { spec := s.Tiers[TierLight]; spec.InputTokenBudget = 0; s.Tiers[TierLight] = spec }},
		{"min output below budget", func(s *ProfileSpec) {
			spec := s.Tiers[TierLight]
			spec.MinOutputTokens = spec.OutputTokenBudget - 1
			s.Tiers[TierLight] = spec
		}},
		{"min context below budgets", func(s *ProfileSpec) {
			spec := s.Tiers[TierLight]
			spec.MinContextTokens = spec.InputTokenBudget + spec.OutputTokenBudget - 1
			s.Tiers[TierLight] = spec
		}},
		{"shrinking tier", func(s *ProfileSpec) { s.Tiers[TierDeep] = s.Tiers[TierLight] }},
		{"zero standard threshold", func(s *ProfileSpec) { s.Thresholds = TierThresholds{Standard: 0, Deep: 20} }},
		{"inverted thresholds", func(s *ProfileSpec) { s.Thresholds = TierThresholds{Standard: 20, Deep: 20} }},
		{"threshold above max score", func(s *ProfileSpec) { s.Thresholds = TierThresholds{Standard: 10, Deep: maxDifficultyScore + 1} }},
		{"skill without heading", func(s *ProfileSpec) { s.Skill = "no heading" }},
		{"skill too large", func(s *ProfileSpec) { s.Skill = "# x\n" + strings.Repeat("a", maxSkillBytes) }},
		{"invalid utf8 skill", func(s *ProfileSpec) { s.Skill = "# x\n\xff" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			spec := validSpec(t)
			test.mutate(&spec)
			if _, err := NewProfile(spec); !errors.Is(err, ErrInvalidProfile) {
				t.Fatalf("NewProfile() error = %v, want ErrInvalidProfile", err)
			}
		})
	}
	if _, err := NewProfile(validSpec(t)); err != nil {
		t.Fatalf("valid spec rejected: %v", err)
	}
}

func TestProfileModelFreeProfileRejectsTiers(t *testing.T) {
	spec := ProfileSpec{
		ID: ProfileOrchestrator, Version: 1, Purpose: "Route.", Priority: 100, ModelCall: ModelCallNone,
		Activation: Activation{Conditions: []Condition{ConditionAlways}}, Skill: "# Orchestrator\n",
		Tiers: cloneTierSpecs(reviewTiers),
	}
	if _, err := NewProfile(spec); !errors.Is(err, ErrInvalidProfile) {
		t.Fatalf("NewProfile() error = %v", err)
	}
}

func TestProfileNewCatalogRejectsInvalidSets(t *testing.T) {
	catalog := mustCatalog(t)
	profiles := catalog.Profiles()
	bugHunter, _ := catalog.Profile(ProfileBugHunter)
	withoutOrchestrator := []Profile{}
	for _, profile := range profiles {
		if profile.ID() != ProfileOrchestrator {
			withoutOrchestrator = append(withoutOrchestrator, profile)
		}
	}
	tampered := bugHunter
	tampered.priority = 1
	for _, test := range []struct {
		name     string
		version  uint32
		profiles []Profile
		want     error
	}{
		{"zero version", 0, profiles, ErrInvalidCatalog},
		{"empty", CatalogVersion, nil, ErrInvalidCatalog},
		{"duplicate", CatalogVersion, append(append([]Profile(nil), profiles[:8]...), bugHunter), ErrInvalidCatalog},
		{"missing orchestrator", CatalogVersion, withoutOrchestrator, ErrInvalidCatalog},
		{"tampered profile", CatalogVersion, []Profile{profiles[5], tampered}, ErrInvalidProfileIdentity},
		{"zero profile", CatalogVersion, []Profile{{}}, ErrInvalidProfileIdentity},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewCatalog(test.version, test.profiles); !errors.Is(err, test.want) {
				t.Fatalf("NewCatalog() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestProfileCatalogJSONExposesSkillsScoringAndCandidateOnlyAuthority(t *testing.T) {
	catalog := mustCatalog(t)
	encoded, err := json.Marshal(catalog)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Contract string `json:"contract"`
		Identity string `json:"identity"`
		Scoring  []struct {
			Signal string `json:"signal"`
		} `json:"scoring"`
		Profiles []struct {
			ID        string        `json:"id"`
			Identity  string        `json:"identity"`
			Skill     string        `json:"skill"`
			Authority authorityWire `json:"authority"`
		} `json:"profiles"`
	}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Contract != CatalogContract || decoded.Identity != catalog.Identity() || len(decoded.Scoring) != len(difficultyWeights) || len(decoded.Profiles) != 9 {
		t.Fatalf("catalog JSON = %s", encoded)
	}
	for _, profile := range decoded.Profiles {
		want := authorityWire{CandidatesOnly: true, RequiresIndependentVerification: true}
		if profile.Authority != want || profile.Skill == "" || !validDigest(profile.Identity) {
			t.Fatalf("profile %s JSON = %+v", profile.ID, profile.Authority)
		}
	}
	if !bytes.Contains(encoded, []byte(`"dynamic_validation":false`)) || !bytes.Contains(encoded, []byte(`"tool_execution":false`)) {
		t.Fatal("catalog JSON does not state disabled execution authority")
	}
}

func TestProfileCatalogRedactsFormatting(t *testing.T) {
	catalog := mustCatalog(t)
	profile, _ := catalog.Profile(ProfileSecurityProbe)
	for _, value := range []string{fmt.Sprint(catalog), fmt.Sprintf("%#v", catalog), fmt.Sprint(profile), fmt.Sprintf("%#v", profile)} {
		if strings.Contains(value, "Strix") || strings.Contains(value, "security_probe") {
			t.Fatalf("formatting leaked content: %q", value)
		}
	}
}

func TestProfileScoringTableMaxScoreMatchesCaps(t *testing.T) {
	var total uint64
	seen := map[DifficultySignal]bool{}
	for _, weight := range difficultyWeights {
		if weight.divisor == 0 || weight.points == 0 || weight.cap == 0 || seen[weight.signal] {
			t.Fatalf("invalid scoring row %+v", weight)
		}
		seen[weight.signal] = true
		total += weight.cap
	}
	if total != maxDifficultyScore {
		t.Fatalf("sum of caps = %d, maxDifficultyScore = %d", total, maxDifficultyScore)
	}
	for _, id := range knownProfileIDs {
		if id == ProfileOrchestrator {
			continue
		}
		if _, ok := profileTierThresholds[id]; !ok {
			t.Fatalf("%s has no declared thresholds", id)
		}
	}
}
