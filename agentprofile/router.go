package agentprofile

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
)

// RoutingPlan contract.
const (
	RoutingPlanContract = "open-trestle/agent-profile-routing-plan"
	RoutingPlanVersion  = 1
)

// ErrInvalidRoutingPlan identifies a plan whose content does not match its identity.
var ErrInvalidRoutingPlan = errors.New("invalid agent profile routing plan")

// EntryStatus is the planning outcome for one profile.
type EntryStatus string

const (
	// EntryPlanned means the profile has an exact generator route and budget.
	EntryPlanned EntryStatus = "planned"
	// EntryDeterministicOnly means the profile runs without a model (orchestrator, or knowledge graph with no gaps).
	EntryDeterministicOnly EntryStatus = "deterministic_only"
	// EntryInactive means no activation predicate matched the change.
	EntryInactive EntryStatus = "inactive"
	// EntryOmitted means the profile activated but will not run; see OmissionReason.
	EntryOmitted EntryStatus = "omitted"
)

// OmissionReason explains why an activated profile was omitted.
type OmissionReason string

const (
	// OmissionTierUnassigned means no route is assigned for the scored tier and no escalation order supplied one.
	OmissionTierUnassigned OmissionReason = "tier_unassigned"
	// OmissionBudgetCap means the profile was dropped to keep planned tokens within the configured cap.
	OmissionBudgetCap OmissionReason = "budget_cap_exceeded"
)

// Verification describes whether a planned profile's candidates can be independently verified.
type Verification string

const (
	// VerificationIndependent means a verifier route satisfying the independence policy is assigned.
	VerificationIndependent Verification = "independent"
	// VerificationUnverifiable means no independent verifier route is assigned; candidates cannot become findings.
	VerificationUnverifiable Verification = "unverifiable"
	// VerificationNotApplicable means the profile is not planned to call a model.
	VerificationNotApplicable Verification = "not_applicable"
)

// PlanEntry is the immutable routing decision for one profile.
type PlanEntry struct {
	profileID          ProfileID
	profileVersion     uint32
	profileIdentity    string
	priority           uint8
	modelCall          ModelCall
	activated          bool
	activationReasons  []string
	modelGaps          []string
	scored             bool
	difficulty         Difficulty
	scoredTier         Tier
	status             EntryStatus
	omission           OmissionReason
	omissionDetail     string
	hasGenerator       bool
	generator          routeSelection
	ranking            gateway.RouteRankingPolicy
	requirements       provider.ModelRequirements
	budget             TierSpec
	verification       Verification
	verificationDetail string
	hasVerifier        bool
	verifier           routeSelection
	verifierRanking    gateway.RouteRankingPolicy
	plannedTokens      uint64
}

// ProfileID returns the profile identifier.
func (e PlanEntry) ProfileID() ProfileID { return e.profileID }

// Status returns the planning outcome.
func (e PlanEntry) Status() EntryStatus { return e.status }

// Activated reports whether any activation predicate matched.
func (e PlanEntry) Activated() bool { return e.activated }

// ActivationReasons returns the matched predicates, or the reason none matched.
func (e PlanEntry) ActivationReasons() []string { return append([]string(nil), e.activationReasons...) }

// Difficulty returns the score breakdown and whether one was computed.
func (e PlanEntry) Difficulty() (Difficulty, bool) {
	clone := Difficulty{Score: e.difficulty.Score, Contributions: append([]DifficultyContribution(nil), e.difficulty.Contributions...)}
	return clone, e.scored
}

// ScoredTier returns the tier selected by the difficulty thresholds.
func (e PlanEntry) ScoredTier() Tier { return e.scoredTier }

// Omission returns the omission reason and detail for an omitted entry.
func (e PlanEntry) Omission() (OmissionReason, string) { return e.omission, e.omissionDetail }

// Requirements returns the model requirements for the scored tier.
func (e PlanEntry) Requirements() provider.ModelRequirements { return e.requirements }

// TokenBudget returns the scored tier's input and output token budget.
func (e PlanEntry) TokenBudget() TierSpec { return e.budget }

// CostBudget binds the token budget to a caller-supplied hard cost cap for gateway dispatch.
func (e PlanEntry) CostBudget(maxCostMicroUSD uint64) (provider.ModelCostBudget, error) {
	if !e.hasGenerator {
		return provider.ModelCostBudget{}, fmt.Errorf("%w: %s is not planned", ErrInvalidRoutingPlan, e.profileID)
	}
	return provider.NewModelCostBudget(uint64(e.budget.InputTokenBudget), uint64(e.budget.OutputTokenBudget), maxCostMicroUSD)
}

// Verification returns the verification status and its explanation.
func (e PlanEntry) Verification() (Verification, string) { return e.verification, e.verificationDetail }

// PlannedTokens returns the tokens counted toward the total cap (generator plus verifier budgets).
func (e PlanEntry) PlannedTokens() uint64 { return e.plannedTokens }

// String returns a redacted description.
func (e PlanEntry) String() string { return "agent profile plan entry" }

// GoString returns a redacted Go-syntax description.
func (e PlanEntry) GoString() string { return "agentprofile.PlanEntry{<redacted>}" }

// Omission records one activated profile that will not run.
type Omission struct {
	ProfileID ProfileID
	Reason    OmissionReason
	Detail    string
}

// RoutingPlan is the immutable, content-identified output of Plan.
//
// A RoutingPlan is advisory input to dispatch, not authority. It never
// bypasses gateway eligibility: the gateway still enforces provider policy
// zones, local-only requests, route capacity (max_output_tokens within output
// capacity; input plus output within context), cost budgets, and
// generator/verifier independence when each request is dispatched.
type RoutingPlan struct {
	identity            string
	catalogIdentity     string
	catalogVersion      uint32
	assignmentsIdentity string
	featuresIdentity    string
	independence        gateway.RouteIndependenceLevel
	escalationOrder     []Tier
	totalTokenBudget    uint64
	plannedTokens       uint64
	derived             derivedFeatures
	entries             []PlanEntry
	omissions           []Omission
}

type derivedFeatures struct {
	languages       []string
	fileClasses     []string
	securitySignals []string
	styleIntents    []string
	semanticGaps    []string
}

// Identity returns the SHA-256 identity of the canonical plan.
func (p RoutingPlan) Identity() string { return p.identity }

// CatalogIdentity returns the catalog identity the plan was made with.
func (p RoutingPlan) CatalogIdentity() string { return p.catalogIdentity }

// AssignmentsIdentity returns the assignments identity the plan was made with.
func (p RoutingPlan) AssignmentsIdentity() string { return p.assignmentsIdentity }

// FeaturesIdentity returns the change-features identity the plan was made with.
func (p RoutingPlan) FeaturesIdentity() string { return p.featuresIdentity }

// PlannedTokens returns the summed planned tokens of planned entries.
func (p RoutingPlan) PlannedTokens() uint64 { return p.plannedTokens }

// Entries returns one entry per catalog profile in profile-ID order.
func (p RoutingPlan) Entries() []PlanEntry { return append([]PlanEntry(nil), p.entries...) }

// Entry returns the entry for one profile.
func (p RoutingPlan) Entry(id ProfileID) (PlanEntry, bool) {
	for _, entry := range p.entries {
		if entry.profileID == id {
			return entry, true
		}
	}
	return PlanEntry{}, false
}

// Omissions returns omissions in decision order: unassigned tiers first (profile-ID order), then budget drops in drop order.
func (p RoutingPlan) Omissions() []Omission { return append([]Omission(nil), p.omissions...) }

// String returns a redacted description.
func (p RoutingPlan) String() string { return "agent profile routing plan" }

// GoString returns a redacted Go-syntax description.
func (p RoutingPlan) GoString() string { return "agentprofile.RoutingPlan{<redacted>}" }

// Validate verifies the content-derived identity.
func (p RoutingPlan) Validate() error {
	if p.identity == "" || p.identity != deriveIdentity(p.body()) {
		return ErrInvalidRoutingPlan
	}
	return nil
}

// Plan deterministically routes one change across the catalog. It performs no
// model call, no network access, reads no clock, and uses no randomness; the
// same inputs always yield the same plan identity. Plan never bypasses
// gateway eligibility, which still runs for every request at dispatch.
func Plan(catalog Catalog, assignments Assignments, features ChangeFeatures) (RoutingPlan, error) {
	if err := catalog.Validate(); err != nil {
		return RoutingPlan{}, err
	}
	if err := assignments.Validate(); err != nil {
		return RoutingPlan{}, err
	}
	if err := features.Validate(); err != nil {
		return RoutingPlan{}, err
	}
	plan := RoutingPlan{
		catalogIdentity: catalog.identity, catalogVersion: catalog.version,
		assignmentsIdentity: assignments.identity, featuresIdentity: features.identity,
		independence: assignments.independence.Level(), escalationOrder: assignments.EscalationOrder(),
		totalTokenBudget: assignments.totalTokenBudget, derived: deriveFeatureSummary(features),
	}
	for _, profile := range catalog.profiles {
		entry, err := planProfile(profile, assignments, features)
		if err != nil {
			return RoutingPlan{}, err
		}
		if entry.status == EntryOmitted {
			plan.omissions = append(plan.omissions, Omission{ProfileID: entry.profileID, Reason: entry.omission, Detail: entry.omissionDetail})
		}
		plan.entries = append(plan.entries, entry)
	}
	plan.applyBudgetCap()
	for _, entry := range plan.entries {
		plan.plannedTokens += entry.plannedTokens
	}
	plan.identity = deriveIdentity(plan.body())
	return plan, nil
}

func planProfile(profile Profile, assignments Assignments, features ChangeFeatures) (PlanEntry, error) {
	entry := PlanEntry{
		profileID: profile.id, profileVersion: profile.version, profileIdentity: profile.identity,
		priority: profile.priority, modelCall: profile.modelCall, verification: VerificationNotApplicable,
	}
	scope, reasons, activated := activate(profile, features)
	entry.activated, entry.activationReasons = activated, reasons
	if !activated {
		entry.status = EntryInactive
		return entry, nil
	}
	switch profile.modelCall {
	case ModelCallNone:
		entry.status = EntryDeterministicOnly
		return entry, nil
	case ModelCallGapOnly:
		entry.modelGaps = features.semanticGaps()
		if len(entry.modelGaps) == 0 {
			entry.status = EntryDeterministicOnly
			return entry, nil
		}
	}
	entry.scored = true
	entry.difficulty = scoreDifficulty(scope, features)
	entry.scoredTier = tierForScore(entry.difficulty.Score, profile.thresholds)
	requirements, err := profile.Requirements(entry.scoredTier)
	if err != nil {
		return PlanEntry{}, err
	}
	entry.requirements = requirements
	entry.budget, _ = profile.TierSpec(entry.scoredTier)
	generator, ok := assignments.resolve(profile.id, entry.scoredTier, false)
	if !ok {
		entry.status = EntryOmitted
		entry.omission = OmissionTierUnassigned
		entry.omissionDetail = fmt.Sprintf("no generator route is assigned for tier %s and no escalation order supplies one", entry.scoredTier)
		return entry, nil
	}
	ranking, err := gateway.NewPinnedRouteRankingPolicy(generator.route, nil)
	if err != nil {
		return PlanEntry{}, err
	}
	entry.status, entry.hasGenerator, entry.generator, entry.ranking = EntryPlanned, true, generator, ranking
	tokens := uint64(entry.budget.InputTokenBudget) + uint64(entry.budget.OutputTokenBudget)
	entry.plannedTokens = tokens
	verifier, ok := assignments.resolve(profile.id, entry.scoredTier, true)
	switch {
	case !ok:
		entry.verification = VerificationUnverifiable
		entry.verificationDetail = fmt.Sprintf("no verifier route is assigned for tier %s; candidates cannot become findings", entry.scoredTier)
	case !routesIndependent(assignments.independence.Level(), generator.route, verifier.route):
		entry.verification = VerificationUnverifiable
		entry.verificationDetail = fmt.Sprintf("the assigned verifier route is not %s from the generator route; candidates cannot become findings", assignments.independence.Level())
	default:
		verifierRanking, err := gateway.NewPinnedRouteRankingPolicy(verifier.route, nil)
		if err != nil {
			return PlanEntry{}, err
		}
		entry.verification, entry.hasVerifier, entry.verifier, entry.verifierRanking = VerificationIndependent, true, verifier, verifierRanking
		entry.verificationDetail = fmt.Sprintf("verifier route satisfies %s; the gateway re-checks independence at dispatch", assignments.independence.Level())
		entry.plannedTokens += tokens
	}
	return entry, nil
}

// routesIndependent mirrors the gateway's static separation rule
// (internal/gateway route_independence.go) for unresolved route references.
// The gateway re-verifies independence on resolved records at dispatch.
func routesIndependent(level gateway.RouteIndependenceLevel, first, second provider.RouteReference) bool {
	switch level {
	case gateway.RouteIndependenceDistinctRoute:
		return first != second
	case gateway.RouteIndependenceDistinctModel:
		return first.ProviderID() != second.ProviderID() || first.ModelID() != second.ModelID() || first.ModelVersion() != second.ModelVersion()
	case gateway.RouteIndependenceDistinctProvider:
		return first.ProviderID() != second.ProviderID()
	default:
		return false
	}
}

// applyBudgetCap drops planned entries, lowest priority first (ties: higher
// profile ID first), until planned tokens fit the cap. Each drop is recorded.
func (p *RoutingPlan) applyBudgetCap() {
	if p.totalTokenBudget == 0 {
		return
	}
	var total uint64
	var planned []int
	for index, entry := range p.entries {
		if entry.status == EntryPlanned {
			total += entry.plannedTokens
			planned = append(planned, index)
		}
	}
	sort.Slice(planned, func(i, j int) bool {
		left, right := p.entries[planned[i]], p.entries[planned[j]]
		if left.priority != right.priority {
			return left.priority < right.priority
		}
		return left.profileID > right.profileID
	})
	for _, index := range planned {
		if total <= p.totalTokenBudget {
			return
		}
		entry := &p.entries[index]
		before := total
		total -= entry.plannedTokens
		entry.omissionDetail = fmt.Sprintf("dropped at priority %d: planned tokens %d exceeded cap %d; %d remain after dropping %d", entry.priority, before, p.totalTokenBudget, total, entry.plannedTokens)
		entry.status, entry.omission = EntryOmitted, OmissionBudgetCap
		entry.hasGenerator, entry.generator, entry.ranking = false, routeSelection{}, gateway.RouteRankingPolicy{}
		entry.hasVerifier, entry.verifier, entry.verifierRanking = false, routeSelection{}, gateway.RouteRankingPolicy{}
		entry.verification, entry.verificationDetail = VerificationNotApplicable, ""
		entry.plannedTokens = 0
		p.omissions = append(p.omissions, Omission{ProfileID: entry.profileID, Reason: OmissionBudgetCap, Detail: entry.omissionDetail})
	}
}

// eligibleFiles excludes vendor and generated files, which never activate or score a profile.
func eligibleFiles(features ChangeFeatures) []changedFile {
	files := make([]changedFile, 0, len(features.files))
	for _, file := range features.files {
		if file.class != FileClassVendor && file.class != FileClassGenerated {
			files = append(files, file)
		}
	}
	return files
}

// activate evaluates OR-combined predicates and returns the scope, reasons, and outcome.
func activate(profile Profile, features ChangeFeatures) ([]changedFile, []string, bool) {
	files := eligibleFiles(features)
	always := false
	inScope := make([]bool, len(files))
	counts := map[string]int{}
	conditionReasons := []string{}
	mark := func(index int, reason string) {
		inScope[index] = true
		counts[reason]++
	}
	activation := profile.activation
	for index, file := range files {
		for _, glob := range activation.PathGlobs {
			if matchGlob(glob, file.path) {
				mark(index, "path_glob:"+glob)
			}
		}
		for _, language := range activation.Languages {
			if file.hasLanguage && file.language == language {
				mark(index, "language:"+string(language))
			}
		}
		for _, class := range activation.FileClasses {
			if file.class == class {
				mark(index, "file_class:"+string(class))
			}
		}
		for _, signal := range activation.Signals {
			if containsSignal(file.signals, signal) {
				mark(index, "signal:"+string(signal))
			}
		}
	}
	for _, condition := range activation.Conditions {
		switch condition {
		case ConditionAlways:
			always = true
			conditionReasons = append(conditionReasons, "condition:always")
			for index := range files {
				inScope[index] = true
			}
		case ConditionIntentDeclared:
			if features.descriptionPresent || len(features.linkedDocPaths) > 0 {
				conditionReasons = append(conditionReasons, fmt.Sprintf("condition:intent_declared (description=%t, linked_docs=%d)", features.descriptionPresent, len(features.linkedDocPaths)))
				for index := range files {
					inScope[index] = true
				}
			}
		case ConditionDocsAndCodeChanged:
			if features.hasClass(FileClassDocs) && features.hasSourceFile() {
				conditionReasons = append(conditionReasons, "condition:docs_and_code_changed")
				for index, file := range files {
					if file.class == FileClassDocs || file.class == FileClassSource {
						inScope[index] = true
					}
				}
			}
		case ConditionDeclaredStyleMatches:
			matched := map[StyleIntent]int{}
			for index, file := range files {
				if !file.hasLanguage {
					continue
				}
				for _, intent := range features.styleIntents {
					if styleGoverns(intent, file.language) {
						matched[intent]++
						inScope[index] = true
					}
				}
			}
			for _, intent := range features.styleIntents {
				if matched[intent] > 0 {
					conditionReasons = append(conditionReasons, fmt.Sprintf("condition:declared_style %s (files=%d)", intent, matched[intent]))
				}
			}
		}
	}
	scope := make([]changedFile, 0, len(files))
	for index, file := range files {
		if inScope[index] {
			scope = append(scope, file)
		}
	}
	reasons := make([]string, 0, len(counts)+len(conditionReasons))
	for reason, count := range counts {
		reasons = append(reasons, fmt.Sprintf("%s (files=%d)", reason, count))
	}
	sort.Strings(reasons)
	reasons = append(reasons, conditionReasons...)
	if len(reasons) == 0 || len(scope) == 0 && !always {
		return nil, []string{"no changed file matched the profile's path globs, languages, file classes, signals, or conditions"}, false
	}
	return scope, reasons, true
}

// FeatureSummary is the catalog-independent projection the router derives from
// change features: sorted languages, file classes and security signals, and the
// count of semantic gaps.
type FeatureSummary struct {
	Languages, FileClasses, SecuritySignals []string
	SemanticGaps                            int
}

// Summary derives the same languages, file classes, security signals and
// semantic-gap count a routing plan records, without a catalog or route
// assignments. It is available when planning is not, for example when the
// general review's verification failed after its change was recorded.
func (f ChangeFeatures) Summary() FeatureSummary {
	derived := deriveFeatureSummary(f)
	return FeatureSummary{
		Languages: append([]string{}, derived.languages...), FileClasses: append([]string{}, derived.fileClasses...),
		SecuritySignals: append([]string{}, derived.securitySignals...), SemanticGaps: len(derived.semanticGaps),
	}
}

func deriveFeatureSummary(features ChangeFeatures) derivedFeatures {
	languages, classes, security := map[string]struct{}{}, map[string]struct{}{}, map[string]struct{}{}
	for _, file := range features.files {
		if file.hasLanguage {
			languages[string(file.language)] = struct{}{}
		}
		classes[string(file.class)] = struct{}{}
		for _, signal := range file.signals {
			if signal.IsSecurity() {
				security[string(signal)] = struct{}{}
			}
		}
	}
	return derivedFeatures{
		languages: sortedKeys(languages), fileClasses: sortedKeys(classes), securitySignals: sortedKeys(security),
		styleIntents: stringsOf(features.styleIntents), semanticGaps: nonNilStrings(features.semanticGaps()),
	}
}

func sortedKeys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for key := range set {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

// Wire encoding.

type routeSelectionWire struct {
	Route                 routeWire `json:"route"`
	Tier                  string    `json:"tier"`
	Source                string    `json:"source"`
	EscalatedFrom         string    `json:"escalated_from,omitempty"`
	RankingPolicyIdentity string    `json:"ranking_policy_identity"`
}

type contributionWire struct {
	Signal   string `json:"signal"`
	Observed uint64 `json:"observed"`
	Points   uint64 `json:"points"`
	Cap      uint64 `json:"cap"`
	Note     string `json:"note"`
}

type difficultyWire struct {
	Score    uint64             `json:"score"`
	MaxScore uint64             `json:"max_score"`
	Signals  []contributionWire `json:"signals"`
}

type requirementsWire struct {
	MinContextTokens uint32   `json:"min_context_tokens"`
	MinOutputTokens  uint32   `json:"min_output_tokens"`
	RequiredFeatures []string `json:"required_features"`
}

type budgetWire struct {
	InputTokens  uint32 `json:"input_tokens"`
	OutputTokens uint32 `json:"output_tokens"`
}

type entryWire struct {
	ProfileID          string              `json:"profile_id"`
	ProfileVersion     uint32              `json:"profile_version"`
	ProfileIdentity    string              `json:"profile_identity"`
	Priority           uint8               `json:"priority"`
	ModelCall          string              `json:"model_call"`
	Status             string              `json:"status"`
	Activated          bool                `json:"activated"`
	ActivationReasons  []string            `json:"activation_reasons"`
	ModelGaps          []string            `json:"model_gaps,omitempty"`
	Difficulty         *difficultyWire     `json:"difficulty,omitempty"`
	ScoredTier         string              `json:"scored_tier,omitempty"`
	Requirements       *requirementsWire   `json:"requirements,omitempty"`
	TokenBudget        *budgetWire         `json:"token_budget,omitempty"`
	Generator          *routeSelectionWire `json:"generator,omitempty"`
	Verification       string              `json:"verification"`
	VerificationDetail string              `json:"verification_detail,omitempty"`
	Verifier           *routeSelectionWire `json:"verifier,omitempty"`
	PlannedTokens      uint64              `json:"planned_tokens"`
	Omission           string              `json:"omission,omitempty"`
	OmissionDetail     string              `json:"omission_detail,omitempty"`
	Authority          authorityWire       `json:"authority"`
}

type omissionWire struct {
	ProfileID string `json:"profile_id"`
	Reason    string `json:"reason"`
	Detail    string `json:"detail"`
}

type derivedWire struct {
	Languages       []string `json:"languages"`
	FileClasses     []string `json:"file_classes"`
	SecuritySignals []string `json:"security_signals"`
	StyleIntents    []string `json:"style_intents"`
	SemanticGaps    []string `json:"semantic_gaps"`
}

type planBodyWire struct {
	Contract            string         `json:"contract"`
	Version             int            `json:"version"`
	CatalogIdentity     string         `json:"catalog_identity"`
	CatalogVersion      uint32         `json:"catalog_version"`
	AssignmentsIdentity string         `json:"assignments_identity"`
	FeaturesIdentity    string         `json:"features_identity"`
	Independence        string         `json:"independence"`
	EscalationOrder     []string       `json:"escalation_order"`
	TotalTokenBudget    uint64         `json:"total_token_budget"`
	PlannedTokens       uint64         `json:"planned_tokens"`
	GatewayEligibility  string         `json:"gateway_eligibility"`
	Derived             derivedWire    `json:"derived_features"`
	Entries             []entryWire    `json:"entries"`
	Omissions           []omissionWire `json:"omissions"`
}

const gatewayEligibilityNote = "not bypassed: provider zones, local-only, capacity, cost budgets, and verifier independence are enforced by internal/gateway at dispatch"

func selectionWire(selection routeSelection, ranking gateway.RouteRankingPolicy) *routeSelectionWire {
	return &routeSelectionWire{
		Route: routeToWire(selection.route), Tier: string(selection.tier), Source: string(selection.source),
		EscalatedFrom: string(selection.escalatedFrom), RankingPolicyIdentity: ranking.Identity(),
	}
}

func (e PlanEntry) wire() entryWire {
	wire := entryWire{
		ProfileID: string(e.profileID), ProfileVersion: e.profileVersion, ProfileIdentity: e.profileIdentity,
		Priority: e.priority, ModelCall: string(e.modelCall), Status: string(e.status), Activated: e.activated,
		ActivationReasons: nonNilStrings(e.activationReasons), ModelGaps: e.modelGaps,
		Verification: string(e.verification), VerificationDetail: e.verificationDetail,
		PlannedTokens: e.plannedTokens, Omission: string(e.omission), OmissionDetail: e.omissionDetail,
		Authority: Authority{}.wire(),
	}
	if e.scored {
		difficulty := &difficultyWire{Score: e.difficulty.Score, MaxScore: maxDifficultyScore, Signals: []contributionWire{}}
		for _, row := range e.difficulty.Contributions {
			difficulty.Signals = append(difficulty.Signals, contributionWire{Signal: string(row.Signal), Observed: row.Observed, Points: row.Points, Cap: row.Cap, Note: row.Note})
		}
		wire.Difficulty = difficulty
		wire.ScoredTier = string(e.scoredTier)
		features := []string{}
		for _, feature := range e.requirements.RequiredFeatures() {
			features = append(features, feature.String())
		}
		wire.Requirements = &requirementsWire{MinContextTokens: e.requirements.MinContextTokens(), MinOutputTokens: e.requirements.MinOutputTokens(), RequiredFeatures: features}
		wire.TokenBudget = &budgetWire{InputTokens: e.budget.InputTokenBudget, OutputTokens: e.budget.OutputTokenBudget}
	}
	if e.hasGenerator {
		wire.Generator = selectionWire(e.generator, e.ranking)
	}
	if e.hasVerifier {
		wire.Verifier = selectionWire(e.verifier, e.verifierRanking)
	}
	return wire
}

func (p RoutingPlan) body() planBodyWire {
	body := planBodyWire{
		Contract: RoutingPlanContract, Version: RoutingPlanVersion, CatalogIdentity: p.catalogIdentity,
		CatalogVersion: p.catalogVersion, AssignmentsIdentity: p.assignmentsIdentity, FeaturesIdentity: p.featuresIdentity,
		Independence: p.independence.String(), EscalationOrder: stringsOf(p.escalationOrder),
		TotalTokenBudget: p.totalTokenBudget, PlannedTokens: p.plannedTokens, GatewayEligibility: gatewayEligibilityNote,
		Derived: derivedWire{
			Languages: p.derived.languages, FileClasses: p.derived.fileClasses, SecuritySignals: p.derived.securitySignals,
			StyleIntents: p.derived.styleIntents, SemanticGaps: p.derived.semanticGaps,
		},
		Entries: []entryWire{}, Omissions: []omissionWire{},
	}
	for _, entry := range p.entries {
		body.Entries = append(body.Entries, entry.wire())
	}
	for _, omission := range p.omissions {
		body.Omissions = append(body.Omissions, omissionWire{ProfileID: string(omission.ProfileID), Reason: string(omission.Reason), Detail: omission.Detail})
	}
	return body
}

// MarshalJSON encodes the canonical plan with its identity.
func (p RoutingPlan) MarshalJSON() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Identity string `json:"identity"`
		planBodyWire
	}{Identity: p.identity, planBodyWire: p.body()})
}
