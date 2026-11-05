package agentprofile

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
)

// goldenPlanIdentity pins broadChange planned with fullAssignments against the packaged catalog.
const goldenPlanIdentity = "1f37ce69b9b4329fa2be60b104713372c0ff475060b80f3654aa5d7846280ed4"

func goChangeWithTest(addedLines uint32) ChangeFeaturesSpec {
	return ChangeFeaturesSpec{Files: []ChangedFileSpec{
		{Path: "lib/core.go", AddedLines: addedLines},
		{Path: "lib/core_test.go", AddedLines: 1},
	}}
}

func TestProfileActivation(t *testing.T) {
	catalog := mustCatalog(t)
	assignments := fullAssignments(t, catalog)
	for _, test := range []struct {
		name string
		spec ChangeFeaturesSpec
		want map[ProfileID]EntryStatus
	}{
		{
			name: "go only without config or intent",
			spec: goChangeWithTest(30),
			want: map[ProfileID]EntryStatus{
				ProfileOrchestrator: EntryDeterministicOnly, ProfileKnowledgeGraph: EntryDeterministicOnly,
				ProfileSecurityProbe: EntryInactive, ProfileFrontend: EntryInactive, ProfileBackend: EntryPlanned,
				ProfileTestAuthor: EntryPlanned, ProfileStyleConformance: EntryInactive, ProfileBugHunter: EntryPlanned,
				ProfileDriftAuditor: EntryInactive,
			},
		},
		{
			name: "web change activates frontend and a knowledge graph gap",
			spec: ChangeFeaturesSpec{Files: []ChangedFileSpec{{Path: "web/src/App.tsx", AddedLines: 20}}},
			want: map[ProfileID]EntryStatus{
				ProfileFrontend: EntryPlanned, ProfileBackend: EntryInactive, ProfileKnowledgeGraph: EntryPlanned,
				ProfileStyleConformance: EntryInactive, ProfileSecurityProbe: EntryInactive,
			},
		},
		{
			name: "declared gofmt activates style for go",
			spec: ChangeFeaturesSpec{Files: goChangeWithTest(5).Files, ConfigFiles: []ConfigFile{{Path: "go.mod"}}},
			want: map[ProfileID]EntryStatus{ProfileStyleConformance: EntryPlanned, ProfileFrontend: EntryInactive},
		},
		{
			name: "declared prettier does not activate style for go",
			spec: ChangeFeaturesSpec{Files: goChangeWithTest(5).Files, ConfigFiles: []ConfigFile{{Path: ".prettierrc"}}},
			want: map[ProfileID]EntryStatus{ProfileStyleConformance: EntryInactive},
		},
		{
			name: "docs and code activate drift",
			spec: ChangeFeaturesSpec{Files: []ChangedFileSpec{{Path: "lib/core.go", AddedLines: 3}, {Path: "docs/core.md", AddedLines: 3}}},
			want: map[ProfileID]EntryStatus{ProfileDriftAuditor: EntryPlanned},
		},
		{
			name: "declared description activates drift",
			spec: ChangeFeaturesSpec{Files: goChangeWithTest(3).Files, Intent: IntentSpec{DescriptionPresent: true}},
			want: map[ProfileID]EntryStatus{ProfileDriftAuditor: EntryPlanned},
		},
		{
			name: "auth path activates security probe",
			spec: ChangeFeaturesSpec{Files: []ChangedFileSpec{{Path: "internal/auth/session.go", AddedLines: 3}}},
			want: map[ProfileID]EntryStatus{ProfileSecurityProbe: EntryPlanned},
		},
		{
			name: "secret file glob activates security probe",
			spec: ChangeFeaturesSpec{Files: []ChangedFileSpec{{Path: "deploy/.env.production", AddedLines: 1}}},
			want: map[ProfileID]EntryStatus{ProfileSecurityProbe: EntryPlanned, ProfileBugHunter: EntryInactive},
		},
		{
			name: "analyzer concurrency signal activates backend",
			spec: ChangeFeaturesSpec{Files: []ChangedFileSpec{{Path: "web/src/worker.ts", AddedLines: 3, Signals: []Signal{SignalConcurrency}}}},
			want: map[ProfileID]EntryStatus{ProfileBackend: EntryPlanned, ProfileFrontend: EntryPlanned},
		},
		{
			name: "vendor-only change activates only the orchestrator",
			spec: ChangeFeaturesSpec{Files: []ChangedFileSpec{{Path: "vendor/example.com/auth/token.go", AddedLines: 400}}, Intent: IntentSpec{}},
			want: map[ProfileID]EntryStatus{
				ProfileOrchestrator: EntryDeterministicOnly, ProfileKnowledgeGraph: EntryInactive, ProfileSecurityProbe: EntryInactive,
				ProfileFrontend: EntryInactive, ProfileBackend: EntryInactive, ProfileTestAuthor: EntryInactive,
				ProfileStyleConformance: EntryInactive, ProfileBugHunter: EntryInactive, ProfileDriftAuditor: EntryInactive,
			},
		},
		{
			name: "explicit analyzer gap needs the knowledge graph model",
			spec: ChangeFeaturesSpec{Files: goChangeWithTest(3).Files, SemanticGapPaths: []string{"lib/core.go"}},
			want: map[ProfileID]EntryStatus{ProfileKnowledgeGraph: EntryPlanned},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			plan := mustPlan(t, catalog, assignments, mustFeatures(t, test.spec))
			if len(plan.Entries()) != len(knownProfileIDs) {
				t.Fatalf("entries = %d", len(plan.Entries()))
			}
			for id, want := range test.want {
				entry := mustEntry(t, plan, id)
				if entry.Status() != want {
					t.Fatalf("%s status = %s, want %s (reasons %v)", id, entry.Status(), want, entry.ActivationReasons())
				}
				if len(entry.ActivationReasons()) == 0 {
					t.Fatalf("%s has no recorded activation reason", id)
				}
			}
		})
	}
}

func TestProfileKnowledgeGraphRecordsGaps(t *testing.T) {
	catalog := mustCatalog(t)
	plan := mustPlan(t, catalog, fullAssignments(t, catalog), mustFeatures(t, ChangeFeaturesSpec{Files: []ChangedFileSpec{
		{Path: "tools/build.py", AddedLines: 4}, {Path: "lib/core.go", AddedLines: 4},
	}}))
	entry := mustEntry(t, plan, ProfileKnowledgeGraph)
	if entry.Status() != EntryPlanned || strings.Join(entry.modelGaps, ",") != "unsupported_language:python" {
		t.Fatalf("knowledge graph = %s gaps %v", entry.Status(), entry.modelGaps)
	}
}

func TestProfileTierThresholdBoundaries(t *testing.T) {
	catalog := mustCatalog(t)
	assignments := fullAssignments(t, catalog)
	bugHunter, _ := catalog.Profile(ProfileBugHunter)
	if bugHunter.Thresholds() != (TierThresholds{Standard: 12, Deep: 40}) {
		t.Fatalf("fixture assumes bug_hunter thresholds 12/40, got %+v", bugHunter.Thresholds())
	}
	for _, test := range []struct {
		name      string
		lines     uint32
		publicAPI uint32
		fanOut    uint32
		score     uint64
		tier      Tier
	}{
		{"zero", 0, 0, 0, 0, TierLight},
		{"just below standard", 299, 0, 0, 11, TierLight},
		{"at standard", 300, 0, 0, 12, TierStandard},
		{"just below deep", 500, 3, 16, 39, TierStandard},
		{"at deep", 500, 3, 20, 40, TierDeep},
		{"capped lines", 100000, 0, 0, 20, TierStandard},
	} {
		t.Run(test.name, func(t *testing.T) {
			spec := goChangeWithTest(test.lines)
			spec.PublicAPIChanges, spec.ReferenceFanOut = test.publicAPI, test.fanOut
			entry := mustEntry(t, mustPlan(t, catalog, assignments, mustFeatures(t, spec)), ProfileBugHunter)
			difficulty, scored := entry.Difficulty()
			if !scored || difficulty.Score != test.score || entry.ScoredTier() != test.tier || entry.RouteTier() != test.tier {
				t.Fatalf("score = %d tier = %s route tier = %s, want %d %s", difficulty.Score, entry.ScoredTier(), entry.RouteTier(), test.score, test.tier)
			}
			var sum uint64
			for _, row := range difficulty.Contributions {
				if row.Points > row.Cap {
					t.Fatalf("row %s exceeds cap", row.Signal)
				}
				sum += row.Points
			}
			if sum != difficulty.Score || len(difficulty.Contributions) != len(difficultyWeights) {
				t.Fatalf("breakdown does not explain score: %d rows sum %d", len(difficulty.Contributions), sum)
			}
			tierSpec, _ := bugHunter.TierSpec(test.tier)
			if entry.TokenBudget() != tierSpec || entry.Requirements().MinContextTokens() != tierSpec.MinContextTokens || entry.Requirements().MinOutputTokens() != tierSpec.MinOutputTokens {
				t.Fatalf("requirements/budget do not follow tier %s", test.tier)
			}
		})
	}
}

func TestProfileScoringSignals(t *testing.T) {
	features := mustFeatures(t, ChangeFeaturesSpec{
		Files: []ChangedFileSpec{
			{Path: "internal/auth/token.go", AddedLines: 10, Signals: []Signal{SignalConcurrency}},
			{Path: "webhook/sql/query.py", AddedLines: 15},
		},
	})
	difficulty := scoreDifficulty(eligibleFiles(features), features)
	got := map[DifficultySignal]DifficultyContribution{}
	for _, row := range difficulty.Contributions {
		got[row.Signal] = row
	}
	// auth, secrets, webhook, sql -> 4 kinds -> min(18, 24) = 18.
	if got[DifficultySecurityPaths].Observed != 4 || got[DifficultySecurityPaths].Points != 18 {
		t.Fatalf("security row = %+v", got[DifficultySecurityPaths])
	}
	if got[DifficultyConcurrency].Points != 4 || got[DifficultyLanguages].Points != 4 || got[DifficultyChangedFiles].Points != 2 || got[DifficultyChangedLines].Points != 1 {
		t.Fatalf("rows = %+v", got)
	}
	if got[DifficultyTestAbsence].Points != 6 {
		t.Fatalf("test absence row = %+v", got[DifficultyTestAbsence])
	}
	if got[DifficultyCoverageGap].Points != 0 || !strings.Contains(got[DifficultyCoverageGap].Note, "unknown") {
		t.Fatalf("unknown coverage must contribute 0 and say so: %+v", got[DifficultyCoverageGap])
	}
	measured := mustFeatures(t, ChangeFeaturesSpec{Files: goChangeWithTest(1).Files, Coverage: &CoverageSpec{UncoveredChangedLines: 1000}})
	for _, row := range scoreDifficulty(eligibleFiles(measured), measured).Contributions {
		if row.Signal == DifficultyCoverageGap && (row.Points != 10 || row.Observed != 1000) {
			t.Fatalf("coverage row = %+v", row)
		}
	}
}

func TestProfileEscalationIsExplicitAndRecorded(t *testing.T) {
	catalog := mustCatalog(t)
	standard, deep := mustRoute(t, "ollama", "qwen3:32b"), mustRoute(t, "ollama", "qwen3:235b")
	spec := AssignmentsSpec{
		Independence: gateway.RouteIndependenceDistinctRoute,
		Tiers:        map[Tier]provider.RouteReference{TierStandard: standard, TierDeep: deep},
	}
	features := mustFeatures(t, goChangeWithTest(10))
	noEscalation := mustPlan(t, catalog, mustAssignments(t, catalog, spec), features)
	entry := mustEntry(t, noEscalation, ProfileBugHunter)
	reason, detail := entry.Omission()
	if entry.Status() != EntryOmitted || reason != OmissionTierUnassigned || !strings.Contains(detail, "light") {
		t.Fatalf("unassigned tier: status %s reason %s detail %q", entry.Status(), reason, detail)
	}
	if _, ok := entry.GeneratorRoute(); ok {
		t.Fatal("omitted entry carries a route")
	}
	if !containsOmission(noEscalation.Omissions(), ProfileBugHunter, OmissionTierUnassigned) {
		t.Fatalf("omission not listed: %+v", noEscalation.Omissions())
	}

	spec.EscalationOrder = []Tier{TierLight, TierStandard, TierDeep}
	escalated := mustPlan(t, catalog, mustAssignments(t, catalog, spec), features)
	entry = mustEntry(t, escalated, ProfileBugHunter)
	route, ok := entry.GeneratorRoute()
	if entry.Status() != EntryPlanned || !ok || route != standard || entry.RouteTier() != TierStandard || entry.ScoredTier() != TierLight || entry.generator.escalatedFrom != TierLight {
		t.Fatalf("escalation: status %s route tier %s scored %s", entry.Status(), entry.RouteTier(), entry.ScoredTier())
	}
	bugHunter, _ := catalog.Profile(ProfileBugHunter)
	lightSpec, _ := bugHunter.TierSpec(TierLight)
	if entry.TokenBudget() != lightSpec {
		t.Fatal("escalation must not change the scored tier's requirements or budget")
	}
	encoded, _ := json.Marshal(escalated)
	if !bytes.Contains(encoded, []byte(`"escalated_from":"light"`)) || !bytes.Contains(encoded, []byte(`"escalation_order":["light","standard","deep"]`)) {
		t.Fatalf("escalation not recorded in JSON: %s", encoded)
	}
	if escalated.Identity() == noEscalation.Identity() {
		t.Fatal("escalation did not change plan identity")
	}
}

func TestProfileOverrideWinsOverGlobal(t *testing.T) {
	catalog := mustCatalog(t)
	global, override := mustRoute(t, "ollama", "qwen3:8b"), mustRoute(t, "vllm", "qwen3-coder")
	assignments := mustAssignments(t, catalog, AssignmentsSpec{
		Independence: gateway.RouteIndependenceDistinctRoute,
		Tiers:        map[Tier]provider.RouteReference{TierLight: global},
		Profiles:     map[ProfileID]ProfileAssignmentSpec{ProfileBackend: {Tiers: map[Tier]provider.RouteReference{TierLight: override}}},
	})
	plan := mustPlan(t, catalog, assignments, mustFeatures(t, goChangeWithTest(1)))
	backend, bug := mustEntry(t, plan, ProfileBackend), mustEntry(t, plan, ProfileBugHunter)
	if route, _ := backend.GeneratorRoute(); route != override || backend.generator.source != routeSourceProfileOverride {
		t.Fatal("profile override not applied")
	}
	if route, _ := bug.GeneratorRoute(); route != global || bug.generator.source != routeSourceGlobal {
		t.Fatal("global assignment not applied")
	}
	ranking, ok := backend.RankingPolicy()
	pinned, hasPin := ranking.PinnedRoute()
	if !ok || !hasPin || pinned != override || len(ranking.PreferredRoutes()) != 0 || ranking.Validate() != nil {
		t.Fatal("ranking policy is not pinned to the selected route")
	}
}

func TestProfileVerifierIndependence(t *testing.T) {
	catalog := mustCatalog(t)
	generator := mustRoute(t, "ollama", "qwen3:8b")
	sameModelOtherConnection, err := provider.NewRouteReference(provider.ProviderZoneLocal, "ollama", "chat-completions", "local/second", "qwen3:8b", "")
	if err != nil {
		t.Fatal(err)
	}
	otherProvider := mustRoute(t, "llamacpp", "qwen3:8b")
	for _, test := range []struct {
		name     string
		level    gateway.RouteIndependenceLevel
		verifier *provider.RouteReference
		want     Verification
	}{
		{"no verifier", gateway.RouteIndependenceDistinctProvider, nil, VerificationUnverifiable},
		{"identical route", gateway.RouteIndependenceDistinctRoute, &generator, VerificationUnverifiable},
		{"distinct route suffices", gateway.RouteIndependenceDistinctRoute, &sameModelOtherConnection, VerificationIndependent},
		{"same model fails distinct_model", gateway.RouteIndependenceDistinctModel, &sameModelOtherConnection, VerificationUnverifiable},
		{"same model id on other provider passes distinct_model", gateway.RouteIndependenceDistinctModel, &otherProvider, VerificationIndependent},
		{"other provider passes distinct_provider", gateway.RouteIndependenceDistinctProvider, &otherProvider, VerificationIndependent},
	} {
		t.Run(test.name, func(t *testing.T) {
			spec := AssignmentsSpec{Independence: test.level, Tiers: map[Tier]provider.RouteReference{TierLight: generator}}
			if test.verifier != nil {
				spec.VerifierTiers = map[Tier]provider.RouteReference{TierLight: *test.verifier}
			}
			entry := mustEntry(t, mustPlan(t, catalog, mustAssignments(t, catalog, spec), mustFeatures(t, goChangeWithTest(1))), ProfileBugHunter)
			verification, detail := entry.Verification()
			if entry.Status() != EntryPlanned || verification != test.want || detail == "" {
				t.Fatalf("verification = %s (%q), want %s", verification, detail, test.want)
			}
			route, hasVerifier := entry.VerifierRoute()
			budget := uint64(entry.TokenBudget().InputTokenBudget) + uint64(entry.TokenBudget().OutputTokenBudget)
			if test.want == VerificationIndependent {
				if !hasVerifier || route != *test.verifier || entry.PlannedTokens() != 2*budget {
					t.Fatal("independent verifier not bound or not budgeted")
				}
				ranking, _ := entry.VerifierRankingPolicy()
				if pinned, ok := ranking.PinnedRoute(); !ok || pinned != *test.verifier {
					t.Fatal("verifier ranking not pinned")
				}
			} else if hasVerifier || entry.PlannedTokens() != budget {
				t.Fatal("unverifiable entry must carry no verifier and budget only generation")
			}
		})
	}
}

// TestProfileIndependenceMirrorsGateway cross-checks the plan-time rule against
// gateway.VerifyIndependentRouteRecords on equivalent registry records.
func TestProfileIndependenceMirrorsGateway(t *testing.T) {
	routes := []provider.RouteReference{
		mustRoute(t, "ollama", "qwen3:8b"),
		mustRoute(t, "ollama", "qwen3:32b"),
		mustRoute(t, "llamacpp", "qwen3:8b"),
	}
	otherConnection, err := provider.NewRouteReference(provider.ProviderZoneLocal, "ollama", "chat-completions", "local/second", "qwen3:8b", "")
	if err != nil {
		t.Fatal(err)
	}
	routes = append(routes, otherConnection)
	for _, level := range []gateway.RouteIndependenceLevel{gateway.RouteIndependenceDistinctRoute, gateway.RouteIndependenceDistinctModel, gateway.RouteIndependenceDistinctProvider} {
		policy, err := gateway.NewRouteIndependencePolicy(level)
		if err != nil {
			t.Fatal(err)
		}
		for _, first := range routes {
			for _, second := range routes {
				if first == second {
					if routesIndependent(level, first, second) {
						t.Fatalf("%s: identical routes judged independent", level)
					}
					continue
				}
				gatewayResult := gateway.VerifyIndependentRouteRecords(policy, mustRecord(t, first), mustRecord(t, second)) == nil
				if got := routesIndependent(level, first, second); got != gatewayResult {
					t.Fatalf("%s: plan rule = %t, gateway = %t for %s/%s vs %s/%s", level, got, gatewayResult,
						first.ProviderID(), first.ModelID(), second.ProviderID(), second.ModelID())
				}
			}
		}
	}
}

func mustRecord(t *testing.T, route provider.RouteReference) provider.RouteRegistryRecord {
	t.Helper()
	capabilities, err := provider.NewModelCapabilities(200000, 32000, []provider.ModelFeature{provider.ModelFeatureStructuredOutput})
	if err != nil {
		t.Fatal(err)
	}
	capability, err := provider.NewRouteCapabilityDeclaration(route, capabilities)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := provider.NewRouteCandidateDeclaration(capability, provider.ContentLoggingDisabled, provider.NewUnknownRoutePricing(), provider.RouteQualityTier2)
	if err != nil {
		t.Fatal(err)
	}
	record, err := provider.NewRouteRegistryRecord(1, candidate, provider.RouteRegistryPending, strings.Repeat("d", 64))
	if err != nil {
		t.Fatal(err)
	}
	return record
}

// broadChange activates every model-calling profile.
func broadChange(t *testing.T) ChangeFeatures {
	t.Helper()
	return mustFeatures(t, ChangeFeaturesSpec{
		Files: []ChangedFileSpec{
			{Path: "internal/auth/session.go", AddedLines: 120},
			{Path: "web/src/Login.tsx", AddedLines: 80},
			{Path: "docs/auth.md", AddedLines: 10},
		},
		Intent:      IntentSpec{DescriptionPresent: true},
		ConfigFiles: []ConfigFile{{Path: "go.mod"}},
	})
}

func TestProfileBudgetCapDropsLowestPriorityFirst(t *testing.T) {
	catalog := mustCatalog(t)
	features := broadChange(t)
	uncapped := mustPlan(t, catalog, fullAssignments(t, catalog), features)
	planned := 0
	for _, entry := range uncapped.Entries() {
		if entry.Status() == EntryPlanned {
			planned++
		}
	}
	if planned != 8 || len(uncapped.Omissions()) != 0 {
		t.Fatalf("fixture must plan all eight model profiles, planned %d omissions %+v", planned, uncapped.Omissions())
	}
	wantOrder := []ProfileID{ProfileStyleConformance, ProfileDriftAuditor, ProfileTestAuthor, ProfileKnowledgeGraph, ProfileFrontend, ProfileBackend, ProfileBugHunter, ProfileSecurityProbe}
	for _, test := range []struct {
		name  string
		cap   uint64
		drops int
	}{
		{"cap equals total", uncapped.PlannedTokens(), 0},
		{"one token short", uncapped.PlannedTokens() - 1, 1},
		{"minimal cap drops everything", 1, 8},
	} {
		t.Run(test.name, func(t *testing.T) {
			assignments := fullAssignments(t, catalog)
			spec := AssignmentsSpec{Independence: assignments.independence.Level(), Tiers: assignments.tiers, VerifierTiers: assignments.verifierTiers, TotalTokenBudget: test.cap}
			plan := mustPlan(t, catalog, mustAssignments(t, catalog, spec), features)
			omissions := plan.Omissions()
			if len(omissions) != test.drops {
				t.Fatalf("drops = %d, want %d: %+v", len(omissions), test.drops, omissions)
			}
			for index, omission := range omissions {
				if omission.ProfileID != wantOrder[index] || omission.Reason != OmissionBudgetCap || omission.Detail == "" {
					t.Fatalf("drop %d = %+v, want %s", index, omission, wantOrder[index])
				}
				entry := mustEntry(t, plan, omission.ProfileID)
				if _, ok := entry.GeneratorRoute(); ok || entry.Status() != EntryOmitted || entry.PlannedTokens() != 0 {
					t.Fatalf("dropped %s still carries a route or tokens", omission.ProfileID)
				}
			}
			if plan.PlannedTokens() > test.cap {
				t.Fatalf("planned tokens %d exceed cap %d", plan.PlannedTokens(), test.cap)
			}
		})
	}
}

func TestProfilePlanIsDeterministicAndGolden(t *testing.T) {
	catalog := mustCatalog(t)
	first := mustPlan(t, catalog, fullAssignments(t, catalog), broadChange(t))
	second := mustPlan(t, mustCatalog(t), fullAssignments(t, catalog), broadChange(t))
	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, _ := json.Marshal(second)
	if first.Identity() != second.Identity() || !bytes.Equal(firstJSON, secondJSON) {
		t.Fatal("plan is not deterministic")
	}
	if first.Identity() != goldenPlanIdentity {
		t.Fatalf("plan identity = %s, want golden %s", first.Identity(), goldenPlanIdentity)
	}
	if first.CatalogIdentity() != catalog.Identity() || first.FeaturesIdentity() != broadChange(t).Identity() || !validDigest(first.AssignmentsIdentity()) {
		t.Fatal("plan does not bind its input identities")
	}
	var decoded struct {
		Identity           string `json:"identity"`
		GatewayEligibility string `json:"gateway_eligibility"`
		Entries            []struct {
			ProfileID string        `json:"profile_id"`
			Authority authorityWire `json:"authority"`
		} `json:"entries"`
		Omissions []json.RawMessage `json:"omissions"`
	}
	if err := json.Unmarshal(firstJSON, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Identity != first.Identity() || !strings.Contains(decoded.GatewayEligibility, "not bypassed") || len(decoded.Entries) != 9 || decoded.Omissions == nil {
		t.Fatalf("plan JSON = %s", firstJSON)
	}
	for index, entry := range decoded.Entries {
		if entry.ProfileID != string(knownProfileIDs[index]) || entry.Authority.ToolExecution || !entry.Authority.CandidatesOnly {
			t.Fatalf("entry %d = %+v", index, entry)
		}
	}
}

func TestProfilePlanRejectsTamperedInputsAndDetectsTampering(t *testing.T) {
	catalog := mustCatalog(t)
	assignments := fullAssignments(t, catalog)
	features := broadChange(t)
	if _, err := Plan(Catalog{}, assignments, features); !errors.Is(err, ErrInvalidCatalogIdentity) {
		t.Fatalf("zero catalog accepted: %v", err)
	}
	if _, err := Plan(catalog, Assignments{}, features); err == nil {
		t.Fatal("zero assignments accepted")
	}
	if _, err := Plan(catalog, assignments, ChangeFeatures{}); !errors.Is(err, ErrInvalidChangeFeatures) {
		t.Fatalf("zero features accepted: %v", err)
	}
	plan := mustPlan(t, catalog, assignments, features)
	plan.entries = plan.Entries()
	plan.entries[1].status = EntryInactive
	if err := plan.Validate(); !errors.Is(err, ErrInvalidRoutingPlan) {
		t.Fatalf("tampered plan validated: %v", err)
	}
	if _, err := json.Marshal(plan); err == nil {
		t.Fatal("tampered plan marshaled")
	}
}

func TestProfilePlanEntryCostBudget(t *testing.T) {
	catalog := mustCatalog(t)
	plan := mustPlan(t, catalog, fullAssignments(t, catalog), mustFeatures(t, goChangeWithTest(1)))
	entry := mustEntry(t, plan, ProfileBugHunter)
	budget, err := entry.CostBudget(5000)
	if err != nil || budget.EstimatedInputTokens() != entry.TokenBudget().InputTokenBudget || budget.MaxOutputTokens() != entry.TokenBudget().OutputTokenBudget || budget.MaxCostMicroUSD() != 5000 {
		t.Fatalf("CostBudget() = %v, %v", budget, err)
	}
	if _, err := mustEntry(t, plan, ProfileFrontend).CostBudget(5000); !errors.Is(err, ErrInvalidRoutingPlan) {
		t.Fatalf("inactive entry produced a cost budget: %v", err)
	}
}

func containsOmission(omissions []Omission, id ProfileID, reason OmissionReason) bool {
	for _, omission := range omissions {
		if omission.ProfileID == id && omission.Reason == reason {
			return true
		}
	}
	return false
}
