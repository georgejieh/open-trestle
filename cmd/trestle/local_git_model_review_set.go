package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/georgejieh/open-trestle/agentprofile"
	"github.com/georgejieh/open-trestle/diagnostics"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/localreview"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

// Multi-specialist review set contract and cost bounds.
const (
	modelReviewSetContract = "open-trestle/local-git-model-review-set"
	modelReviewSetVersion  = 1

	defaultMaxSpecialists = 3
	maxMaxSpecialists     = 6

	maxModelReviewSetJSONBytes = 1 << 20
	maxModelReviewSetTextBytes = 256 << 10

	specialistModeNone     = "none"
	specialistModeAuto     = "auto"
	specialistModeExplicit = "explicit"

	generalMemberLabel = "general"

	// Every member uses the runtime policy's generation/verification routes.
	routeAssignmentNotApplied = "not_applied: every member uses the runtime policy's single generation and verification route pair; the routing plan's tier and route choice is informational only"
)

// specialistRequest is the parsed --specialists/--max-specialists intent. The
// zero value is mode none.
type specialistRequest struct {
	mode     string
	explicit []review.ContextSpecialist
	max      int
}

func (r specialistRequest) active() bool {
	return r.mode == specialistModeAuto || r.mode == specialistModeExplicit
}

// parseSpecialistRequest accepts "none", "auto" or a comma-separated list of
// unique packaged direct-review profile IDs, and an optional --max-specialists
// in 1..6 (default 3). --max-specialists without an active selection, or an
// explicit list longer than the limit, is a usage error: an explicit list is
// never silently cut.
func parseSpecialistRequest(value, maxValue string) (specialistRequest, error) {
	invalid := errors.New("invalid --specialists intent")
	request := specialistRequest{max: defaultMaxSpecialists}
	if maxValue != "" {
		limit, err := strconv.Atoi(maxValue)
		if err != nil || strconv.Itoa(limit) != maxValue || limit < 1 || limit > maxMaxSpecialists {
			return specialistRequest{}, invalid
		}
		request.max = limit
	}
	switch value {
	case "":
		return specialistRequest{}, invalid
	case specialistModeNone:
		if maxValue != "" {
			return specialistRequest{}, invalid
		}
		return specialistRequest{mode: specialistModeNone}, nil
	case specialistModeAuto:
		request.mode = specialistModeAuto
		return request, nil
	}
	seen := map[string]bool{}
	for _, id := range strings.Split(value, ",") {
		if id == "" || seen[id] {
			return specialistRequest{}, invalid
		}
		seen[id] = true
		specialist, err := review.NewContextSpecialist(id)
		if err != nil {
			return specialistRequest{}, errUnknownModelReviewProfile{value: id, flag: "--specialists"}
		}
		request.explicit = append(request.explicit, specialist)
	}
	if len(request.explicit) > request.max {
		return specialistRequest{}, invalid
	}
	request.mode = specialistModeExplicit
	return request, nil
}

// Selection trace wire types.

type specialistFeaturesWire struct {
	Identity         string   `json:"identity"`
	ChangedFiles     int      `json:"changed_files"`
	Languages        []string `json:"languages"`
	FileClasses      []string `json:"file_classes"`
	SecuritySignals  []string `json:"security_signals"`
	SemanticGaps     int      `json:"semantic_gaps"`
	PublicAPIChanges uint32   `json:"public_api_changes"`
	ReferenceFanOut  uint32   `json:"reference_fan_out"`
	Source           string   `json:"source"`
	// StyleConfigurationUnread counts recognized base style configuration
	// files the features could not carry (over a file bound, not valid UTF-8,
	// or beyond the 1 MiB document bound); omitted when zero.
	StyleConfigurationUnread int `json:"style_configuration_unread,omitempty"`
}

type specialistPlanWire struct {
	Identity               string `json:"identity"`
	CatalogIdentity        string `json:"catalog_identity"`
	AssignmentsIdentity    string `json:"assignments_identity"`
	FeaturesIdentity       string `json:"features_identity"`
	AssignmentsBasis       string `json:"assignments_basis"`
	GenerationRouteBasis   string `json:"generation_route_basis"`
	VerificationRouteBasis string `json:"verification_route_basis"`
}

type selectedSpecialistWire struct {
	ProfileID         string   `json:"profile_id"`
	ProfileIdentity   string   `json:"profile_identity"`
	Priority          uint8    `json:"priority,omitempty"`
	ScoredTier        string   `json:"scored_tier,omitempty"`
	ActivationReasons []string `json:"activation_reasons"`
}

type droppedSpecialistWire struct {
	ProfileID string `json:"profile_id"`
	Reason    string `json:"reason"`
	Detail    string `json:"detail"`
}

type specialistSelectionWire struct {
	Mode            string                   `json:"mode"`
	MaxSpecialists  int                      `json:"max_specialists"`
	Status          string                   `json:"status"`
	Reason          string                   `json:"reason,omitempty"`
	Features        *specialistFeaturesWire  `json:"features"`
	Plan            *specialistPlanWire      `json:"plan"`
	Selected        []selectedSpecialistWire `json:"selected"`
	Dropped         []droppedSpecialistWire  `json:"dropped"`
	Inactive        []string                 `json:"inactive"`
	RouteAssignment string                   `json:"route_assignment"`
}

// Drop reasons recorded in the selection trace.
const (
	dropReasonLimit         = "max_specialists"
	dropReasonNotApplicable = "not_applicable"
)

// generalRoutePair resolves the route references the general review actually
// dispatched to, from its recorded generation and verification route record
// identities. The plan needs route references to build assignments; it never
// re-derives route selection.
func generalRoutePair(general localreview.Report, inventory runtimeconfig.RouteInventory) (generation, verification provider.RouteReference, err error) {
	var foundGeneration, foundVerification bool
	for _, observed := range inventory.Candidates() {
		record := observed.ResolvedRecord().RouteRegistryRecord()
		reference := record.RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference()
		switch record.Identity() {
		case general.GenerationRoute:
			generation, foundGeneration = reference, true
		case general.VerificationRoute:
			verification, foundVerification = reference, true
		}
	}
	if general.GenerationRoute == "" || general.VerificationRoute == "" || !foundGeneration || !foundVerification {
		return generation, verification, errors.New("general review routes unavailable")
	}
	return generation, verification, nil
}

// summarizeSpecialistFeatures projects the recorded change features. The
// languages, file classes and security signals come from the features
// themselves, the same derivation a routing plan records, so they stay
// accurate when no plan could be built (for example after the general review's
// verification failed but its change and analysis were recorded).
func summarizeSpecialistFeatures(features agentprofile.ChangeFeatures) *specialistFeaturesWire {
	summary := &specialistFeaturesWire{Identity: features.Identity(), Languages: []string{}, FileClasses: []string{}, SecuritySignals: []string{}, Source: "recorded_change_and_semantic_impact_artifacts_of_the_general_review"}
	var featureWire struct {
		Files            []json.RawMessage `json:"files"`
		PublicAPIChanges uint32            `json:"public_api_changes"`
		ReferenceFanOut  uint32            `json:"reference_fan_out"`
	}
	if encoded, err := features.MarshalJSON(); err == nil && json.Unmarshal(encoded, &featureWire) == nil {
		summary.ChangedFiles, summary.PublicAPIChanges, summary.ReferenceFanOut = len(featureWire.Files), featureWire.PublicAPIChanges, featureWire.ReferenceFanOut
	}
	if features.Validate() == nil {
		derived := features.Summary()
		summary.Languages = append(summary.Languages, derived.Languages...)
		summary.FileClasses = append(summary.FileClasses, derived.FileClasses...)
		summary.SecuritySignals = append(summary.SecuritySignals, derived.SecuritySignals...)
		summary.SemanticGaps = derived.SemanticGaps
	}
	return summary
}

// planAutoSpecialists routes the change across the packaged catalog and keeps
// activated, planned direct-review specialists in priority order (ties by
// profile ID), cut to limit. No model is called. The assignments document is
// synthesized: every tier maps to the general review's recorded generation
// route and every verifier tier to its recorded verification route, so the plan never omits a
// profile for an unassigned tier and the plan's route choice is informational.
func planAutoSpecialists(features agentprofile.ChangeFeatures, policy runtimeconfig.RuntimePolicy, inventory runtimeconfig.RouteInventory, general localreview.Report, limit int) (specialistSelectionWire, []review.ContextSpecialist) {
	selection := specialistSelectionWire{Mode: specialistModeAuto, MaxSpecialists: limit, Selected: []selectedSpecialistWire{}, Dropped: []droppedSpecialistWire{}, Inactive: []string{}, RouteAssignment: routeAssignmentNotApplied}
	planUnavailable := func() (specialistSelectionWire, []review.ContextSpecialist) {
		selection.Status = "plan_unavailable"
		selection.Features = summarizeSpecialistFeatures(features)
		return selection, nil
	}
	catalog, err := agentprofile.DefaultCatalog()
	if err != nil {
		return planUnavailable()
	}
	generation, verification, err := generalRoutePair(general, inventory)
	if err != nil {
		return planUnavailable()
	}
	tiers, verifierTiers := map[agentprofile.Tier]provider.RouteReference{}, map[agentprofile.Tier]provider.RouteReference{}
	for _, tier := range agentprofile.Tiers() {
		tiers[tier], verifierTiers[tier] = generation, verification
	}
	assignments, err := agentprofile.NewAssignments(catalog, agentprofile.AssignmentsSpec{Independence: policy.Independence().Level(), Tiers: tiers, VerifierTiers: verifierTiers})
	if err != nil {
		return planUnavailable()
	}
	plan, err := agentprofile.Plan(catalog, assignments, features)
	if err != nil {
		return planUnavailable()
	}
	selection.Status = "planned"
	selection.Features = summarizeSpecialistFeatures(features)
	selection.Plan = &specialistPlanWire{
		Identity: plan.Identity(), CatalogIdentity: plan.CatalogIdentity(), AssignmentsIdentity: plan.AssignmentsIdentity(), FeaturesIdentity: plan.FeaturesIdentity(),
		AssignmentsBasis: "synthesized_single_route_pair_from_general_review", GenerationRouteBasis: "general_review_generation_route_record", VerificationRouteBasis: "general_review_verification_route_record",
	}
	type candidate struct {
		entry      agentprofile.PlanEntry
		priority   uint8
		specialist review.ContextSpecialist
	}
	var candidates []candidate
	for _, entry := range plan.Entries() {
		id := string(entry.ProfileID())
		if !entry.Activated() {
			selection.Inactive = append(selection.Inactive, id)
			continue
		}
		specialist, specialistErr := review.NewContextSpecialist(id)
		switch {
		case entry.Status() == agentprofile.EntryOmitted:
			reason, detail := entry.Omission()
			selection.Dropped = append(selection.Dropped, droppedSpecialistWire{ProfileID: id, Reason: string(reason), Detail: detail})
		case entry.Status() == agentprofile.EntryDeterministicOnly:
			selection.Dropped = append(selection.Dropped, droppedSpecialistWire{ProfileID: id, Reason: dropReasonNotApplicable, Detail: "deterministic_only: the profile makes no model call for this change"})
		case specialistErr != nil:
			selection.Dropped = append(selection.Dropped, droppedSpecialistWire{ProfileID: id, Reason: dropReasonNotApplicable, Detail: "not a direct defect-review specialist; planning-only in the direct path"})
		case entry.Status() == agentprofile.EntryPlanned:
			profile, _ := catalog.Profile(entry.ProfileID())
			candidates = append(candidates, candidate{entry: entry, priority: profile.Priority(), specialist: specialist})
		default:
			selection.Dropped = append(selection.Dropped, droppedSpecialistWire{ProfileID: id, Reason: dropReasonNotApplicable, Detail: "plan status " + string(entry.Status())})
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].priority != candidates[j].priority {
			return candidates[i].priority > candidates[j].priority
		}
		return candidates[i].entry.ProfileID() < candidates[j].entry.ProfileID()
	})
	var selected []review.ContextSpecialist
	for index, value := range candidates {
		id := string(value.entry.ProfileID())
		if index >= limit {
			selection.Dropped = append(selection.Dropped, droppedSpecialistWire{ProfileID: id, Reason: dropReasonLimit, Detail: fmt.Sprintf("priority %d ranked %d of %d activated specialists; --max-specialists is %d", value.priority, index+1, len(candidates), limit)})
			continue
		}
		selection.Selected = append(selection.Selected, selectedSpecialistWire{ProfileID: id, ProfileIdentity: value.specialist.ProfileIdentity(), Priority: value.priority, ScoredTier: string(value.entry.ScoredTier()), ActivationReasons: value.entry.ActivationReasons()})
		selected = append(selected, value.specialist)
	}
	return selection, selected
}

// Set output wire types.

// setContextShortfallWire carries the counts of a member refused because its
// reservation exceeds the route's declared context.
type setContextShortfallWire struct {
	RequiredTokens        uint64 `json:"required_tokens"`
	EstimatedInputTokens  uint32 `json:"estimated_input_tokens"`
	MaxOutputTokens       uint32 `json:"max_output_tokens"`
	DeclaredContextTokens uint32 `json:"declared_context_tokens"`
}

type setMemberWire struct {
	Member             string `json:"member"`
	ProfileIdentity    string `json:"profile_identity,omitempty"`
	Launched           bool   `json:"launched"`
	NotLaunchedReason  string `json:"not_launched_reason,omitempty"`
	Status             string `json:"status"`
	CI                 string `json:"ci_disposition"`
	RunStatus          string `json:"run_status"`
	Failure            string `json:"failure"`
	FailureTask        string `json:"failure_task,omitempty"`
	FailureDetail      string `json:"failure_detail,omitempty"`
	ReviewRunID        string `json:"review_run_id"`
	ScopeIdentity      string `json:"scope_identity"`
	PlanIdentity       string `json:"plan_identity"`
	ContextIdentity    string `json:"context_identity"`
	GenerationRoute    string `json:"generation_route_record_identity"`
	VerificationRoute  string `json:"verification_route_record_identity"`
	Independence       string `json:"independence"`
	DiagnosticSet      string `json:"diagnostic_set_identity"`
	UsageKnown         bool   `json:"usage_known"`
	ActualCostMicroUSD uint64 `json:"actual_cost_micro_usd"`
	// TokenUsage is the member result's token_usage. It is absent when the
	// member result reports none, as for a member that never ran.
	TokenUsage          *localreview.TokenUsage `json:"token_usage,omitempty"`
	Candidates          *uint16                 `json:"candidate_count,omitempty"`
	Verified            *uint16                 `json:"verified_count,omitempty"`
	Rejected            *uint16                 `json:"rejected_count,omitempty"`
	Inconclusive        *uint16                 `json:"inconclusive_count,omitempty"`
	VerifiedFindings    int                     `json:"verified_findings"`
	Limitations         []string                `json:"limitations"`
	reportAvailable     bool
	statusFindingsEmpty bool
	failureHint         string

	// ContextShortfall is present only with failure_detail
	// route_context_insufficient.
	ContextShortfall *setContextShortfallWire `json:"context_shortfall,omitempty"`
}

type setContributorWire struct {
	Member          string `json:"member"`
	FindingIdentity string `json:"finding_identity"`
	Severity        string `json:"severity"`
	StartLine       uint32 `json:"start_line"`
	EndLine         uint32 `json:"end_line"`
	// Side is "base" when the lines are removed lines of the base revision.
	Side string `json:"side,omitempty"`
}

type setFindingWire struct {
	FindingIdentity string `json:"finding_identity"`
	Title           string `json:"title"`
	Claim           string `json:"claim"`
	Severity        string `json:"severity"`
	Path            string `json:"path"`
	StartLine       uint32 `json:"start_line"`
	EndLine         uint32 `json:"end_line"`
	// Side is "base" when the lines are removed lines of the base revision,
	// and HeadLine is then the head line beside them, if one remains.
	Side         string               `json:"side,omitempty"`
	HeadLine     uint32               `json:"head_line,omitempty"`
	Category     string               `json:"category,omitempty"`
	Fix          string               `json:"fix,omitempty"`
	FixAuthority string               `json:"fix_authority,omitempty"`
	EvidenceIDs  []string             `json:"evidence_ids"`
	Contributors []setContributorWire `json:"contributors"`
	// Rank is the finding's 1-based position (localreview.RankFindings);
	// findings are listed in rank order.
	Rank int `json:"rank"`
	// PreExisting is set when every contributor is pre-existing: on unchanged
	// lines the change provably cannot reach. Such a finding never blocks CI.
	// UnprovenOrigin is set when every contributor is on unchanged lines but
	// the change may have caused at least one of them; such a finding blocks
	// like an introduced one.
	PreExisting    bool `json:"pre_existing,omitempty"`
	UnprovenOrigin bool `json:"unproven_origin,omitempty"`
	// Merged lists every contributor other than the representative with its
	// own verified statement and the rule that merged it (near_identical,
	// same_declaration or same_lines), in contributor order; omitted when
	// nothing was merged.
	Merged []setMergedWire `json:"merged,omitempty"`
	report localreview.ReportFinding
	merged localreview.MergedFinding
}

// setMergedWire is one wording merged into a set finding.
type setMergedWire struct {
	Member          string `json:"member"`
	FindingIdentity string `json:"finding_identity"`
	Title           string `json:"title"`
	Claim           string `json:"claim"`
	Rule            string `json:"rule"`
}

type setSummaryWire struct {
	MembersRun       int            `json:"members_run"`
	MembersSelected  int            `json:"members_selected"`
	Findings         int            `json:"findings"`
	BySeverity       map[string]int `json:"by_severity"`
	ByCategory       map[string]int `json:"by_category"`
	DuplicatesMerged int            `json:"duplicates_merged"`
	SourceCoverage   *struct {
		Analyzed uint32 `json:"analyzed"`
		Selected uint32 `json:"selected"`
		Omitted  uint32 `json:"omitted"`
	} `json:"source_coverage"`
}

type setBoundsWire struct {
	MaxSpecialists           int    `json:"max_specialists"`
	MemberTimeoutMillis      int64  `json:"member_timeout_milliseconds"`
	MaxModelWallTimeMillis   int64  `json:"max_model_wall_time_milliseconds"`
	MemberCleanupBoundMillis int64  `json:"member_cleanup_bound_milliseconds"`
	Execution                string `json:"execution"`
	// Concurrency is how many specialist members could run at once (1 when
	// they ran one by one); SequentialReason names why they ran one by one.
	Concurrency      int    `json:"specialist_concurrency"`
	SequentialReason string `json:"sequential_reason,omitempty"`
}

type modelReviewSetWire struct {
	Contract  string                  `json:"contract"`
	Version   int                     `json:"schema_version"`
	Status    string                  `json:"status"`
	CI        string                  `json:"ci_disposition"`
	Complete  bool                    `json:"complete"`
	Selection specialistSelectionWire `json:"selection"`
	Members   []setMemberWire         `json:"members"`
	Summary   setSummaryWire          `json:"summary"`
	// Walkthrough describes the whole set (localreview.AggregateWalkthroughs):
	// the secret scan and verifier totals over the completed members, with
	// each one's own account in verified_by_member, and the shared per-file
	// summary and deduplicated missing-verification notes.
	Walkthrough            *localreview.SetWalkthrough `json:"walkthrough,omitempty"`
	Findings               []setFindingWire            `json:"findings"`
	Bounds                 setBoundsWire               `json:"bounds"`
	Limitations            []string                    `json:"limitations"`
	ComprehensiveClearance bool                        `json:"comprehensive_clearance"`
	// StyleAdvice repeats the general member's style advice once for the set,
	// inline. Its fields are omitted when it has none, so a set without advice
	// keeps its version 1 bytes.
	localreview.StyleAdvice
	headRevision string
	independence string
	failure      string
	runStatus    string
	report       *localreview.Report
}

// runLocalModelReviewSet runs the general review, then each selected
// specialist as its own session and run, sequentially. It stops launching
// members once the invocation context is done or a launched member's run did
// not succeed (refused, failed, canceled, or source unreadable); it never
// retries. preparedStatus is a non-empty unstarted status when configuration
// or source preparation already failed, in which case no session starts.
func runLocalModelReviewSet(ctx, execution context.Context, options localModelReviewOptions, inputs localModelReviewInputs, preparedStatus string, stdout, stderr io.Writer, observe func(modelReviewOutcome)) int {
	request := options.specialists
	selection := specialistSelectionWire{Mode: request.mode, MaxSpecialists: request.max, Selected: []selectedSpecialistWire{}, Dropped: []droppedSpecialistWire{}, Inactive: []string{}, RouteAssignment: routeAssignmentNotApplied}
	var general localModelReviewMember
	if preparedStatus != "" {
		result, err := localreview.NewUnstartedSpecialistResult(preparedStatus, options.objectStoreProfile, review.ContextSpecialist{})
		if err != nil {
			return 1
		}
		general.result = result
	} else {
		var ok bool
		general, ok = runLocalModelReviewMember(ctx, execution, options, inputs, review.ContextSpecialist{}, true)
		if !ok {
			return 1
		}
		if general.partialCheckout {
			fmt.Fprintln(stderr, partialCheckoutHint)
		}
	}
	var selected []review.ContextSpecialist
	switch {
	case request.mode == specialistModeExplicit:
		selection.Status = "explicit"
		if general.hasFeatures {
			selection.Features = summarizeSpecialistFeatures(general.features)
		}
		for _, specialist := range request.explicit {
			selection.Selected = append(selection.Selected, selectedSpecialistWire{ProfileID: specialist.ProfileID(), ProfileIdentity: specialist.ProfileIdentity(), ActivationReasons: []string{"explicit_operator_selection"}})
		}
		selected = request.explicit
	case general.hasFeatures:
		generalReport, _ := general.result.Report()
		selection, selected = planAutoSpecialists(general.features, inputs.policy, inputs.inventory, generalReport, request.max)
	default:
		selection.Status = "features_unavailable"
		selection.Reason = featuresUnavailableReason(general.result)
	}
	if selection.Features != nil {
		selection.Features.StyleConfigurationUnread = general.styleConfigUnread
	}
	members := []localModelReviewMember{general}
	notLaunched := map[int]string{}
	stopReason := ""
	if report, err := general.result.Report(); err != nil || report.RunStatus != "succeeded" {
		stopReason = "general_review_did_not_complete"
	}
	// Specialists run in waves of up to concurrency members at once (one
	// member per wave when they must run one by one). A wave starts only when
	// the invocation is not canceled and every launched member succeeded.
	concurrency, sequentialReason := 1, ""
	if stopReason == "" {
		concurrency, sequentialReason = specialistConcurrency(inputs, len(selected))
	}
	for start := 0; start < len(selected); start += concurrency {
		end := min(start+concurrency, len(selected))
		if stopReason == "" && ctx != nil && ctx.Err() != nil {
			stopReason = "canceled"
		}
		if stopReason != "" {
			for index := start; index < end; index++ {
				result, err := localreview.NewUnstartedSpecialistResult(unlaunchedStatus(stopReason), options.objectStoreProfile, selected[index])
				if err != nil {
					return 1
				}
				notLaunched[index+1] = stopReason
				members = append(members, localModelReviewMember{specialist: selected[index], result: result})
			}
			continue
		}
		wave := make([]localModelReviewMember, end-start)
		launched := make([]bool, end-start)
		var group sync.WaitGroup
		for index := start; index < end; index++ {
			group.Add(1)
			go func(slot int, specialist review.ContextSpecialist) {
				defer group.Done()
				memberExecution, cancel := context.WithTimeout(ctx, options.timeout)
				defer cancel()
				wave[slot], launched[slot] = runLocalModelReviewMember(ctx, memberExecution, options, inputs, specialist, false)
			}(index-start, selected[index])
		}
		group.Wait()
		// Members are recorded in selection order, whichever finished first.
		for slot, member := range wave {
			if !launched[slot] {
				return 1
			}
			if member.partialCheckout {
				fmt.Fprintln(stderr, partialCheckoutHint)
			}
			members = append(members, member)
			if stopReason != "" {
				continue
			}
			if report, err := member.result.Report(); err != nil {
				stopReason = "stopped_after_" + member.specialist.ProfileID() + "_unreadable"
			} else if report.RunStatus != "succeeded" {
				stopReason = "stopped_after_" + member.specialist.ProfileID() + "_" + report.Status
			}
		}
	}
	set := buildModelReviewSet(selection, members, notLaunched, options, concurrency, sequentialReason)
	inputs.spending.finish()
	if observe != nil {
		observe(modelReviewOutcome{status: set.Status, findings: len(set.Findings), advisory: set.Status == "findings" && set.CI == "inconclusive"})
	}
	return writeModelReviewSet(options.format, options.exitPolicy, options.renderOptions(), set, stdout, stderr)
}

// featuresUnavailableReason explains why no change features were read from the
// general review: the task it failed at when one is recorded.
func featuresUnavailableReason(result localreview.Result) string {
	report, err := result.Report()
	switch {
	case err != nil:
		return "general review result unreadable"
	case report.FailureTask != "":
		return "general review failed at " + report.FailureTask
	case report.RunStatus != "succeeded":
		return "general review did not complete (" + report.Status + ")"
	}
	return "change features could not be read from the general review"
}

func unlaunchedStatus(reason string) string {
	if reason == "canceled" {
		return "canceled"
	}
	return "incomplete"
}

func memberLabel(specialist review.ContextSpecialist) string {
	if specialist.IsZero() {
		return generalMemberLabel
	}
	return specialist.ProfileID()
}

// buildModelReviewSet summarizes members and merges their verified findings.
// maxConcurrentSpecialists bounds the specialist members that run at once.
const maxConcurrentSpecialists = 3

// Reasons specialist members run one by one.
const (
	sequentialOneSpecialist   = "at_most_one_specialist"
	sequentialLocalRoute      = "local_model_route"
	sequentialLoopbackService = "loopback_model_service"
	sequentialSpendingLimit   = "spending_limit_could_be_passed"
)

// specialistConcurrency decides how many of count specialist members may run
// at once, and otherwise why they run one by one. Members are independent
// sessions with their own run, objects root, gateway and route state, and the
// spending record is serialized, so the code allows concurrency. It is used
// only where the routes allow it: never for a model on this machine or a
// loopback service (such as a local Ollama, which serializes requests, so
// concurrent members would only share one member's timeout), and never when a
// limited key's recorded spend plus the wave's worst case could reach its
// limit, so the one-by-one limit check is never defeated.
func specialistConcurrency(inputs localModelReviewInputs, count int) (int, string) {
	if count <= 1 {
		return 1, sequentialOneSpecialist
	}
	for _, candidate := range inputs.inventory.Candidates() {
		if candidate.ResolvedRecord().RouteRegistryRecord().RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference().Zone() == provider.ProviderZoneLocal {
			return 1, sequentialLocalRoute
		}
	}
	for _, connection := range inputs.policy.Connections() {
		if locality, err := provider.ClassifyServiceEndpoint(connection.Endpoint()); err != nil || locality == provider.ServiceEndpointLoopback {
			return 1, sequentialLoopbackService
		}
	}
	concurrency := min(count, maxConcurrentSpecialists)
	if !inputs.spending.batchWithinLimits(concurrency) {
		return 1, sequentialSpendingLimit
	}
	return concurrency, ""
}

func buildModelReviewSet(selection specialistSelectionWire, members []localModelReviewMember, notLaunched map[int]string, options localModelReviewOptions, concurrency int, sequentialReason string) modelReviewSetWire {
	if concurrency < 1 {
		concurrency = 1
	}
	execution := "sequential: general review first, then selected specialists in priority order; each member has its own timeout and independent verification"
	parallelism := "sequential_members_no_parallelism"
	if concurrency > 1 {
		execution = fmt.Sprintf("concurrent: general review first, then selected specialists up to %d at a time, in priority order; each member has its own timeout and independent verification", concurrency)
		parallelism = "specialists_concurrent_bounded"
	}
	specialists := max(len(members)-1, 0)
	waves := (specialists + concurrency - 1) / concurrency
	set := modelReviewSetWire{
		Contract: modelReviewSetContract, Version: modelReviewSetVersion, Selection: selection, Members: []setMemberWire{}, Findings: []setFindingWire{},
		Summary: setSummaryWire{BySeverity: map[string]int{}, ByCategory: map[string]int{}, MembersSelected: len(members)},
		Limitations: []string{
			"per_profile_route_assignment_not_applied", parallelism, "deduplication_is_heuristic",
			"merged_findings_only_from_completed_members", "no_publication",
		},
	}
	cleanup := localModelCleanupTimeout(options.timeout)
	set.Bounds = setBoundsWire{
		MaxSpecialists: selection.MaxSpecialists, MemberTimeoutMillis: options.timeout.Milliseconds(),
		MaxModelWallTimeMillis:   int64(1+waves) * options.timeout.Milliseconds(),
		MemberCleanupBoundMillis: cleanup.Milliseconds(),
		Execution:                execution,
		Concurrency:              concurrency,
		SequentialReason:         map[bool]string{true: "", false: sequentialReason}[concurrency > 1],
	}
	// Style advice derives from the change and base tree that every member
	// shares, so the set reports the general member's once, never per member.
	if len(members) > 0 && members[0].specialist.IsZero() {
		set.StyleAdvice = members[0].result.StyleAdvice()
	}
	// The walkthrough totals every completed member, in member order. When no
	// member completed, the first member with a walkthrough (a general review
	// that failed after recording the change) describes the set alone, so its
	// per-file summary is kept.
	var walks []localreview.MemberWalkthrough
	var firstWalk *localreview.MemberWalkthrough
	var memberFindings [][]localreview.ReportFinding
	labels := make([]string, len(members))
	complete := true
	worst := ""
	for index, member := range members {
		labels[index] = memberLabel(member.specialist)
		wire := setMemberWire{Member: labels[index], ProfileIdentity: member.specialist.ProfileIdentity(), Launched: true, Limitations: []string{}}
		if reason, ok := notLaunched[index]; ok {
			wire.Launched, wire.NotLaunchedReason = false, reason
		}
		report, err := member.result.Report()
		if err != nil {
			wire.Status, wire.CI, wire.RunStatus = "failed", "error", "unknown"
			wire.Limitations = append(wire.Limitations, "member_result_unreadable")
			memberFindings = append(memberFindings, nil)
			if index == 0 {
				// The general member's report carries the set's source
				// coverage. Without it the set cannot state how much source
				// was analyzed, so the loss is recorded at the set level where
				// a CI consumer reads it, not only on the member wire.
				set.Limitations = append(set.Limitations, "general_member_report_unreadable_source_coverage_unknown")
			}
		} else {
			wire.reportAvailable = true
			wire.Status, wire.CI, wire.RunStatus, wire.Failure = report.Status, report.CIDisposition, report.RunStatus, report.Failure
			wire.FailureTask, wire.FailureDetail, wire.failureHint = report.FailureTask, report.FailureDetail, report.FailureHint
			if s := report.ContextShortfall; s != nil {
				wire.ContextShortfall = &setContextShortfallWire{RequiredTokens: s.RequiredTokens, EstimatedInputTokens: s.EstimatedInputTokens, MaxOutputTokens: s.MaxOutputTokens, DeclaredContextTokens: s.DeclaredContextTokens}
			}
			wire.ReviewRunID, wire.ScopeIdentity, wire.PlanIdentity, wire.ContextIdentity = report.ReviewRunID, report.ScopeIdentity, report.PlanIdentity, report.ContextIdentity
			wire.GenerationRoute, wire.VerificationRoute, wire.Independence, wire.DiagnosticSet = report.GenerationRoute, report.VerificationRoute, report.Independence, report.DiagnosticSet
			wire.UsageKnown, wire.ActualCostMicroUSD, wire.TokenUsage = report.UsageKnown, report.ActualCostMicroUSD, report.TokenUsage
			wire.Limitations = append(wire.Limitations, report.Limitations...)
			wire.VerifiedFindings = len(report.Findings)
			wire.statusFindingsEmpty = report.Status == "findings" && len(report.Findings) == 0
			if report.HasVerifiedSet {
				wire.Candidates, wire.Verified, wire.Rejected, wire.Inconclusive = sarifPointer(report.Candidates), sarifPointer(report.Verified), sarifPointer(report.Rejected), sarifPointer(report.Inconclusive)
			}
			if report.RunStatus == "succeeded" {
				memberFindings = append(memberFindings, report.Findings)
				walks = append(walks, localreview.MemberWalkthrough{Member: labels[index], Walkthrough: report.Walkthrough})
			} else {
				memberFindings = append(memberFindings, nil)
				if firstWalk == nil && report.Walkthrough != nil {
					firstWalk = &localreview.MemberWalkthrough{Member: labels[index], Walkthrough: report.Walkthrough}
				}
			}
			if index == 0 {
				set.headRevision, set.independence = report.HeadRevision, report.Independence
				if report.HasSourceCoverage {
					set.Summary.SourceCoverage = &struct {
						Analyzed uint32 `json:"analyzed"`
						Selected uint32 `json:"selected"`
						Omitted  uint32 `json:"omitted"`
					}{report.SourceAnalyzed, report.SourceSelected, report.SourceOmitted}
				}
				generalReport := report
				set.report = &generalReport
			}
		}
		if wire.Launched {
			set.Summary.MembersRun++
		}
		if wire.RunStatus != "succeeded" {
			complete = false
			if setStatusRank(wire.Status) > setStatusRank(worst) {
				worst = wire.Status
				set.failure, set.runStatus = wire.Failure, wire.RunStatus
			}
		}
		set.Members = append(set.Members, wire)
	}
	if len(walks) == 0 && firstWalk != nil {
		walks = append(walks, *firstWalk)
	}
	set.Walkthrough = localreview.AggregateWalkthroughs(walks)
	independence := make([]string, len(set.Members))
	for index, member := range set.Members {
		independence[index] = member.Independence
	}
	merged, duplicates := mergeVerifiedFindingsWithIndependence(labels, independence, memberFindings)
	set.Findings = merged
	set.Summary.Findings, set.Summary.DuplicatesMerged = len(merged), duplicates
	for _, finding := range merged {
		set.Summary.BySeverity[finding.Severity]++
		category := finding.Category
		if category == "" {
			category = "uncategorized"
		}
		set.Summary.ByCategory[category]++
	}
	set.Complete = complete
	switch {
	case !complete:
		set.Status = worst
		set.CI = map[string]string{"failed": "error", "refused": "blocked"}[worst]
		if set.CI == "" {
			set.CI = "inconclusive"
		}
		// An incomplete set never demotes a verified high or critical finding
		// that the change introduced from a completed member: it still blocks.
		if hasErrorSeverityFinding(merged) {
			set.CI = "blocked"
		}
	case len(merged) > 0:
		// Low-severity and pre-existing findings never block CI: a set whose
		// merged findings are all advisory keeps status findings and is
		// inconclusive. A medium, high or critical finding the change
		// introduced blocks (localreview.BlocksCI).
		set.Status, set.CI = "findings", "inconclusive"
		for _, finding := range merged {
			if finding.merged.Blocking() {
				set.CI = "blocked"
			}
		}
	default:
		allClean := true
		for _, member := range set.Members {
			allClean = allClean && member.Status == "no_candidates"
		}
		set.Status, set.CI = "incomplete", "inconclusive"
		if allClean {
			set.Status = "no_candidates"
		}
	}
	if complete {
		set.runStatus = "succeeded"
	}
	return set
}

// hasErrorSeverityFinding reports whether a merged finding is a verified high or
// critical (error-severity) finding that is not pre-existing.
func hasErrorSeverityFinding(findings []setFindingWire) bool {
	for _, finding := range findings {
		if finding.report.Severity == diagnostics.SeverityError && !finding.PreExisting {
			return true
		}
	}
	return false
}

// setStatusRank orders non-completed member statuses by severity.
func setStatusRank(status string) int {
	switch status {
	case "failed":
		return 4
	case "refused":
		return 3
	case "canceled":
		return 2
	case "":
		return 0
	}
	return 1
}

// mergeVerifiedFindings de-duplicates the members' verified findings with the
// shared rule (localreview.DeduplicateFindings) and orders them by rank
// (localreview.RankFindings). Each group reports its representative, the
// strongest verified finding, at its own location, and lists every
// contributor with its own finding identity, severity and range. Members are
// origins in run order. independence holds each member's recorded
// verification independence, aligned with labels; it may be nil.
func mergeVerifiedFindings(labels []string, findings [][]localreview.ReportFinding) ([]setFindingWire, int) {
	return mergeVerifiedFindingsWithIndependence(labels, nil, findings)
}

func mergeVerifiedFindingsWithIndependence(labels, independence []string, findings [][]localreview.ReportFinding) ([]setFindingWire, int) {
	origins := make([]localreview.FindingOrigin, 0, len(findings))
	for index, memberFindings := range findings {
		origin := localreview.FindingOrigin{Label: labels[index], Findings: memberFindings}
		if index < len(independence) {
			origin.Independence = independence[index]
		}
		origins = append(origins, origin)
	}
	ranked := localreview.RankFindings(localreview.DeduplicateFindings(origins))
	out := make([]setFindingWire, 0, len(ranked))
	for _, group := range ranked {
		value := setFindingFromReport(group.Finding)
		value.Rank, value.PreExisting, value.UnprovenOrigin, value.merged = group.Rank, group.PreExisting(), group.UnprovenOrigin(), group
		value.Contributors = make([]setContributorWire, 0, len(group.Contributors))
		for _, contributor := range group.Contributors {
			value.Contributors = append(value.Contributors, setContributorWire{Member: contributor.Origin, FindingIdentity: contributor.Identity, Severity: contributor.Severity.String(), StartLine: contributor.StartLine, EndLine: contributor.EndLine, Side: recordedSetSide(contributor.Side)})
			if contributor.Identity != group.Finding.Identity {
				value.Merged = append(value.Merged, setMergedWire{Member: contributor.Origin, FindingIdentity: contributor.Identity, Title: contributor.Title, Claim: contributor.Claim, Rule: contributor.MergedBy})
			}
		}
		out = append(out, value)
	}
	return out, localreview.MergedDuplicates(ranked)
}

// recordedSetSide is the omitempty set token of a side: head is absent.
func recordedSetSide(side diagnostics.LineSide) string {
	if side == diagnostics.LineSideBase {
		return "base"
	}
	return ""
}

func setFindingFromReport(finding localreview.ReportFinding) setFindingWire {
	value := setFindingWire{
		FindingIdentity: finding.Identity, Title: finding.Title, Claim: finding.Claim, Severity: finding.Severity.String(), Path: finding.Path,
		StartLine: finding.StartLine, EndLine: finding.EndLine, Side: recordedSetSide(finding.Side), HeadLine: finding.HeadLine,
		Category: finding.Category, Fix: finding.Fix,
		EvidenceIDs: append([]string{}, finding.EvidenceIDs...), report: finding,
	}
	if value.Fix != "" {
		value.FixAuthority = localreview.FixAuthority
	}
	return value
}

func (f setFindingWire) contributorLabels() []string {
	labels := []string{}
	seen := map[string]bool{}
	for _, contributor := range f.Contributors {
		if !seen[contributor.Member] {
			seen[contributor.Member] = true
			labels = append(labels, contributor.Member)
		}
	}
	return labels
}

// exitCode applies the exit policy to the merged set:
//   - default: 4 blocked (a blocking finding or a refused member), 3
//     inconclusive (including an advisory set whose findings are all low
//     severity or pre-existing), 1 error.
//   - findings: 0 when every member completed and no merged finding is error
//     severity (verified high/critical); otherwise the default code.
//   - strict: 0 only when every member completed with no candidates.
//   - always-zero: 0 when the general review completed, even if a specialist
//     member was refused or failed; when the general review did not complete,
//     the default code (so a refused general review exits 4).
func (s modelReviewSetWire) exitCode(policy localreview.ExitPolicy) int {
	code := 1
	switch s.CI {
	case "blocked":
		code = 4
	case "inconclusive":
		code = 3
	}
	switch policy {
	case localreview.ExitPolicyAlwaysZero:
		if len(s.Members) > 0 && s.Members[0].RunStatus == "succeeded" {
			return 0
		}
	case localreview.ExitPolicyFindings:
		if s.Complete && !s.hasBlockingFinding() {
			return 0
		}
	case localreview.ExitPolicyStrict:
		if s.Complete && s.Status == "no_candidates" {
			return 0
		}
	}
	return code
}

func (s modelReviewSetWire) hasBlockingFinding() bool {
	for _, member := range s.Members {
		if member.statusFindingsEmpty || !member.reportAvailable {
			return true
		}
	}
	return hasErrorSeverityFinding(s.Findings)
}

func writeModelReviewSet(format string, policy localreview.ExitPolicy, options localreview.RenderOptions, set modelReviewSetWire, stdout, stderr io.Writer) int {
	var encoded []byte
	var err error
	switch format {
	case "text":
		encoded, err = renderModelReviewSetText(set, options)
	case "markdown":
		encoded, err = renderModelReviewSetMarkdown(set, options)
	case "sarif":
		encoded, err = encodeModelReviewSetSARIF(set)
	default:
		encoded, err = json.Marshal(set)
		if err == nil {
			encoded = append(encoded, '\n')
			if len(encoded) > maxModelReviewSetJSONBytes {
				err = errors.New("model review set exceeds output bound")
			}
		}
	}
	if err == nil {
		var n int
		n, err = stdout.Write(encoded)
		if err == nil && n != len(encoded) {
			err = io.ErrShortWrite
		}
	}
	if err != nil {
		fmt.Fprintln(stderr, "write result: failed")
		return 1
	}
	return set.exitCode(policy)
}

// rankedGroups returns the set's merged findings as ranked groups, in rank
// order.
func (s modelReviewSetWire) rankedGroups() []localreview.MergedFinding {
	groups := make([]localreview.MergedFinding, 0, len(s.Findings))
	for _, finding := range s.Findings {
		groups = append(groups, finding.merged)
	}
	return groups
}

func setContributors(group localreview.MergedFinding) []string { return group.OriginLabels() }

// renderModelReviewSetText writes the set for people: the status, the
// reviewers that ran and any that did not finish (with the failure and hint),
// the walkthrough of the whole set, the merged findings in rank order with the
// members that confirmed each and their other wordings, the pre-existing
// findings, the hidden count, style advice, the total tokens and the
// clearance line. options.Verbose adds the internals: the selection trace,
// change features, dropped profiles, the route assignment note, per-member
// key-value lines, the finding summary and the limitations.
func renderModelReviewSetText(set modelReviewSetWire, options localreview.RenderOptions) ([]byte, error) {
	var buffer bytes.Buffer
	fmt.Fprintf(&buffer, "status: %s\nci: %s\n", set.Status, set.CI)
	reviewers := []string{}
	for _, member := range set.Members {
		if member.Launched {
			reviewers = append(reviewers, member.Member)
		}
	}
	fmt.Fprintf(&buffer, "reviewers: %s (%d of %d ran)\n", joinOrNone(reviewers), set.Summary.MembersRun, set.Summary.MembersSelected)
	for _, member := range set.Members {
		switch {
		case !member.Launched:
			fmt.Fprintf(&buffer, "not run: %s (%s)\n", member.Member, notLaunchedText(member.NotLaunchedReason))
		case member.RunStatus != "succeeded":
			text := member.Status
			if member.Failure != "" {
				text += ": " + localreview.FailureLine(member.Failure, member.FailureTask, member.FailureDetail)
			}
			fmt.Fprintf(&buffer, "not finished: %s (%s)\n", member.Member, text)
			if member.failureHint != "" {
				fmt.Fprintf(&buffer, "hint: %s: %s\n", member.Member, member.failureHint)
			}
		}
	}
	if options.Verbose {
		writeModelReviewSetDetails(&buffer, set)
	}
	for _, line := range localreview.SetWalkthroughText(set.Walkthrough) {
		buffer.WriteString(line)
	}
	buffer.WriteString(localreview.FindingsText(set.rankedGroups(), options, setContributors))
	if !set.Complete {
		buffer.WriteString("incomplete: one or more reviewers did not finish; the findings come only from those that did, so this is not a clean result\n")
	}
	// A coverage gap is a fact a person needs; full coverage is only detail.
	if coverage := set.Summary.SourceCoverage; coverage != nil && coverage.Omitted > 0 && !options.Verbose {
		fmt.Fprintf(&buffer, "source coverage: analyzed=%d selected=%d omitted=%d\n", coverage.Analyzed, coverage.Selected, coverage.Omitted)
	}
	usages := make([]*localreview.TokenUsage, 0, len(set.Members))
	zeroDataRetentionNotRequired := false
	for _, member := range set.Members {
		usages = append(usages, member.TokenUsage)
		zeroDataRetentionNotRequired = zeroDataRetentionNotRequired || slices.Contains(member.Limitations, localreview.LimitationOpenRouterZDRNotRequired)
	}
	if zeroDataRetentionNotRequired {
		buffer.WriteString(localreview.ZeroDataRetentionNotRequiredText)
	}
	if line := localreview.TotalTokensLine(usages); line != "" {
		buffer.WriteString(strings.Replace(line, "\n", fmt.Sprintf(" (%d reviewer%s)\n", len(reviewers), map[bool]string{true: "", false: "s"}[len(reviewers) == 1]), 1))
	}
	for _, line := range set.StyleAdvice.Lines() {
		buffer.WriteString(line)
	}
	if options.Verbose {
		fmt.Fprintf(&buffer, "limitations: %s\n", strings.Join(set.Limitations, ", "))
	}
	buffer.WriteString("comprehensive clearance: false\n")
	if buffer.Len() > maxModelReviewSetTextBytes {
		return nil, errors.New("model review set text exceeds output bound")
	}
	return buffer.Bytes(), nil
}

// notLaunchedText words why a selected member was not run.
func notLaunchedText(reason string) string {
	switch {
	case reason == "general_review_did_not_complete":
		return "the general review did not finish"
	case reason == "canceled":
		return "the review was canceled"
	case strings.HasPrefix(reason, "stopped_after_"):
		rest := strings.TrimPrefix(reason, "stopped_after_")
		if member, ok := strings.CutSuffix(rest, "_unreadable"); ok && member != "" {
			return "stopped after the result of " + member + " could not be read"
		}
		if index := strings.LastIndex(rest, "_"); index > 0 {
			return "stopped after " + rest[:index] + " did not finish (" + rest[index+1:] + ")"
		}
	}
	return reason
}

// writeModelReviewSetDetails writes the --verbose internals of a set: the
// selection trace, the per-member key-value lines and the finding summary.
func writeModelReviewSetDetails(buffer *bytes.Buffer, set modelReviewSetWire) {
	fmt.Fprintf(buffer, "complete: %t\n", set.Complete)
	selectionStatus := set.Selection.Status
	if set.Selection.Reason != "" {
		selectionStatus += " (" + set.Selection.Reason + ")"
	}
	fmt.Fprintf(buffer, "selection: mode=%s status=%s max=%d\n", set.Selection.Mode, selectionStatus, set.Selection.MaxSpecialists)
	if features := set.Selection.Features; features != nil {
		fmt.Fprintf(buffer, "change features: files=%d languages=%s classes=%s security=%s\n", features.ChangedFiles, joinOrNone(features.Languages), joinOrNone(features.FileClasses), joinOrNone(features.SecuritySignals))
	}
	selected := []string{}
	for _, value := range set.Selection.Selected {
		selected = append(selected, value.ProfileID)
	}
	fmt.Fprintf(buffer, "selected: %s\n", joinOrNone(selected))
	for _, value := range set.Selection.Dropped {
		fmt.Fprintf(buffer, "dropped: %s (%s)\n", value.ProfileID, value.Reason)
	}
	fmt.Fprintf(buffer, "route assignment: %s\n", set.Selection.RouteAssignment)
	fmt.Fprintf(buffer, "members run: %d of %d\n", set.Summary.MembersRun, set.Summary.MembersSelected)
	for _, member := range set.Members {
		if !member.Launched {
			fmt.Fprintf(buffer, "member: %s not run (%s)\n", member.Member, member.NotLaunchedReason)
			continue
		}
		if member.RunStatus != "succeeded" && member.Failure != "" {
			fmt.Fprintf(buffer, "member: %s status=%s run=%s verified_findings=%d failure=%s\n", member.Member, member.Status, member.RunStatus, member.VerifiedFindings, localreview.FailureLine(member.Failure, member.FailureTask, member.FailureDetail))
			if member.failureHint != "" {
				fmt.Fprintf(buffer, "member hint: %s: %s\n", member.Member, member.failureHint)
			}
			continue
		}
		fmt.Fprintf(buffer, "member: %s status=%s run=%s verified_findings=%d\n", member.Member, member.Status, member.RunStatus, member.VerifiedFindings)
	}
	severities := sortedCounts(set.Summary.BySeverity)
	categories := sortedCounts(set.Summary.ByCategory)
	fmt.Fprintf(buffer, "findings: %d (merged duplicates: %d) severity: %s category: %s\n", set.Summary.Findings, set.Summary.DuplicatesMerged, joinOrNone(severities), joinOrNone(categories))
	if coverage := set.Summary.SourceCoverage; coverage != nil {
		fmt.Fprintf(buffer, "files covered: analyzed=%d selected=%d omitted=%d\n", coverage.Analyzed, coverage.Selected, coverage.Omitted)
	}
}

// renderModelReviewSetMarkdown renders the set as a pull request summary
// comment: status, the reviewers that ran, the general review's walkthrough,
// then the merged findings in rank order with the members that confirmed them.
func renderModelReviewSetMarkdown(set modelReviewSetWire, options localreview.RenderOptions) ([]byte, error) {
	var buffer bytes.Buffer
	buffer.WriteString("## Open Trestle review\n\n")
	fmt.Fprintf(&buffer, "**Status:** %s · **CI:** %s · **Complete:** %t\n", localreview.MarkdownText(set.Status), localreview.MarkdownText(set.CI), set.Complete)
	reviewers := []string{}
	for _, member := range set.Members {
		if member.Launched {
			reviewers = append(reviewers, localreview.MarkdownCode(member.Member))
		}
	}
	fmt.Fprintf(&buffer, "\nReviewers: %s (%d of %d ran; specialists %s).\n", strings.Join(reviewers, ", "), set.Summary.MembersRun, set.Summary.MembersSelected, localreview.MarkdownText(set.Selection.Mode))
	for _, member := range set.Members {
		switch {
		case !member.Launched:
			fmt.Fprintf(&buffer, "\n- %s did not run (%s).\n", localreview.MarkdownCode(member.Member), localreview.MarkdownText(member.NotLaunchedReason))
		case member.RunStatus != "succeeded":
			fmt.Fprintf(&buffer, "\n- %s did not finish: %s.\n", localreview.MarkdownCode(member.Member), localreview.MarkdownText(localreview.FailureLine(member.Failure, member.FailureTask, member.FailureDetail)))
		}
	}
	if set.Walkthrough != nil {
		buffer.WriteString("\n" + localreview.SetWalkthroughMarkdown(set.Walkthrough))
	}
	buffer.WriteString(localreview.FindingsMarkdown(set.rankedGroups(), options, setContributors))
	if !set.Complete {
		buffer.WriteString("\nOne or more reviewers did not finish; the findings come only from those that did. This is not a clean result.\n")
	}
	buffer.WriteString(localreview.MarkdownFooter)
	if buffer.Len() > maxModelReviewSetTextBytes {
		return nil, errors.New("model review set Markdown exceeds output bound")
	}
	return buffer.Bytes(), nil
}

func joinOrNone(values []string) string {
	if len(values) == 0 {
		return "none"
	}
	return strings.Join(values, ", ")
}

func sortedCounts(counts map[string]int) []string {
	out := make([]string, 0, len(counts))
	for key, count := range counts {
		out = append(out, fmt.Sprintf("%s=%d", key, count))
	}
	sort.Strings(out)
	return out
}

// encodeModelReviewSetSARIF emits one SARIF run whose results are the merged
// verified findings, each carrying trestleContributors.
func encodeModelReviewSetSARIF(set modelReviewSetWire) ([]byte, error) {
	report := localreview.Report{
		Status: set.Status, CIDisposition: set.CI, RunStatus: set.runStatus, Failure: set.failure, Independence: set.independence,
		Limitations: append([]string{}, set.Limitations...), HeadRevision: set.headRevision, Findings: []localreview.ReportFinding{}, Omissions: []localreview.ReportOmission{},
		StyleAdvice: set.StyleAdvice,
	}
	if set.report != nil && set.report.HasSourceCoverage {
		report.HasSourceCoverage = true
		report.SourceAnalyzed, report.SourceSelected, report.SourceOmitted = set.report.SourceAnalyzed, set.report.SourceSelected, set.report.SourceOmitted
		report.Omissions = append(report.Omissions, set.report.Omissions...)
	}
	contributors := map[string][]string{}
	for _, finding := range set.Findings {
		// The set's merge decides rank, representative and origin class.
		value := finding.report
		value.Rank, value.DuplicateOf, value.PreExisting, value.UnprovenOrigin = finding.Rank, "", finding.PreExisting, finding.UnprovenOrigin
		report.Findings = append(report.Findings, value)
		contributors[finding.FindingIdentity] = finding.contributorLabels()
	}
	if set.Complete {
		report.HasVerifiedSet = true
		for _, member := range set.Members {
			if member.Candidates != nil {
				report.Candidates = saturatingAdd16(report.Candidates, *member.Candidates)
				report.Verified = saturatingAdd16(report.Verified, *member.Verified)
				report.Rejected = saturatingAdd16(report.Rejected, *member.Rejected)
				report.Inconclusive = saturatingAdd16(report.Inconclusive, *member.Inconclusive)
			}
		}
	}
	log, err := buildModelReviewSARIFWithContributors(report, contributors)
	if err != nil {
		return nil, err
	}
	if !set.Complete {
		// Some members completed and their verified findings are listed; the
		// single-run "no findings were evaluated" wording would be false here.
		// The notification also names a lost source-coverage account, which a
		// consumer needs even when no finding was produced.
		coverage := ""
		if set.report == nil || !set.report.HasSourceCoverage {
			coverage = " Source coverage counts are unavailable for this run."
		}
		log.Runs[0].Invocations[0].ToolExecutionNotifications = []sarifNotification{{Level: "error", Message: sarifMessage{Text: "One or more review set members did not complete (status=" + set.Status + "); the results list only verified findings from members that completed. This is not a clean result." + coverage + " Limitations: " + strings.Join(set.Limitations, ", ") + "."}}}
	}
	encoded, err := json.Marshal(log)
	if err != nil {
		return nil, fmt.Errorf("encode model review set SARIF: %w", err)
	}
	if len(encoded)+1 > maxDiagnosticSARIFBytes {
		return nil, fmt.Errorf("model review set SARIF exceeds %d-byte limit", maxDiagnosticSARIFBytes)
	}
	return append(encoded, '\n'), nil
}

func saturatingAdd16(a, b uint16) uint16 {
	if a > ^uint16(0)-b {
		return ^uint16(0)
	}
	return a + b
}
