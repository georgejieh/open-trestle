package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode"

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

type setMemberWire struct {
	Member              string   `json:"member"`
	ProfileIdentity     string   `json:"profile_identity,omitempty"`
	Launched            bool     `json:"launched"`
	NotLaunchedReason   string   `json:"not_launched_reason,omitempty"`
	Status              string   `json:"status"`
	CI                  string   `json:"ci_disposition"`
	RunStatus           string   `json:"run_status"`
	Failure             string   `json:"failure"`
	FailureTask         string   `json:"failure_task,omitempty"`
	FailureDetail       string   `json:"failure_detail,omitempty"`
	ReviewRunID         string   `json:"review_run_id"`
	ScopeIdentity       string   `json:"scope_identity"`
	PlanIdentity        string   `json:"plan_identity"`
	ContextIdentity     string   `json:"context_identity"`
	GenerationRoute     string   `json:"generation_route_record_identity"`
	VerificationRoute   string   `json:"verification_route_record_identity"`
	Independence        string   `json:"independence"`
	DiagnosticSet       string   `json:"diagnostic_set_identity"`
	UsageKnown          bool     `json:"usage_known"`
	ActualCostMicroUSD  uint64   `json:"actual_cost_micro_usd"`
	Candidates          *uint16  `json:"candidate_count,omitempty"`
	Verified            *uint16  `json:"verified_count,omitempty"`
	Rejected            *uint16  `json:"rejected_count,omitempty"`
	Inconclusive        *uint16  `json:"inconclusive_count,omitempty"`
	VerifiedFindings    int      `json:"verified_findings"`
	Limitations         []string `json:"limitations"`
	reportAvailable     bool
	statusFindingsEmpty bool
	failureHint         string
}

type setContributorWire struct {
	Member          string `json:"member"`
	FindingIdentity string `json:"finding_identity"`
	Severity        string `json:"severity"`
	StartLine       uint32 `json:"start_line"`
	EndLine         uint32 `json:"end_line"`
}

type setFindingWire struct {
	FindingIdentity string               `json:"finding_identity"`
	Title           string               `json:"title"`
	Claim           string               `json:"claim"`
	Severity        string               `json:"severity"`
	Path            string               `json:"path"`
	StartLine       uint32               `json:"start_line"`
	EndLine         uint32               `json:"end_line"`
	Category        string               `json:"category,omitempty"`
	Fix             string               `json:"fix,omitempty"`
	FixAuthority    string               `json:"fix_authority,omitempty"`
	EvidenceIDs     []string             `json:"evidence_ids"`
	Contributors    []setContributorWire `json:"contributors"`
	report          localreview.ReportFinding
	coveredStart    uint32
	coveredEnd      uint32
	normalizedTitle string
	entries         []findingGroupEntry
	narrowStart     uint32
	narrowEnd       uint32
	// representativeMember and representativeTokens identify the one finding
	// whose claims decide whether a later finding is the same issue. They are
	// the group's first finding, replaced when a more severe member becomes
	// the reported representative.
	representativeMember int
	representativeTokens map[string]bool
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
}

type modelReviewSetWire struct {
	Contract               string                  `json:"contract"`
	Version                int                     `json:"schema_version"`
	Status                 string                  `json:"status"`
	CI                     string                  `json:"ci_disposition"`
	Complete               bool                    `json:"complete"`
	Selection              specialistSelectionWire `json:"selection"`
	Members                []setMemberWire         `json:"members"`
	Summary                setSummaryWire          `json:"summary"`
	Findings               []setFindingWire        `json:"findings"`
	Bounds                 setBoundsWire           `json:"bounds"`
	Limitations            []string                `json:"limitations"`
	ComprehensiveClearance bool                    `json:"comprehensive_clearance"`
	headRevision           string
	independence           string
	failure                string
	runStatus              string
	report                 *localreview.Report
}

// runLocalModelReviewSet runs the general review, then each selected
// specialist as its own session and run, sequentially. It stops launching
// members once the invocation context is done or a launched member's run did
// not succeed (refused, failed, canceled, or source unreadable); it never
// retries. preparedStatus is a non-empty unstarted status when configuration
// or source preparation already failed, in which case no session starts.
func runLocalModelReviewSet(ctx, execution context.Context, options localModelReviewOptions, inputs localModelReviewInputs, preparedStatus string, stdout, stderr io.Writer) int {
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
	members := []localModelReviewMember{general}
	notLaunched := map[int]string{}
	stopReason := ""
	if report, err := general.result.Report(); err != nil || report.RunStatus != "succeeded" {
		stopReason = "general_review_did_not_complete"
	}
	for index, specialist := range selected {
		if stopReason == "" && ctx != nil && ctx.Err() != nil {
			stopReason = "canceled"
		}
		if stopReason != "" {
			result, err := localreview.NewUnstartedSpecialistResult(unlaunchedStatus(stopReason), options.objectStoreProfile, specialist)
			if err != nil {
				return 1
			}
			notLaunched[index+1] = stopReason
			members = append(members, localModelReviewMember{specialist: specialist, result: result})
			continue
		}
		memberExecution, cancel := context.WithTimeout(ctx, options.timeout)
		member, ok := runLocalModelReviewMember(ctx, memberExecution, options, inputs, specialist, false)
		cancel()
		if !ok {
			return 1
		}
		if member.partialCheckout {
			fmt.Fprintln(stderr, partialCheckoutHint)
		}
		members = append(members, member)
		if report, err := member.result.Report(); err != nil {
			stopReason = "stopped_after_" + specialist.ProfileID() + "_unreadable"
		} else if report.RunStatus != "succeeded" {
			stopReason = "stopped_after_" + specialist.ProfileID() + "_" + report.Status
		}
	}
	set := buildModelReviewSet(selection, members, notLaunched, options)
	return writeModelReviewSet(options.format, options.exitPolicy, set, stdout, stderr)
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
func buildModelReviewSet(selection specialistSelectionWire, members []localModelReviewMember, notLaunched map[int]string, options localModelReviewOptions) modelReviewSetWire {
	set := modelReviewSetWire{
		Contract: modelReviewSetContract, Version: modelReviewSetVersion, Selection: selection, Members: []setMemberWire{}, Findings: []setFindingWire{},
		Summary: setSummaryWire{BySeverity: map[string]int{}, ByCategory: map[string]int{}, MembersSelected: len(members)},
		Limitations: []string{
			"per_profile_route_assignment_not_applied", "sequential_members_no_parallelism", "deduplication_is_heuristic",
			"merged_findings_only_from_completed_members", "no_publication",
		},
	}
	cleanup := localModelCleanupTimeout(options.timeout)
	set.Bounds = setBoundsWire{
		MaxSpecialists: selection.MaxSpecialists, MemberTimeoutMillis: options.timeout.Milliseconds(),
		MaxModelWallTimeMillis:   int64(len(members)) * options.timeout.Milliseconds(),
		MemberCleanupBoundMillis: cleanup.Milliseconds(),
		Execution:                "sequential: general review first, then selected specialists in priority order; each member has its own timeout and independent verification",
	}
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
			wire.ReviewRunID, wire.ScopeIdentity, wire.PlanIdentity, wire.ContextIdentity = report.ReviewRunID, report.ScopeIdentity, report.PlanIdentity, report.ContextIdentity
			wire.GenerationRoute, wire.VerificationRoute, wire.Independence, wire.DiagnosticSet = report.GenerationRoute, report.VerificationRoute, report.Independence, report.DiagnosticSet
			wire.UsageKnown, wire.ActualCostMicroUSD = report.UsageKnown, report.ActualCostMicroUSD
			wire.Limitations = append(wire.Limitations, report.Limitations...)
			wire.VerifiedFindings = len(report.Findings)
			wire.statusFindingsEmpty = report.Status == "findings" && len(report.Findings) == 0
			if report.HasVerifiedSet {
				wire.Candidates, wire.Verified, wire.Rejected, wire.Inconclusive = sarifPointer(report.Candidates), sarifPointer(report.Verified), sarifPointer(report.Rejected), sarifPointer(report.Inconclusive)
			}
			if report.RunStatus == "succeeded" {
				memberFindings = append(memberFindings, report.Findings)
			} else {
				memberFindings = append(memberFindings, nil)
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
	merged, duplicates := mergeVerifiedFindings(labels, memberFindings)
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
		// from a completed member: it still blocks.
		if hasErrorSeverityFinding(merged) {
			set.CI = "blocked"
		}
	case len(merged) > 0:
		set.Status, set.CI = "findings", "blocked"
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
// critical (error-severity) finding.
func hasErrorSeverityFinding(findings []setFindingWire) bool {
	for _, finding := range findings {
		if finding.report.Severity == diagnostics.SeverityError {
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

// severityRank orders diagnostic severities; higher is more severe.
func severityRank(severity diagnostics.Severity) int {
	switch severity {
	case diagnostics.SeverityError:
		return 4
	case diagnostics.SeverityWarning:
		return 3
	case diagnostics.SeverityInformation:
		return 2
	case diagnostics.SeverityHint:
		return 1
	}
	return 0
}

// normalizeFindingTitle lowercases a title and collapses every run of
// non-letter, non-digit characters to one space.
func normalizeFindingTitle(title string) string {
	var builder strings.Builder
	space := false
	for _, character := range strings.ToLower(title) {
		if unicode.IsLetter(character) || unicode.IsDigit(character) {
			if space && builder.Len() > 0 {
				builder.WriteByte(' ')
			}
			builder.WriteRune(character)
			space = false
		} else {
			space = true
		}
	}
	return builder.String()
}

// findingDuplicateOverlapNumerator / findingDuplicateOverlapDenominator is the
// minimum Jaccard overlap (0.3) of two findings' word sets for them to count as
// the same issue. Integer arithmetic keeps the comparison exact.
const (
	findingDuplicateOverlapNumerator   = 3
	findingDuplicateOverlapDenominator = 10
)

// findingStopwords are frequent English words that carry no defect identity.
var findingStopwords = map[string]bool{
	"the": true, "and": true, "for": true, "with": true, "that": true, "this": true, "from": true, "into": true, "when": true,
	"without": true, "which": true, "may": true, "can": true, "could": true, "will": true, "would": true, "not": true, "its": true,
	"are": true, "was": true, "were": true, "has": true, "have": true, "been": true, "being": true, "than": true, "then": true,
	"because": true, "due": true, "also": true, "does": true, "any": true, "all": true, "but": true, "only": true, "there": true,
	"their": true, "they": true, "should": true, "must": true, "such": true, "other": true, "some": true, "more": true,
}

// findingTokens is the set of lowercase words of at least three letters or
// digits in a finding's title and claim, without stopwords.
func findingTokens(title, claim string) map[string]bool {
	tokens := map[string]bool{}
	for _, word := range strings.Fields(normalizeFindingTitle(title + " " + claim)) {
		if len(word) >= 3 && !findingStopwords[word] {
			tokens[word] = true
		}
	}
	return tokens
}

// tokensOverlap reports a Jaccard overlap of at least 0.3.
func tokensOverlap(a, b map[string]bool) bool {
	shared := 0
	for word := range a {
		if b[word] {
			shared++
		}
	}
	union := len(a) + len(b) - shared
	return union > 0 && shared*findingDuplicateOverlapDenominator >= union*findingDuplicateOverlapNumerator
}

// findingGroupEntry is what the duplicate rule compares for one absorbed finding.
type findingGroupEntry struct {
	member   int
	title    string
	tokens   map[string]bool
	evidence []string
}

// related reports whether a finding describes the same issue as the group's
// representative finding. Only the representative's own claim tokens count:
// letting an absorbed finding's tokens qualify a later merge would chain
// findings together and can collapse a distinct defect into another defect's
// title and severity.
//
// The representative is the group's first finding in run order, so member
// order still decides which finding anchors a group. When a more severe
// member replaces it, the group's tokens are replaced with that member's
// tokens so the comparison always uses one finding's claims.
func (g *setFindingWire) related(member int, tokens map[string]bool) bool {
	if g.representativeMember == member {
		return false
	}
	return tokensOverlap(g.representativeTokens, tokens)
}

// mergeVerifiedFindings de-duplicates verified findings across members. Two
// findings are duplicates when they share path and category, the finding's
// line range overlaps the representative's range, and it describes the same
// issue as the representative (see related). Only the representative's range
// and claims decide a match, so a finding cannot join a group through a
// finding the group already absorbed. Wording overlap is still a heuristic:
// it can merge or keep apart findings that a person would judge differently.
//
// The group keeps the most severe finding as its representative; ties keep the
// earliest member in run order. The reported range is the narrowest
// contributing range (ties keep the earliest). Every contributing member is
// listed. Matching is deterministic: members in run order, findings sorted by
// path, range and identity. Output is sorted by path, line range, category
// and identity.
func mergeVerifiedFindings(labels []string, findings [][]localreview.ReportFinding) ([]setFindingWire, int) {
	var groups []*setFindingWire
	duplicates := 0
	for index, memberFindings := range findings {
		ordered := append([]localreview.ReportFinding(nil), memberFindings...)
		sort.SliceStable(ordered, func(i, j int) bool {
			a, b := ordered[i], ordered[j]
			if a.Path != b.Path {
				return a.Path < b.Path
			}
			if a.StartLine != b.StartLine {
				return a.StartLine < b.StartLine
			}
			if a.EndLine != b.EndLine {
				return a.EndLine < b.EndLine
			}
			return a.Identity < b.Identity
		})
		for _, finding := range ordered {
			title := normalizeFindingTitle(finding.Title)
			tokens := findingTokens(finding.Title, finding.Claim)
			entry := findingGroupEntry{member: index, title: title, tokens: tokens, evidence: finding.EvidenceIDs}
			contributor := setContributorWire{Member: labels[index], FindingIdentity: finding.Identity, Severity: finding.Severity.String(), StartLine: finding.StartLine, EndLine: finding.EndLine}
			var group *setFindingWire
			for _, candidate := range groups {
				if candidate.Path == finding.Path && candidate.Category == finding.Category &&
					finding.StartLine <= candidate.coveredEnd && candidate.coveredStart <= finding.EndLine &&
					candidate.related(index, tokens) {
					group = candidate
					break
				}
			}
			if group == nil {
				value := setFindingFromReport(finding, title)
				value.Contributors = []setContributorWire{contributor}
				value.entries = []findingGroupEntry{entry}
				value.narrowStart, value.narrowEnd = finding.StartLine, finding.EndLine
				value.coveredStart, value.coveredEnd = finding.StartLine, finding.EndLine
				value.representativeMember, value.representativeTokens = index, tokens
				groups = append(groups, &value)
				continue
			}
			duplicates++
			group.Contributors = append(group.Contributors, contributor)
			group.entries = append(group.entries, entry)
			if finding.EndLine-finding.StartLine < group.narrowEnd-group.narrowStart {
				group.narrowStart, group.narrowEnd = finding.StartLine, finding.EndLine
			}
			if severityRank(finding.Severity) > severityRank(group.report.Severity) {
				replacement := setFindingFromReport(finding, title)
				replacement.Contributors = group.Contributors
				// The reported representative also decides later merges, so its
				// range and claims become the group's comparison basis.
				replacement.coveredStart, replacement.coveredEnd = finding.StartLine, finding.EndLine
				replacement.entries, replacement.narrowStart, replacement.narrowEnd = group.entries, group.narrowStart, group.narrowEnd
				replacement.representativeMember, replacement.representativeTokens = index, tokens
				*group = replacement
			}
		}
	}
	out := make([]setFindingWire, 0, len(groups))
	for _, group := range groups {
		value := *group
		value.StartLine, value.EndLine = value.narrowStart, value.narrowEnd
		out = append(out, value)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		switch {
		case a.Path != b.Path:
			return a.Path < b.Path
		case a.StartLine != b.StartLine:
			return a.StartLine < b.StartLine
		case a.EndLine != b.EndLine:
			return a.EndLine < b.EndLine
		case a.Category != b.Category:
			return a.Category < b.Category
		}
		return a.FindingIdentity < b.FindingIdentity
	})
	return out, duplicates
}

func setFindingFromReport(finding localreview.ReportFinding, normalizedTitle string) setFindingWire {
	value := setFindingWire{
		FindingIdentity: finding.Identity, Title: finding.Title, Claim: finding.Claim, Severity: finding.Severity.String(), Path: finding.Path,
		StartLine: finding.StartLine, EndLine: finding.EndLine, Category: finding.Category, Fix: finding.Fix,
		EvidenceIDs: append([]string{}, finding.EvidenceIDs...), report: finding,
		coveredStart: finding.StartLine, coveredEnd: finding.EndLine, normalizedTitle: normalizedTitle,
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
//   - default: 4 blocked (findings or a refused member), 3 inconclusive, 1 error.
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
	for _, finding := range s.Findings {
		if finding.report.Severity == diagnostics.SeverityError {
			return true
		}
	}
	return false
}

func writeModelReviewSet(format string, policy localreview.ExitPolicy, set modelReviewSetWire, stdout, stderr io.Writer) int {
	var encoded []byte
	var err error
	switch format {
	case "text":
		encoded, err = renderModelReviewSetText(set)
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

func renderModelReviewSetText(set modelReviewSetWire) ([]byte, error) {
	var buffer bytes.Buffer
	fmt.Fprintf(&buffer, "specialist review set: status=%s ci=%s complete=%t\n", set.Status, set.CI, set.Complete)
	selectionStatus := set.Selection.Status
	if set.Selection.Reason != "" {
		selectionStatus += " (" + set.Selection.Reason + ")"
	}
	fmt.Fprintf(&buffer, "selection: mode=%s status=%s max=%d\n", set.Selection.Mode, selectionStatus, set.Selection.MaxSpecialists)
	if features := set.Selection.Features; features != nil {
		fmt.Fprintf(&buffer, "change features: files=%d languages=%s classes=%s security=%s\n", features.ChangedFiles, joinOrNone(features.Languages), joinOrNone(features.FileClasses), joinOrNone(features.SecuritySignals))
	}
	selected := []string{}
	for _, value := range set.Selection.Selected {
		selected = append(selected, value.ProfileID)
	}
	fmt.Fprintf(&buffer, "selected: %s\n", joinOrNone(selected))
	for _, value := range set.Selection.Dropped {
		fmt.Fprintf(&buffer, "dropped: %s (%s)\n", value.ProfileID, value.Reason)
	}
	fmt.Fprintf(&buffer, "route assignment: %s\n", set.Selection.RouteAssignment)
	fmt.Fprintf(&buffer, "members run: %d of %d\n", set.Summary.MembersRun, set.Summary.MembersSelected)
	for _, member := range set.Members {
		if !member.Launched {
			fmt.Fprintf(&buffer, "member: %s not run (%s)\n", member.Member, member.NotLaunchedReason)
			continue
		}
		if member.RunStatus != "succeeded" && member.Failure != "" {
			fmt.Fprintf(&buffer, "member: %s status=%s run=%s verified_findings=%d failure=%s\n", member.Member, member.Status, member.RunStatus, member.VerifiedFindings, localreview.FailureLine(member.Failure, member.FailureTask, member.FailureDetail))
			if member.failureHint != "" {
				fmt.Fprintf(&buffer, "member hint: %s: %s\n", member.Member, member.failureHint)
			}
			continue
		}
		fmt.Fprintf(&buffer, "member: %s status=%s run=%s verified_findings=%d\n", member.Member, member.Status, member.RunStatus, member.VerifiedFindings)
	}
	severities := sortedCounts(set.Summary.BySeverity)
	categories := sortedCounts(set.Summary.ByCategory)
	fmt.Fprintf(&buffer, "findings: %d (merged duplicates: %d) severity: %s category: %s\n", set.Summary.Findings, set.Summary.DuplicatesMerged, joinOrNone(severities), joinOrNone(categories))
	if coverage := set.Summary.SourceCoverage; coverage != nil {
		fmt.Fprintf(&buffer, "files covered: analyzed=%d selected=%d omitted=%d\n", coverage.Analyzed, coverage.Selected, coverage.Omitted)
	}
	for _, finding := range set.Findings {
		fmt.Fprintf(&buffer, "finding: %s %s\nsource: %s:%d-%d\nmessage: %s\nevidence: %s\n", finding.Severity, finding.Title, finding.Path, finding.StartLine, finding.EndLine, finding.Claim, strings.Join(finding.EvidenceIDs, ", "))
		if finding.Category != "" {
			fmt.Fprintf(&buffer, "category: %s\n", finding.Category)
		}
		if finding.Fix != "" {
			// Fix text is unverified model guidance; it is printed, never applied.
			fmt.Fprintf(&buffer, "fix: %s\n", finding.Fix)
		}
		fmt.Fprintf(&buffer, "contributors: %s\n", strings.Join(finding.contributorLabels(), ", "))
	}
	fmt.Fprintf(&buffer, "limitations: %s\ncomprehensive clearance: false\n", strings.Join(set.Limitations, ", "))
	if buffer.Len() > maxModelReviewSetTextBytes {
		return nil, errors.New("model review set text exceeds output bound")
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
	}
	if set.report != nil && set.report.HasSourceCoverage {
		report.HasSourceCoverage = true
		report.SourceAnalyzed, report.SourceSelected, report.SourceOmitted = set.report.SourceAnalyzed, set.report.SourceSelected, set.report.SourceOmitted
		report.Omissions = append(report.Omissions, set.report.Omissions...)
	}
	contributors := map[string][]string{}
	for _, finding := range set.Findings {
		report.Findings = append(report.Findings, finding.report)
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
