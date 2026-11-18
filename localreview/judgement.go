package localreview

import (
	"slices"

	"github.com/georgejieh/open-trestle/diagnostics"
	"github.com/georgejieh/open-trestle/semanticimpact"
)

// The deterministic judgement of a completed review: after independent
// verification, the host classifies each verified finding as introduced,
// pre-existing or of unproven origin, merges duplicates (DeduplicateFindings)
// and ranks the result (RankFindings). It is recorded in schema version 6
// results as rank, pre_existing and unproven_origin, in place, and never
// changes which findings were verified.

// rankWire is one distinct finding of a version 6 result, in rank order: the
// representative's diagnostic finding identity and the identities of the
// duplicates merged into it.
type rankWire struct {
	Rank            int      `json:"rank"`
	FindingIdentity string   `json:"finding_identity"`
	Merged          []string `json:"merged_finding_identities,omitempty"`
}

// anchorWire records that one verified finding lies inside a changed
// declaration of the run's semantic-impact profile: the declaration's first
// and last line on the finding's side. A parsed result's anchors cannot be
// re-derived without the profile; they are checked to name distinct findings
// in diagnostic order and to contain each finding's lines, and they only
// decide which findings merge into one ranked defect, which never changes the
// CI disposition or an exit code.
type anchorWire struct {
	FindingIdentity string `json:"finding_identity"`
	StartLine       uint32 `json:"start_line"`
	EndLine         uint32 `json:"end_line"`
}

// declarationAnchor is the narrowest changed declaration on the finding's
// path that holds all of its lines: an added or changed declaration for head
// lines, a removed one for removed base lines. Ties go to the earlier start.
func declarationAnchor(finding ReportFinding, declarations []semanticimpact.Declaration) FindingAnchor {
	var anchor FindingAnchor
	for _, declaration := range declarations {
		removed := declaration.Change() == semanticimpact.ChangeRemoved
		if declaration.Path() != finding.Path || removed != (finding.Side == diagnostics.LineSideBase) || declaration.StartLine() < 1 || declaration.EndLine() < declaration.StartLine() {
			continue
		}
		start, end := uint32(declaration.StartLine()), uint32(declaration.EndLine())
		if start > finding.StartLine || finding.EndLine > end {
			continue
		}
		if !anchor.set() || end-start < anchor.EndLine-anchor.StartLine || end-start == anchor.EndLine-anchor.StartLine && start < anchor.StartLine {
			anchor = FindingAnchor{StartLine: start, EndLine: end}
		}
	}
	return anchor
}

// singleRunOrigin labels the findings of one review run.
func singleRunOrigin(wire resultWire) string {
	if wire.Specialist != nil {
		return wire.Specialist.ProfileID
	}
	return "general"
}

// BlocksCI reports whether a verified finding makes a completed review
// blocking: a medium, high or critical finding that the change introduced. A
// low-severity finding (diagnostic information, or a hint) and a pre-existing
// finding are advisory and never block CI.
func BlocksCI(severity diagnostics.Severity, preExisting bool) bool {
	return !preExisting && severityRank(severity) >= severityRank(diagnostics.SeverityWarning)
}

// Blocking reports whether the merged finding blocks CI (see BlocksCI): its
// representative's severity is medium or higher and at least one contributor
// is on lines the change touched.
func (m MergedFinding) Blocking() bool {
	return BlocksCI(m.Finding.Severity, m.PreExisting())
}

// judgeResult records the judgement of a completed run that has diagnostics.
// A verified finding is pre-existing or of unproven origin when lines
// classify it so (see changeLines.origin); lines without change evidence
// classify none. When
// no verified finding blocks CI (each is low severity or pre-existing, see
// BlocksCI), the result keeps status findings and its CI disposition becomes
// inconclusive: the run is advisory. Only this function marks a result
// judged, so only a classification this process made from the run's own
// artifacts relaxes anything; a parsed result's pre_existing list stays
// advisory.
//
// declarations are the changed declarations of the run's semantic-impact
// profile (nil without one); each finding a changed declaration holds is
// anchored to it (declarationAnchor), recorded in declaration_anchors, and the
// merge rule reads the anchors.
func judgeResult(result Result, lines changeLines, declarations []semanticimpact.Declaration) (Result, error) {
	result.judged = true
	report, err := result.Report()
	if err != nil {
		return Result{}, err
	}
	var preExisting, unproven []string
	var anchors []anchorWire
	for index := range report.Findings {
		finding := &report.Findings[index]
		switch lines.origin(*finding) {
		case originPreExisting:
			finding.PreExisting = true
			preExisting = append(preExisting, finding.Identity)
		case originUnproven:
			finding.UnprovenOrigin = true
			unproven = append(unproven, finding.Identity)
		}
		if finding.Anchor = declarationAnchor(*finding, declarations); finding.Anchor.set() {
			anchors = append(anchors, anchorWire{FindingIdentity: finding.Identity, StartLine: finding.Anchor.StartLine, EndLine: finding.Anchor.EndLine})
		}
	}
	result.wire.PreExisting, result.wire.UnprovenOrigin, result.wire.Anchors = preExisting, unproven, anchors
	result.wire.Rank = rankEntries(report.Findings, singleRunOrigin(result.wire), report.Independence)
	if result.wire.Status == "findings" && len(report.Findings) > 0 && !slices.ContainsFunc(report.Findings, func(finding ReportFinding) bool { return BlocksCI(finding.Severity, finding.PreExisting) }) {
		result.wire.CI = "inconclusive"
	}
	return result, nil
}

// expectedImportedCI is the CI disposition a parsed completed result must
// carry, re-derived from what the result records: the readiness disposition,
// except that a version 6 result with verified findings that are all low
// severity is advisory (inconclusive). The pre-existing class cannot be
// re-derived without the change, so it never relaxes the disposition here,
// and a result whose disposition it relaxed is refused. Results before
// version 6 were written before low-severity runs became advisory and keep
// the readiness disposition.
func expectedImportedCI(version int, findings []diagnostics.Finding, readinessCI string) string {
	if version != tokenUsageResultVersion || readinessCI != "blocked" || len(findings) == 0 {
		return readinessCI
	}
	for _, finding := range findings {
		if BlocksCI(finding.Severity(), false) {
			return readinessCI
		}
	}
	return "inconclusive"
}

// rankEntries merges and ranks one run's findings into rank wire entries.
func rankEntries(findings []ReportFinding, origin, independence string) []rankWire {
	return rankEntriesBy(findings, origin, independence, false)
}

// rankEntriesBy is rankEntries; locationOnly merges by the location-only
// rule of earlier results (see deduplicateFindings).
func rankEntriesBy(findings []ReportFinding, origin, independence string, locationOnly bool) []rankWire {
	if len(findings) == 0 {
		return nil
	}
	ranked := RankFindings(deduplicateFindings([]FindingOrigin{{Label: origin, Independence: independence, Findings: findings}}, locationOnly))
	entries := make([]rankWire, 0, len(ranked))
	for _, group := range ranked {
		entry := rankWire{Rank: group.Rank, FindingIdentity: group.Finding.Identity}
		if merged := group.MergedIdentities(); len(merged) > 0 {
			entry.Merged = merged
		}
		entries = append(entries, entry)
	}
	return entries
}

// applyJudgement sets each report finding's rank and duplicate link from the
// recorded judgement and builds the ranked groups; it sets the pre-existing
// class only when trusted, that is when this process judged the result. An
// untrusted pre_existing list is checked to name distinct findings and is
// otherwise ignored. A result written without a recorded rank is ranked now.
// It fails when the recorded judgement does not cover the findings exactly
// once.
func (report *Report) applyJudgement(wire resultWire, trusted bool) error {
	byIdentity := make(map[string]int, len(report.Findings))
	for index, finding := range report.Findings {
		byIdentity[finding.Identity] = index
	}
	listed := make(map[string]bool, len(wire.PreExisting))
	for _, identity := range wire.PreExisting {
		index, ok := byIdentity[identity]
		if !ok || listed[identity] {
			return ErrInvalidResult
		}
		listed[identity] = true
		report.Findings[index].PreExisting = trusted
	}
	// The unproven_origin list only labels findings that block anyway, so a
	// parsed result's list is shown as recorded. A finding is in at most one
	// of the two lists.
	for _, identity := range wire.UnprovenOrigin {
		index, ok := byIdentity[identity]
		if !ok || listed[identity] {
			return ErrInvalidResult
		}
		listed[identity] = true
		report.Findings[index].UnprovenOrigin = true
	}
	anchored := make(map[string]bool, len(wire.Anchors))
	for _, anchor := range wire.Anchors {
		index, ok := byIdentity[anchor.FindingIdentity]
		if !ok || anchored[anchor.FindingIdentity] {
			return ErrInvalidResult
		}
		finding := &report.Findings[index]
		if anchor.StartLine < 1 || anchor.StartLine > finding.StartLine || finding.EndLine > anchor.EndLine {
			return ErrInvalidResult
		}
		anchored[anchor.FindingIdentity] = true
		finding.Anchor = FindingAnchor{StartLine: anchor.StartLine, EndLine: anchor.EndLine}
	}
	entries := wire.Rank
	if len(entries) == 0 {
		entries = rankEntries(report.Findings, singleRunOrigin(wire), report.Independence)
	}
	covered := 0
	report.Ranked = make([]MergedFinding, 0, len(entries))
	for position, entry := range entries {
		index, ok := byIdentity[entry.FindingIdentity]
		if !ok || entry.Rank != position+1 || report.Findings[index].Rank != 0 {
			return ErrInvalidResult
		}
		representative := &report.Findings[index]
		representative.Rank = entry.Rank
		group := MergedFinding{Finding: *representative, Origins: 1, Independence: report.Independence, Rank: entry.Rank}
		group.Contributors = append(group.Contributors, contributorOf(*representative, singleRunOrigin(wire)))
		for _, identity := range entry.Merged {
			merged, ok := byIdentity[identity]
			if !ok || report.Findings[merged].Rank != 0 || merged == index {
				return ErrInvalidResult
			}
			report.Findings[merged].Rank, report.Findings[merged].DuplicateOf = entry.Rank, representative.Identity
			group.Contributors = append(group.Contributors, contributorOf(report.Findings[merged], singleRunOrigin(wire)))
		}
		group.Finding = *representative
		covered += 1 + len(entry.Merged)
		report.Ranked = append(report.Ranked, group)
	}
	if covered != len(report.Findings) {
		return ErrInvalidResult
	}
	return nil
}

func contributorOf(finding ReportFinding, origin string) FindingContributor {
	return FindingContributor{Origin: origin, Identity: finding.Identity, Severity: finding.Severity, StartLine: finding.StartLine, EndLine: finding.EndLine, Side: finding.Side, PreExisting: finding.PreExisting, UnprovenOrigin: finding.UnprovenOrigin, Title: finding.Title, Claim: finding.Claim}
}

// validRecordedJudgement checks a parsed version 6 result's rank,
// pre_existing, unproven_origin and declaration_anchors against the judgement
// its own diagnostics and guidance produce: pre_existing, unproven_origin and
// the anchors list distinct diagnostic findings in diagnostic order (no
// finding in both classes), and rank is exactly the
// merge and rank of those findings, with the recorded list and anchors as the
// only pre-existing and declaration inputs. Neither can be re-derived without
// the change, so both stay advisory: the parsed result is not judged, the
// list never relaxes the CI disposition, and the anchors only decide merges.
func validRecordedJudgement(result Result) bool {
	wire := result.wire
	unjudged := wire.PreExisting == nil && wire.UnprovenOrigin == nil && wire.Anchors == nil
	if wire.Version != tokenUsageResultVersion {
		// Only version 6 records a judgement or a walkthrough.
		return wire.Rank == nil && unjudged && wire.Walkthrough == nil
	}
	if wire.Walkthrough.validate() != nil {
		return false
	}
	findings := result.diagnostics.Findings()
	if len(findings) == 0 {
		return wire.Rank == nil && unjudged
	}
	if len(wire.Rank) == 0 {
		// A version 6 result written before ranking was recorded.
		return unjudged
	}
	order := make(map[string]int, len(findings))
	for index, finding := range findings {
		order[finding.Identity()] = index
	}
	inOrder := func(identities []string) bool {
		previous := -1
		for _, identity := range identities {
			index, ok := order[identity]
			if !ok || index <= previous {
				return false
			}
			previous = index
		}
		return true
	}
	anchored := make([]string, 0, len(wire.Anchors))
	for _, anchor := range wire.Anchors {
		anchored = append(anchored, anchor.FindingIdentity)
	}
	if !inOrder(wire.PreExisting) || !inOrder(wire.UnprovenOrigin) || !inOrder(anchored) {
		return false
	}
	// The recorded rank was computed with the recorded classification and
	// anchors as its inputs, so it is recomputed the same way: by the current
	// merge rule, or by the location-only rule of results recorded before
	// paraphrases at one place needed related wording to merge. A rank only
	// orders and groups findings; it never changes a disposition.
	recomputed := result
	recomputed.judged = true
	report, err := recomputed.Report()
	if err != nil {
		return false
	}
	same := func(entries []rankWire) bool {
		return slices.EqualFunc(wire.Rank, entries, func(a, b rankWire) bool {
			return a.Rank == b.Rank && a.FindingIdentity == b.FindingIdentity && slices.Equal(a.Merged, b.Merged)
		})
	}
	origin := singleRunOrigin(wire)
	return same(rankEntriesBy(report.Findings, origin, report.Independence, false)) || same(rankEntriesBy(report.Findings, origin, report.Independence, true))
}
