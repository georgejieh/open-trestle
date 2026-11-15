package localreview

import (
	"slices"

	"github.com/georgejieh/open-trestle/diagnostics"
)

// The deterministic judgement of a completed review: after independent
// verification, the host classifies each verified finding as introduced or
// pre-existing, merges duplicates (DeduplicateFindings) and ranks the result
// (RankFindings). It is recorded in schema version 6 results as rank and
// pre_existing, in place, and never changes which findings were verified.

// rankWire is one distinct finding of a version 6 result, in rank order: the
// representative's diagnostic finding identity and the identities of the
// duplicates merged into it.
type rankWire struct {
	Rank            int      `json:"rank"`
	FindingIdentity string   `json:"finding_identity"`
	Merged          []string `json:"merged_finding_identities,omitempty"`
}

// singleRunOrigin labels the findings of one review run.
func singleRunOrigin(wire resultWire) string {
	if wire.Specialist != nil {
		return wire.Specialist.ProfileID
	}
	return "general"
}

// judgeResult records the judgement of a completed run that has diagnostics.
// A verified finding is pre-existing when lines classify it so (see
// changeLines.preExisting); lines without change evidence classify none. When every verified
// finding is pre-existing, the result keeps status findings and its CI
// disposition becomes inconclusive: a pre-existing finding never blocks CI.
func judgeResult(result Result, lines changeLines) (Result, error) {
	report, err := result.Report()
	if err != nil {
		return Result{}, err
	}
	var preExisting []string
	for index := range report.Findings {
		finding := &report.Findings[index]
		finding.PreExisting = lines.preExisting(*finding)
		if finding.PreExisting {
			preExisting = append(preExisting, finding.Identity)
		}
	}
	result.wire.PreExisting = preExisting
	result.wire.Rank = rankEntries(report.Findings, singleRunOrigin(result.wire), report.Independence)
	if result.wire.Status == "findings" && len(report.Findings) > 0 && len(preExisting) == len(report.Findings) {
		result.wire.CI = "inconclusive"
	}
	return result, nil
}

// rankEntries merges and ranks one run's findings into rank wire entries.
func rankEntries(findings []ReportFinding, origin, independence string) []rankWire {
	if len(findings) == 0 {
		return nil
	}
	ranked := RankFindings(DeduplicateFindings([]FindingOrigin{{Label: origin, Independence: independence, Findings: findings}}))
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

// applyJudgement sets each report finding's pre-existing class, rank and
// duplicate link from the recorded judgement and builds the ranked groups. A
// result written without a recorded rank is ranked now, with no pre-existing
// class. It fails when the recorded judgement does not cover the findings
// exactly once.
func (report *Report) applyJudgement(wire resultWire) error {
	byIdentity := make(map[string]int, len(report.Findings))
	for index, finding := range report.Findings {
		byIdentity[finding.Identity] = index
	}
	for _, identity := range wire.PreExisting {
		index, ok := byIdentity[identity]
		if !ok || report.Findings[index].PreExisting {
			return ErrInvalidResult
		}
		report.Findings[index].PreExisting = true
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
	return FindingContributor{Origin: origin, Identity: finding.Identity, Severity: finding.Severity, StartLine: finding.StartLine, EndLine: finding.EndLine, Side: finding.Side, PreExisting: finding.PreExisting}
}

// validRecordedJudgement checks a parsed version 6 result's rank and
// pre_existing against the judgement its own diagnostics and guidance
// produce: pre_existing lists distinct diagnostic findings in diagnostic
// order, and rank is exactly the merge and rank of those findings.
func validRecordedJudgement(result Result) bool {
	wire := result.wire
	if wire.Version != tokenUsageResultVersion {
		// Only version 6 records a judgement or a walkthrough.
		return wire.Rank == nil && wire.PreExisting == nil && wire.Walkthrough == nil
	}
	if wire.Walkthrough.validate() != nil {
		return false
	}
	findings := result.diagnostics.Findings()
	if len(findings) == 0 {
		return wire.Rank == nil && wire.PreExisting == nil
	}
	if len(wire.Rank) == 0 {
		// A version 6 result written before ranking was recorded.
		return wire.PreExisting == nil
	}
	order := make(map[string]int, len(findings))
	for index, finding := range findings {
		order[finding.Identity()] = index
	}
	previous := -1
	for _, identity := range wire.PreExisting {
		index, ok := order[identity]
		if !ok || index <= previous {
			return false
		}
		previous = index
	}
	report, err := result.Report()
	if err != nil {
		return false
	}
	return slices.EqualFunc(wire.Rank, rankEntries(report.Findings, singleRunOrigin(wire), report.Independence), func(a, b rankWire) bool {
		return a.Rank == b.Rank && a.FindingIdentity == b.FindingIdentity && slices.Equal(a.Merged, b.Merged)
	})
}

// expectedCompletedCI is the CI disposition of a completed result: the
// readiness disposition, except that a result whose every verified finding is
// pre-existing is inconclusive rather than blocked.
func expectedCompletedCI(set diagnostics.Set, preExisting []string, readinessCI string) string {
	if readinessCI == "blocked" && set.VerifiedCount() > 0 && len(preExisting) == len(set.Findings()) {
		return "inconclusive"
	}
	return readinessCI
}
