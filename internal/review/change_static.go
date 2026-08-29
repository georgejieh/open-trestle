package review

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"sort"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

// Absolute caps bound validation and AST work independently of caller limits.
const (
	maxDebugOutputChangeFiles        = 1024
	maxDebugOutputChangeBytesPerFile = 1 << 20
	maxDebugOutputChangeTotalBytes   = 64 << 20
	maxDebugOutputChangeFindings     = 1 << 16
	debugOutputChangeRuleVersion     = "1"
)

// DebugOutputChangeError identifies an expected bounded review failure.
type DebugOutputChangeError string

// DebugOutputChangeResourceLimit identifies an invalid or exceeded review bound.
const DebugOutputChangeResourceLimit DebugOutputChangeError = "resource_limit"

// Error returns the stable review failure category.
func (e DebugOutputChangeError) Error() string { return string(e) }

// DebugOutputChangeLimits bounds one pure change-level rule execution.
type DebugOutputChangeLimits struct {
	MaxFiles        int
	MaxBytesPerFile int
	MaxTotalBytes   int64
	MaxFindings     int
}

// DebugOutputChangeOutcome identifies one file's static-rule coverage.
type DebugOutputChangeOutcome string

const (
	// DebugOutputChangeOutcomeAnalyzed identifies a file scanned over positive head ranges.
	DebugOutputChangeOutcomeAnalyzed DebugOutputChangeOutcome = "analyzed"
	// DebugOutputChangeOutcomeNotApplicable identifies a file outside rule execution.
	DebugOutputChangeOutcomeNotApplicable DebugOutputChangeOutcome = "not_applicable"
)

// DebugOutputChangeReason explains one file coverage outcome.
type DebugOutputChangeReason string

const (
	// DebugOutputChangeReasonNone identifies completed rule analysis.
	DebugOutputChangeReasonNone DebugOutputChangeReason = "none"
	// DebugOutputChangeReasonUnsupportedLanguage identifies a non-Go path.
	DebugOutputChangeReasonUnsupportedLanguage DebugOutputChangeReason = "unsupported_language"
	// DebugOutputChangeReasonNoPositiveHeadRanges identifies deletion-only evidence.
	DebugOutputChangeReasonNoPositiveHeadRanges DebugOutputChangeReason = "no_positive_head_ranges"
)

// DebugOutputChangeFileCoverage records exact rule coverage for one changed path.
type DebugOutputChangeFileCoverage struct {
	path       string
	outcome    DebugOutputChangeOutcome
	reason     DebugOutputChangeReason
	headDigest string
	matchCount int
}

// DebugOutputChangeResult records complete bounded rule execution over one Change.
type DebugOutputChangeResult struct {
	identity       string
	changeIdentity string
	ruleVersion    string
	findings       []Finding
	evidenceItems  []evidence.EvidenceItem
	files          []DebugOutputChangeFileCoverage
}

// ReviewDebugOutputChange applies the existing debug-output rule to one exact Change.
func ReviewDebugOutputChange(change evidence.Change, headContents map[string][]byte, limits DebugOutputChangeLimits) (DebugOutputChangeResult, error) {
	canonicalChange, err := evidence.NewChange(change.FileChanges(), change.LineMaps())
	if err != nil || canonicalChange.Identity() != change.Identity() {
		return DebugOutputChangeResult{}, fmt.Errorf("change is not canonical")
	}
	if err := validateDebugOutputChangeLimits(limits); err != nil {
		return DebugOutputChangeResult{}, err
	}
	fileChanges := canonicalChange.FileChanges()
	lineMaps := canonicalChange.LineMaps()
	if len(fileChanges) > limits.MaxFiles {
		return DebugOutputChangeResult{}, DebugOutputChangeResourceLimit
	}
	if len(headContents) != len(fileChanges) {
		return DebugOutputChangeResult{}, fmt.Errorf("head content count does not match Change")
	}
	expectedPaths := make(map[string]struct{}, len(fileChanges))
	for _, fileChange := range fileChanges {
		expectedPaths[fileChange.Path()] = struct{}{}
	}
	providedPaths := make([]string, 0, len(headContents))
	for providedPath := range headContents {
		providedPaths = append(providedPaths, providedPath)
	}
	sort.Strings(providedPaths)
	for _, providedPath := range providedPaths {
		if _, ok := expectedPaths[providedPath]; !ok {
			return DebugOutputChangeResult{}, fmt.Errorf("unexpected head content path %q", providedPath)
		}
	}
	var totalBytes int64
	for index, fileChange := range fileChanges {
		content, ok := headContents[fileChange.Path()]
		if !ok {
			return DebugOutputChangeResult{}, fmt.Errorf("missing head content for %q", fileChange.Path())
		}
		if len(content) > limits.MaxBytesPerFile || totalBytes > limits.MaxTotalBytes-int64(len(content)) {
			return DebugOutputChangeResult{}, DebugOutputChangeResourceLimit
		}
		totalBytes += int64(len(content))
		if digestHex(content) != fileChange.HeadDigest() {
			return DebugOutputChangeResult{}, fmt.Errorf("head content digest does not match Change for %q", fileChange.Path())
		}
		if debugOutputPhysicalLineCount(content) != lineMaps[index].HeadLineCount() {
			return DebugOutputChangeResult{}, fmt.Errorf("head content line count does not match Change for %q", fileChange.Path())
		}
	}

	findings := make([]Finding, 0)
	items := make([]evidence.EvidenceItem, 0)
	files := make([]DebugOutputChangeFileCoverage, len(fileChanges))
	for index, fileChange := range fileChanges {
		content := headContents[fileChange.Path()]
		coverage := DebugOutputChangeFileCoverage{path: fileChange.Path(), headDigest: fileChange.HeadDigest()}
		switch {
		case path.Ext(fileChange.Path()) != ".go":
			coverage.outcome = DebugOutputChangeOutcomeNotApplicable
			coverage.reason = DebugOutputChangeReasonUnsupportedLanguage
		case len(fileChange.ChangedRanges()) == 0:
			coverage.outcome = DebugOutputChangeOutcomeNotApplicable
			coverage.reason = DebugOutputChangeReasonNoPositiveHeadRanges
		default:
			ranges, err := debugOutputRangesForSelections(content, fileChange.Path(), fileChange.ChangedRanges())
			if err != nil {
				return DebugOutputChangeResult{}, fmt.Errorf("analyze debug output for %q: %w", fileChange.Path(), err)
			}
			if len(ranges) > limits.MaxFindings-len(findings) {
				return DebugOutputChangeResult{}, DebugOutputChangeResourceLimit
			}
			for _, sourceRange := range ranges {
				finding, item, err := newDebugOutputChangeFinding(canonicalChange.Identity(), content, sourceRange)
				if err != nil {
					return DebugOutputChangeResult{}, err
				}
				findings = append(findings, finding)
				items = append(items, item)
			}
			coverage.outcome = DebugOutputChangeOutcomeAnalyzed
			coverage.reason = DebugOutputChangeReasonNone
			coverage.matchCount = len(ranges)
		}
		files[index] = coverage
	}
	return newDebugOutputChangeResult(canonicalChange, limits, findings, items, files)
}

func debugOutputPhysicalLineCount(content []byte) int {
	if len(content) == 0 {
		return 0
	}
	count := bytes.Count(content, []byte{'\n'})
	if content[len(content)-1] != '\n' {
		count++
	}
	return count
}

func validateDebugOutputChangeLimits(limits DebugOutputChangeLimits) error {
	if limits.MaxFiles <= 0 || limits.MaxFiles > maxDebugOutputChangeFiles || limits.MaxBytesPerFile <= 0 || limits.MaxBytesPerFile > maxDebugOutputChangeBytesPerFile || limits.MaxTotalBytes <= 0 || limits.MaxTotalBytes > maxDebugOutputChangeTotalBytes || limits.MaxFindings <= 0 || limits.MaxFindings > maxDebugOutputChangeFindings {
		return DebugOutputChangeResourceLimit
	}
	return nil
}

func newDebugOutputChangeFinding(changeIdentity string, source []byte, sourceRange evidence.SourceRange) (Finding, evidence.EvidenceItem, error) {
	selected, err := selectSourceRange(source, sourceRange)
	if err != nil {
		return Finding{}, evidence.EvidenceItem{}, fmt.Errorf("select debug output: %w", err)
	}
	evidenceDigest := digestHex(selected)
	evidenceID, err := canonicalIdentity("evidence-", struct {
		Contract       string `json:"contract"`
		SchemaVersion  int    `json:"schema_version"`
		Rule           string `json:"rule"`
		RuleVersion    string `json:"rule_version"`
		ChangeIdentity string `json:"change_identity"`
		Path           string `json:"path"`
		StartLine      int    `json:"start_line"`
		EndLine        int    `json:"end_line"`
		Digest         string `json:"digest"`
	}{
		Contract: "open-trestle/debug-output-change-evidence", SchemaVersion: 1,
		Rule: staticDebugRuleID, RuleVersion: debugOutputChangeRuleVersion, ChangeIdentity: changeIdentity,
		Path: sourceRange.Path(), StartLine: sourceRange.StartLine(), EndLine: sourceRange.EndLine(), Digest: evidenceDigest,
	})
	if err != nil {
		return Finding{}, evidence.EvidenceItem{}, err
	}
	item, err := evidence.NewEvidenceItem(evidenceID, evidence.EvidenceKindSource, evidenceDigest, sourceRange)
	if err != nil {
		return Finding{}, evidence.EvidenceItem{}, err
	}
	findingID, err := canonicalIdentity("finding-", struct {
		Contract       string   `json:"contract"`
		SchemaVersion  int      `json:"schema_version"`
		Rule           string   `json:"rule"`
		RuleVersion    string   `json:"rule_version"`
		ChangeIdentity string   `json:"change_identity"`
		EvidenceID     string   `json:"evidence_id"`
		Title          string   `json:"title"`
		Severity       Severity `json:"severity"`
	}{
		Contract: "open-trestle/debug-output-change-finding", SchemaVersion: 1,
		Rule: staticDebugRuleID, RuleVersion: debugOutputChangeRuleVersion, ChangeIdentity: changeIdentity,
		EvidenceID: evidenceID, Title: "Debug output left in source", Severity: SeverityMedium,
	})
	if err != nil {
		return Finding{}, evidence.EvidenceItem{}, err
	}
	finding, err := NewFinding(findingID, "Debug output left in source", SeverityMedium, sourceRange, []string{evidenceID})
	return finding, item, err
}

func newDebugOutputChangeResult(change evidence.Change, limits DebugOutputChangeLimits, findings []Finding, items []evidence.EvidenceItem, files []DebugOutputChangeFileCoverage) (DebugOutputChangeResult, error) {
	if len(findings) != len(items) {
		return DebugOutputChangeResult{}, fmt.Errorf("finding and evidence counts differ")
	}
	type fileWire struct {
		Path       string                   `json:"path"`
		Outcome    DebugOutputChangeOutcome `json:"outcome"`
		Reason     DebugOutputChangeReason  `json:"reason"`
		HeadDigest string                   `json:"head_digest"`
		MatchCount int                      `json:"match_count"`
	}
	preimage := struct {
		Contract        string     `json:"contract"`
		SchemaVersion   int        `json:"schema_version"`
		Rule            string     `json:"rule"`
		RuleVersion     string     `json:"rule_version"`
		ChangeIdentity  string     `json:"change_identity"`
		MaxFiles        int        `json:"max_files"`
		MaxBytesPerFile int        `json:"max_bytes_per_file"`
		MaxTotalBytes   int64      `json:"max_total_bytes"`
		MaxFindings     int        `json:"max_findings"`
		Files           []fileWire `json:"files"`
		FindingIDs      []string   `json:"finding_ids"`
		EvidenceIDs     []string   `json:"evidence_ids"`
	}{
		Contract: "open-trestle/debug-output-change-review", SchemaVersion: 1,
		Rule: staticDebugRuleID, RuleVersion: debugOutputChangeRuleVersion, ChangeIdentity: change.Identity(),
		MaxFiles: limits.MaxFiles, MaxBytesPerFile: limits.MaxBytesPerFile, MaxTotalBytes: limits.MaxTotalBytes, MaxFindings: limits.MaxFindings,
		Files: make([]fileWire, len(files)), FindingIDs: make([]string, len(findings)), EvidenceIDs: make([]string, len(items)),
	}
	for index, file := range files {
		preimage.Files[index] = fileWire{Path: file.path, Outcome: file.outcome, Reason: file.reason, HeadDigest: file.headDigest, MatchCount: file.matchCount}
	}
	for index, finding := range findings {
		preimage.FindingIDs[index] = finding.ID()
		preimage.EvidenceIDs[index] = items[index].ID()
	}
	encoded, err := json.Marshal(preimage)
	if err != nil {
		return DebugOutputChangeResult{}, err
	}
	digest := sha256.Sum256(encoded)
	return DebugOutputChangeResult{
		identity: hex.EncodeToString(digest[:]), changeIdentity: change.Identity(), ruleVersion: debugOutputChangeRuleVersion,
		findings: cloneFindings(findings), evidenceItems: append([]evidence.EvidenceItem(nil), items...), files: append([]DebugOutputChangeFileCoverage(nil), files...),
	}, nil
}

func cloneFindings(findings []Finding) []Finding {
	if len(findings) == 0 {
		return nil
	}
	result := make([]Finding, len(findings))
	for index, finding := range findings {
		finding.evidenceIDs = append([]string(nil), finding.evidenceIDs...)
		result[index] = finding
	}
	return result
}

// Identity returns the versioned canonical SHA-256 identity.
func (r DebugOutputChangeResult) Identity() string { return r.identity }

// ChangeIdentity returns the exact reviewed Change identity.
func (r DebugOutputChangeResult) ChangeIdentity() string { return r.changeIdentity }

// RuleVersion returns the pinned static rule version.
func (r DebugOutputChangeResult) RuleVersion() string { return r.ruleVersion }

// Findings returns canonical findings in path and source order.
func (r DebugOutputChangeResult) Findings() []Finding { return cloneFindings(r.findings) }

// EvidenceItems returns canonical source evidence in finding order.
func (r DebugOutputChangeResult) EvidenceItems() []evidence.EvidenceItem {
	return append([]evidence.EvidenceItem(nil), r.evidenceItems...)
}

// Files returns complete coverage in canonical Change path order.
func (r DebugOutputChangeResult) Files() []DebugOutputChangeFileCoverage {
	return append([]DebugOutputChangeFileCoverage(nil), r.files...)
}

// File returns coverage for one exact changed path.
func (r DebugOutputChangeResult) File(filePath string) (DebugOutputChangeFileCoverage, bool) {
	index := sort.Search(len(r.files), func(index int) bool { return r.files[index].path >= filePath })
	if index == len(r.files) || r.files[index].path != filePath {
		return DebugOutputChangeFileCoverage{}, false
	}
	return r.files[index], true
}

// Path returns the exact changed path.
func (c DebugOutputChangeFileCoverage) Path() string { return c.path }

// Outcome returns the file coverage outcome.
func (c DebugOutputChangeFileCoverage) Outcome() DebugOutputChangeOutcome { return c.outcome }

// Reason returns the file coverage reason.
func (c DebugOutputChangeFileCoverage) Reason() DebugOutputChangeReason { return c.reason }

// HeadDigest returns the exact validated head-content digest.
func (c DebugOutputChangeFileCoverage) HeadDigest() string { return c.headDigest }

// MatchCount returns the number of rule matches for the file.
func (c DebugOutputChangeFileCoverage) MatchCount() int { return c.matchCount }
