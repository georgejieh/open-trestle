// Package diagnostics defines secret-free verified review diagnostics for editor transports.
package diagnostics

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/georgejieh/open-trestle/audit"
	"io"
	"path"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	maxDiagnostics             = 100
	maxDiagnosticTextBytes     = 4096
	maxDiagnosticPathBytes     = 1024
	maxDiagnosticLine          = 10000000
	maxDiagnosticSourceCount   = 65664
	maxDiagnosticSelectedCount = 32
	maxEncodedSetBytes         = MaxEncodedSetBytes
)

// MaxEncodedSetBytes is the complete canonical diagnostic payload budget.
const MaxEncodedSetBytes = 1 << 20

var (
	// ErrInvalidFinding identifies malformed or unbound diagnostic data.
	ErrInvalidFinding = errors.New("invalid review diagnostic")
	// ErrInvalidFindingIdentity identifies content inconsistent with its diagnostic identity.
	ErrInvalidFindingIdentity = errors.New("invalid review diagnostic identity")
	// ErrInvalidSet identifies malformed, duplicate, unsorted, or cross-scope diagnostics.
	ErrInvalidSet = errors.New("invalid review diagnostic set")
	// ErrInvalidSetIdentity identifies set content inconsistent with its identity.
	ErrInvalidSetIdentity = errors.New("invalid review diagnostic set identity")
	// ErrInvalidSetEncoding identifies noncanonical, unknown, or excessive JSON.
	ErrInvalidSetEncoding = errors.New("invalid review diagnostic set encoding")
)

// Severity is a closed editor-neutral diagnostic level.
type Severity uint8

const (
	SeverityError Severity = iota + 1
	SeverityWarning
	SeverityInformation
	SeverityHint
)

func (s Severity) String() string {
	switch s {
	case SeverityError:
		return "error"
	case SeverityWarning:
		return "warning"
	case SeverityInformation:
		return "information"
	case SeverityHint:
		return "hint"
	default:
		return ""
	}
}

// Finding is one independently verified source-range diagnostic.
type Finding struct {
	identity, sourceIdentity, fingerprint, title, message, path string
	severity                                                    Severity
	startLine, endLine                                          uint32
	evidenceIDs                                                 []string
}

func NewFinding(sourceIdentity, fingerprint, title, message string, severity Severity, sourcePath string, startLine, endLine uint32, evidenceIDs []string) (Finding, error) {
	evidence := append([]string(nil), evidenceIDs...)
	sort.Strings(evidence)
	validIdentity := validDigest(sourceIdentity) && validDigest(fingerprint)
	validContent := validText(title, 256) && validText(message, maxDiagnosticTextBytes)
	validLocation := severity.String() != "" && validPath(sourcePath) && startLine > 0 && endLine >= startLine && endLine <= maxDiagnosticLine
	validEvidence := len(evidence) > 0 && len(evidence) <= 16
	if !validIdentity || !validContent || !validLocation || !validEvidence {
		return Finding{}, ErrInvalidFinding
	}
	for index, identity := range evidence {
		if !validEvidenceID(identity) || index > 0 && identity == evidence[index-1] {
			return Finding{}, ErrInvalidFinding
		}
	}
	finding := Finding{
		sourceIdentity: sourceIdentity, fingerprint: fingerprint,
		title: strings.Clone(title), message: strings.Clone(message), severity: severity,
		path: strings.Clone(sourcePath), startLine: startLine, endLine: endLine, evidenceIDs: evidence,
	}
	finding.identity = hashValue(struct {
		SourceIdentity string   `json:"source_identity"`
		Fingerprint    string   `json:"fingerprint"`
		Title          string   `json:"title"`
		Message        string   `json:"message"`
		Severity       string   `json:"severity"`
		Path           string   `json:"path"`
		StartLine      uint32   `json:"start_line"`
		EndLine        uint32   `json:"end_line"`
		Evidence       []string `json:"evidence"`
	}{sourceIdentity, fingerprint, title, message, severity.String(), sourcePath, startLine, endLine, evidence})
	return finding, nil
}
func (f Finding) Identity() string       { return f.identity }
func (f Finding) SourceIdentity() string { return f.sourceIdentity }
func (f Finding) Fingerprint() string    { return f.fingerprint }
func (f Finding) Title() string          { return f.title }
func (f Finding) Message() string        { return f.message }
func (f Finding) Severity() Severity     { return f.severity }
func (f Finding) Path() string           { return f.path }
func (f Finding) StartLine() uint32      { return f.startLine }
func (f Finding) EndLine() uint32        { return f.endLine }
func (f Finding) EvidenceIDs() []string  { return append([]string(nil), f.evidenceIDs...) }
func (f Finding) Validate() error {
	rebuilt, err := NewFinding(f.sourceIdentity, f.fingerprint, f.title, f.message, f.severity, f.path, f.startLine, f.endLine, f.evidenceIDs)
	if err != nil {
		return err
	}
	if rebuilt.identity != f.identity {
		return ErrInvalidFindingIdentity
	}
	return nil
}

func (f Finding) String() string   { return "verified review diagnostic" }
func (f Finding) GoString() string { return "diagnostics.Finding{<redacted>}" }
func (f Finding) Format(state fmt.State, verb rune) {
	writeFormat(state, verb, "verified review diagnostic", "diagnostics.Finding{<redacted>}")
}

// OmissionReason is a closed content-free source omission category.
type OmissionReason uint8

const (
	OmissionAuthorization OmissionReason = iota + 1
	OmissionResourceLimit
	OmissionUnsupported
	OmissionAnalysisFailure
	OmissionDuplicate
	OmissionSelectionLimit
)

func (r OmissionReason) String() string {
	switch r {
	case OmissionAuthorization:
		return "authorization"
	case OmissionResourceLimit:
		return "resource_limit"
	case OmissionUnsupported:
		return "unsupported"
	case OmissionAnalysisFailure:
		return "analysis_failure"
	case OmissionDuplicate:
		return "duplicate"
	case OmissionSelectionLimit:
		return "selection_limit"
	default:
		return ""
	}
}

// OmissionSummary contains no source path or content.
type OmissionSummary struct {
	reason OmissionReason
	count  uint32
}

// NewOmissionSummary creates one bounded aggregate source-omission count.
func NewOmissionSummary(reason OmissionReason, count uint32) (OmissionSummary, error) {
	if reason.String() == "" || count == 0 || count > maxDiagnosticSourceCount {
		return OmissionSummary{}, ErrInvalidSet
	}
	return OmissionSummary{reason: reason, count: count}, nil
}

func (s OmissionSummary) Reason() OmissionReason { return s.reason }
func (s OmissionSummary) Count() uint32          { return s.count }
func (s OmissionSummary) Validate() error {
	rebuilt, err := NewOmissionSummary(s.reason, s.count)
	if err != nil || rebuilt != s {
		return ErrInvalidSet
	}
	return nil
}

// Set is a content-addressed snapshot of diagnostics and optional verification coverage for one review run.
type Set struct {
	identity, snapshotIdentity, headRevision, verifiedSetIdentity, sourceContextIdentity string
	scope                                                                                audit.ReviewScope
	findings                                                                             []Finding
	omissionSummaries                                                                    []OmissionSummary
	deterministicChecks                                                                  []DeterministicCheck
	schemaVersion                                                                        int
	candidateCount, rejectedCount, inconclusiveCount                                     uint16
	sourceAnalyzedCount, sourceSelectedCount, sourceOmittedCount                         uint32
}

// NewSet constructs the version 1 diagnostic contract for compatibility.
func NewSet(scope audit.ReviewScope, snapshotIdentity, headRevision, verifiedSetIdentity string, findings []Finding) (Set, error) {
	return newSet(scope, snapshotIdentity, headRevision, verifiedSetIdentity, 1, uint16(len(findings)), 0, 0, "", 0, 0, 0, nil, nil, findings)
}

// NewSetWithCoverage constructs the version 2 diagnostic contract with exact verification accounting.
func NewSetWithCoverage(scope audit.ReviewScope, snapshotIdentity, headRevision, verifiedSetIdentity string, candidateCount, rejectedCount, inconclusiveCount uint16, findings []Finding) (Set, error) {
	return newSet(scope, snapshotIdentity, headRevision, verifiedSetIdentity, 2, candidateCount, rejectedCount, inconclusiveCount, "", 0, 0, 0, nil, nil, findings)
}

// NewSetWithSourceCoverage constructs the version 3 diagnostic contract with verification and source-selection accounting.
func NewSetWithSourceCoverage(scope audit.ReviewScope, snapshotIdentity, headRevision, verifiedSetIdentity, sourceContextIdentity string, candidateCount, rejectedCount, inconclusiveCount uint16, sourceAnalyzedCount, sourceSelectedCount, sourceOmittedCount uint32, findings []Finding) (Set, error) {
	return newSet(scope, snapshotIdentity, headRevision, verifiedSetIdentity, 3, candidateCount, rejectedCount, inconclusiveCount, sourceContextIdentity, sourceAnalyzedCount, sourceSelectedCount, sourceOmittedCount, nil, nil, findings)
}

// NewSetWithOmissionReasons constructs version 4 with exact aggregate omission accounting.
func NewSetWithOmissionReasons(scope audit.ReviewScope, snapshotIdentity, headRevision, verifiedSetIdentity, sourceContextIdentity string, candidateCount, rejectedCount, inconclusiveCount uint16, sourceAnalyzedCount, sourceSelectedCount, sourceOmittedCount uint32, omissionSummaries []OmissionSummary, findings []Finding) (Set, error) {
	return newSet(scope, snapshotIdentity, headRevision, verifiedSetIdentity, 4, candidateCount, rejectedCount, inconclusiveCount, sourceContextIdentity, sourceAnalyzedCount, sourceSelectedCount, sourceOmittedCount, omissionSummaries, nil, findings)
}

// NewSetWithDeterministicChecks constructs version 5 with one exact content-free check.
func NewSetWithDeterministicChecks(scope audit.ReviewScope, snapshotIdentity, headRevision, verifiedSetIdentity, sourceContextIdentity string, candidateCount, rejectedCount, inconclusiveCount uint16, sourceAnalyzedCount, sourceSelectedCount, sourceOmittedCount uint32, omissionSummaries []OmissionSummary, deterministicChecks []DeterministicCheck, findings []Finding) (Set, error) {
	return newSet(scope, snapshotIdentity, headRevision, verifiedSetIdentity, 5, candidateCount, rejectedCount, inconclusiveCount, sourceContextIdentity, sourceAnalyzedCount, sourceSelectedCount, sourceOmittedCount, omissionSummaries, deterministicChecks, findings)
}

func newSet(scope audit.ReviewScope, snapshotIdentity, headRevision, verifiedSetIdentity string, schemaVersion int, candidateCount, rejectedCount, inconclusiveCount uint16, sourceContextIdentity string, sourceAnalyzedCount, sourceSelectedCount, sourceOmittedCount uint32, omissionSummaries []OmissionSummary, deterministicChecks []DeterministicCheck, findings []Finding) (Set, error) {
	verifiedCount := uint16(len(findings))
	totalCount := uint32(verifiedCount) + uint32(rejectedCount) + uint32(inconclusiveCount)
	validCandidateCoverage := candidateCount <= maxDiagnostics && totalCount == uint32(candidateCount)
	validSourceCoverage := sourceAnalyzedCount > 0 && sourceAnalyzedCount <= maxDiagnosticSourceCount && sourceSelectedCount > 0 && sourceSelectedCount <= maxDiagnosticSelectedCount && sourceOmittedCount <= maxDiagnosticSourceCount && uint64(sourceSelectedCount)+uint64(sourceOmittedCount) == uint64(sourceAnalyzedCount)
	canonicalOmissions := append([]OmissionSummary(nil), omissionSummaries...)
	sort.Slice(canonicalOmissions, func(i, j int) bool {
		return canonicalOmissions[i].Reason().String() < canonicalOmissions[j].Reason().String()
	})
	omissionTotal := uint64(0)
	validOmissions := len(canonicalOmissions) <= 6
	for index, summary := range canonicalOmissions {
		if summary.Validate() != nil || index > 0 && canonicalOmissions[index-1].Reason() == summary.Reason() {
			validOmissions = false
		}
		omissionTotal += uint64(summary.Count())
	}
	validOmissions = validOmissions && omissionTotal == uint64(sourceOmittedCount) && (sourceOmittedCount == 0) == (len(canonicalOmissions) == 0)
	canonicalChecks := append([]DeterministicCheck(nil), deterministicChecks...)
	validChecks := len(canonicalChecks) == 1 && canonicalChecks[0].Validate() == nil
	validCoverage := schemaVersion == 1 && candidateCount == verifiedCount && rejectedCount == 0 && inconclusiveCount == 0 && sourceContextIdentity == "" && sourceAnalyzedCount == 0 && sourceSelectedCount == 0 && sourceOmittedCount == 0 && len(canonicalOmissions) == 0 && len(canonicalChecks) == 0 ||
		schemaVersion == 2 && validCandidateCoverage && sourceContextIdentity == "" && sourceAnalyzedCount == 0 && sourceSelectedCount == 0 && sourceOmittedCount == 0 && len(canonicalOmissions) == 0 && len(canonicalChecks) == 0 ||
		schemaVersion == 3 && validCandidateCoverage && validDigest(sourceContextIdentity) && validSourceCoverage && len(canonicalOmissions) == 0 && len(canonicalChecks) == 0 ||
		schemaVersion == 4 && validCandidateCoverage && validDigest(sourceContextIdentity) && validSourceCoverage && validOmissions && len(canonicalChecks) == 0 ||
		schemaVersion == 5 && validCandidateCoverage && validDigest(sourceContextIdentity) && validSourceCoverage && validOmissions && validChecks
	if scope.Validate() != nil || !validDigest(snapshotIdentity) || !validRevision(headRevision) || !validDigest(verifiedSetIdentity) || len(findings) > maxDiagnostics || !validCoverage {
		return Set{}, ErrInvalidSet
	}
	canonical := append([]Finding(nil), findings...)
	sort.Slice(canonical, func(i, j int) bool { return findingLess(canonical[i], canonical[j]) })
	for index, finding := range canonical {
		if finding.Validate() != nil || index > 0 && canonical[index-1].Identity() == finding.Identity() {
			return Set{}, ErrInvalidSet
		}
	}
	set := Set{scope: scope, snapshotIdentity: snapshotIdentity, headRevision: headRevision, verifiedSetIdentity: verifiedSetIdentity, findings: canonical, schemaVersion: schemaVersion, candidateCount: candidateCount, rejectedCount: rejectedCount, inconclusiveCount: inconclusiveCount, sourceAnalyzedCount: sourceAnalyzedCount, sourceSelectedCount: sourceSelectedCount, sourceContextIdentity: sourceContextIdentity, sourceOmittedCount: sourceOmittedCount, omissionSummaries: canonicalOmissions, deterministicChecks: canonicalChecks}
	set.identity = deriveSetIdentity(set)
	return set, nil
}
func (s Set) Identity() string                    { return s.identity }
func (s Set) Scope() audit.ReviewScope            { return s.scope }
func (s Set) SnapshotIdentity() string            { return s.snapshotIdentity }
func (s Set) HeadRevision() string                { return s.headRevision }
func (s Set) VerifiedSetIdentity() string         { return s.verifiedSetIdentity }
func (s Set) SchemaVersion() int                  { return s.schemaVersion }
func (s Set) CandidateCount() uint16              { return s.candidateCount }
func (s Set) VerifiedCount() uint16               { return uint16(len(s.findings)) }
func (s Set) RejectedCount() uint16               { return s.rejectedCount }
func (s Set) InconclusiveCount() uint16           { return s.inconclusiveCount }
func (s Set) VerificationContextIdentity() string { return s.sourceContextIdentity }
func (s Set) SourceAnalyzedCount() uint32         { return s.sourceAnalyzedCount }
func (s Set) SourceSelectedCount() uint32         { return s.sourceSelectedCount }
func (s Set) SourceOmittedCount() uint32          { return s.sourceOmittedCount }
func (s Set) OmissionSummaries() []OmissionSummary {
	return append([]OmissionSummary(nil), s.omissionSummaries...)
}
func (s Set) DeterministicChecks() []DeterministicCheck {
	return append([]DeterministicCheck(nil), s.deterministicChecks...)
}
func (s Set) Findings() []Finding { return append([]Finding(nil), s.findings...) }
func (s Set) Validate() error {
	var rebuilt Set
	var err error
	if s.schemaVersion == 1 {
		rebuilt, err = NewSet(s.scope, s.snapshotIdentity, s.headRevision, s.verifiedSetIdentity, s.findings)
	} else if s.schemaVersion == 2 {
		rebuilt, err = NewSetWithCoverage(s.scope, s.snapshotIdentity, s.headRevision, s.verifiedSetIdentity, s.candidateCount, s.rejectedCount, s.inconclusiveCount, s.findings)
	} else if s.schemaVersion == 3 {
		rebuilt, err = NewSetWithSourceCoverage(s.scope, s.snapshotIdentity, s.headRevision, s.verifiedSetIdentity, s.sourceContextIdentity, s.candidateCount, s.rejectedCount, s.inconclusiveCount, s.sourceAnalyzedCount, s.sourceSelectedCount, s.sourceOmittedCount, s.findings)
	} else if s.schemaVersion == 4 {
		rebuilt, err = NewSetWithOmissionReasons(s.scope, s.snapshotIdentity, s.headRevision, s.verifiedSetIdentity, s.sourceContextIdentity, s.candidateCount, s.rejectedCount, s.inconclusiveCount, s.sourceAnalyzedCount, s.sourceSelectedCount, s.sourceOmittedCount, s.omissionSummaries, s.findings)
	} else if s.schemaVersion == 5 {
		rebuilt, err = NewSetWithDeterministicChecks(s.scope, s.snapshotIdentity, s.headRevision, s.verifiedSetIdentity, s.sourceContextIdentity, s.candidateCount, s.rejectedCount, s.inconclusiveCount, s.sourceAnalyzedCount, s.sourceSelectedCount, s.sourceOmittedCount, s.omissionSummaries, s.deterministicChecks, s.findings)
	} else {
		return ErrInvalidSet
	}
	if err != nil {
		return err
	}
	if rebuilt.identity != s.identity || rebuilt.candidateCount != s.candidateCount || rebuilt.rejectedCount != s.rejectedCount || rebuilt.inconclusiveCount != s.inconclusiveCount || rebuilt.sourceContextIdentity != s.sourceContextIdentity || rebuilt.sourceAnalyzedCount != s.sourceAnalyzedCount || rebuilt.sourceSelectedCount != s.sourceSelectedCount || rebuilt.sourceOmittedCount != s.sourceOmittedCount {
		return ErrInvalidSetIdentity
	}
	if len(rebuilt.omissionSummaries) != len(s.omissionSummaries) {
		return ErrInvalidSetIdentity
	}
	for index := range rebuilt.omissionSummaries {
		if rebuilt.omissionSummaries[index] != s.omissionSummaries[index] {
			return ErrInvalidSetIdentity
		}
	}
	if len(rebuilt.deterministicChecks) != len(s.deterministicChecks) {
		return ErrInvalidSetIdentity
	}
	for index := range rebuilt.deterministicChecks {
		if rebuilt.deterministicChecks[index] != s.deterministicChecks[index] {
			return ErrInvalidSetIdentity
		}
	}
	for index := range rebuilt.findings {
		if rebuilt.findings[index].Identity() != s.findings[index].Identity() {
			return ErrInvalidSet
		}
	}
	return nil
}
func (s Set) String() string   { return "review diagnostic set" }
func (s Set) GoString() string { return "diagnostics.Set{<redacted>}" }

type findingRecord struct {
	Identity       string   `json:"identity"`
	SourceIdentity string   `json:"source_identity"`
	Fingerprint    string   `json:"fingerprint"`
	Title          string   `json:"title"`
	Message        string   `json:"message"`
	Severity       string   `json:"severity"`
	Path           string   `json:"path"`
	StartLine      uint32   `json:"start_line"`
	EndLine        uint32   `json:"end_line"`
	EvidenceIDs    []string `json:"evidence_ids"`
}
type setRecord struct {
	Contract            string          `json:"contract"`
	SchemaVersion       int             `json:"schema_version"`
	Identity            string          `json:"identity"`
	TenantID            string          `json:"tenant_id"`
	RepositoryID        string          `json:"repository_id"`
	ReviewRunID         string          `json:"review_run_id"`
	SnapshotIdentity    string          `json:"snapshot_identity"`
	HeadRevision        string          `json:"head_revision"`
	VerifiedSetIdentity string          `json:"verified_set_identity"`
	Findings            []findingRecord `json:"findings"`
}
type coverageRecord struct {
	CandidateCount    uint16 `json:"candidate_count"`
	VerifiedCount     uint16 `json:"verified_count"`
	RejectedCount     uint16 `json:"rejected_count"`
	InconclusiveCount uint16 `json:"inconclusive_count"`
}
type setRecordV2 struct {
	Contract            string          `json:"contract"`
	SchemaVersion       int             `json:"schema_version"`
	Identity            string          `json:"identity"`
	TenantID            string          `json:"tenant_id"`
	RepositoryID        string          `json:"repository_id"`
	ReviewRunID         string          `json:"review_run_id"`
	SnapshotIdentity    string          `json:"snapshot_identity"`
	HeadRevision        string          `json:"head_revision"`
	VerifiedSetIdentity string          `json:"verified_set_identity"`
	Coverage            coverageRecord  `json:"coverage"`
	Findings            []findingRecord `json:"findings"`
}
type sourceCoverageRecord struct {
	VerificationContextIdentity string `json:"verification_context_identity"`
	AnalyzedCount               uint32 `json:"analyzed_count"`
	SelectedCount               uint32 `json:"selected_count"`
	OmittedCount                uint32 `json:"omitted_count"`
}
type setRecordV3 struct {
	Contract            string               `json:"contract"`
	SchemaVersion       int                  `json:"schema_version"`
	Identity            string               `json:"identity"`
	TenantID            string               `json:"tenant_id"`
	RepositoryID        string               `json:"repository_id"`
	ReviewRunID         string               `json:"review_run_id"`
	SnapshotIdentity    string               `json:"snapshot_identity"`
	HeadRevision        string               `json:"head_revision"`
	VerifiedSetIdentity string               `json:"verified_set_identity"`
	Coverage            coverageRecord       `json:"coverage"`
	SourceCoverage      sourceCoverageRecord `json:"source_coverage"`
	Findings            []findingRecord      `json:"findings"`
}
type omissionSummaryRecord struct {
	Reason string `json:"reason"`
	Count  uint32 `json:"count"`
}
type sourceCoverageRecordV4 struct {
	VerificationContextIdentity string                  `json:"verification_context_identity"`
	AnalyzedCount               uint32                  `json:"analyzed_count"`
	SelectedCount               uint32                  `json:"selected_count"`
	OmittedCount                uint32                  `json:"omitted_count"`
	Omissions                   []omissionSummaryRecord `json:"omissions"`
}
type setRecordV4 struct {
	Contract            string                 `json:"contract"`
	SchemaVersion       int                    `json:"schema_version"`
	Identity            string                 `json:"identity"`
	TenantID            string                 `json:"tenant_id"`
	RepositoryID        string                 `json:"repository_id"`
	ReviewRunID         string                 `json:"review_run_id"`
	SnapshotIdentity    string                 `json:"snapshot_identity"`
	HeadRevision        string                 `json:"head_revision"`
	VerifiedSetIdentity string                 `json:"verified_set_identity"`
	Coverage            coverageRecord         `json:"coverage"`
	SourceCoverage      sourceCoverageRecordV4 `json:"source_coverage"`
	Findings            []findingRecord        `json:"findings"`
}
type deterministicCheckRecord struct {
	Identity               string `json:"identity"`
	SourceCheckIdentity    string `json:"source_check_identity"`
	AnalysisResultIdentity string `json:"analysis_result_identity"`
	ChangeIdentity         string `json:"change_identity"`
	Key                    string `json:"key"`
	RuleVersion            uint16 `json:"rule_version"`
	State                  string `json:"state"`
	ApplicableFiles        uint32 `json:"applicable_files"`
	ApplicableRanges       uint32 `json:"applicable_ranges"`
	CheckedFiles           uint32 `json:"checked_files"`
	CheckedRanges          uint32 `json:"checked_ranges"`
	Matches                uint32 `json:"matches"`
}
type setRecordV5 struct {
	Contract            string                     `json:"contract"`
	SchemaVersion       int                        `json:"schema_version"`
	Identity            string                     `json:"identity"`
	TenantID            string                     `json:"tenant_id"`
	RepositoryID        string                     `json:"repository_id"`
	ReviewRunID         string                     `json:"review_run_id"`
	SnapshotIdentity    string                     `json:"snapshot_identity"`
	HeadRevision        string                     `json:"head_revision"`
	VerifiedSetIdentity string                     `json:"verified_set_identity"`
	Coverage            coverageRecord             `json:"coverage"`
	SourceCoverage      sourceCoverageRecordV4     `json:"source_coverage"`
	Checks              []deterministicCheckRecord `json:"checks"`
	Findings            []findingRecord            `json:"findings"`
}

func EncodeSet(set Set) ([]byte, error) {
	if err := set.Validate(); err != nil {
		return nil, err
	}
	var encoded []byte
	var err error
	switch set.schemaVersion {
	case 1:
		encoded, err = json.Marshal(setToRecord(set))
	case 2:
		encoded, err = json.Marshal(setToRecordV2(set))
	case 3:
		encoded, err = json.Marshal(setToRecordV3(set))
	case 4:
		encoded, err = json.Marshal(setToRecordV4(set))
	case 5:
		encoded, err = json.Marshal(setToRecordV5(set))
	}
	if err != nil || len(encoded) > maxEncodedSetBytes {
		return nil, ErrInvalidSetEncoding
	}
	return encoded, nil
}
func ParseSet(encoded []byte) (Set, error) {
	if len(encoded) == 0 || len(encoded) > maxEncodedSetBytes {
		return Set{}, ErrInvalidSetEncoding
	}
	var header struct {
		SchemaVersion int `json:"schema_version"`
	}
	if err := json.Unmarshal(encoded, &header); err != nil {
		return Set{}, ErrInvalidSetEncoding
	}
	switch header.SchemaVersion {
	case 1:
		return parseSetV1(encoded)
	case 2:
		return parseSetV2(encoded)
	case 3:
		return parseSetV3(encoded)
	case 4:
		return parseSetV4(encoded)
	case 5:
		return parseSetV5(encoded)
	default:
		return Set{}, ErrInvalidSetEncoding
	}
}
func parseSetV1(encoded []byte) (Set, error) {
	var record setRecord
	if err := decodeCanonicalSetRecord(encoded, &record); err != nil || record.Contract != "open-trestle/review-diagnostic-set" || record.SchemaVersion != 1 {
		return Set{}, ErrInvalidSetEncoding
	}
	scope, findings, err := parseSetContents(record.TenantID, record.RepositoryID, record.ReviewRunID, record.Findings)
	if err != nil {
		return Set{}, err
	}
	set, err := NewSet(scope, record.SnapshotIdentity, record.HeadRevision, record.VerifiedSetIdentity, findings)
	if err != nil || set.identity != record.Identity {
		return Set{}, ErrInvalidSetIdentity
	}
	return verifyParsedSetEncoding(set, encoded)
}
func parseSetV2(encoded []byte) (Set, error) {
	var record setRecordV2
	if err := decodeCanonicalSetRecord(encoded, &record); err != nil || record.Contract != "open-trestle/review-diagnostic-set" || record.SchemaVersion != 2 {
		return Set{}, ErrInvalidSetEncoding
	}
	scope, findings, err := parseSetContents(record.TenantID, record.RepositoryID, record.ReviewRunID, record.Findings)
	if err != nil {
		return Set{}, err
	}
	if record.Coverage.VerifiedCount != uint16(len(findings)) {
		return Set{}, ErrInvalidSet
	}
	set, err := NewSetWithCoverage(scope, record.SnapshotIdentity, record.HeadRevision, record.VerifiedSetIdentity, record.Coverage.CandidateCount, record.Coverage.RejectedCount, record.Coverage.InconclusiveCount, findings)
	if err != nil || set.identity != record.Identity {
		return Set{}, ErrInvalidSetIdentity
	}
	return verifyParsedSetEncoding(set, encoded)
}
func parseSetV3(encoded []byte) (Set, error) {
	var record setRecordV3
	if err := decodeCanonicalSetRecord(encoded, &record); err != nil || record.Contract != "open-trestle/review-diagnostic-set" || record.SchemaVersion != 3 {
		return Set{}, ErrInvalidSetEncoding
	}
	scope, findings, err := parseSetContents(record.TenantID, record.RepositoryID, record.ReviewRunID, record.Findings)
	if err != nil {
		return Set{}, err
	}
	if record.Coverage.VerifiedCount != uint16(len(findings)) {
		return Set{}, ErrInvalidSet
	}
	set, err := NewSetWithSourceCoverage(scope, record.SnapshotIdentity, record.HeadRevision, record.VerifiedSetIdentity, record.SourceCoverage.VerificationContextIdentity, record.Coverage.CandidateCount, record.Coverage.RejectedCount, record.Coverage.InconclusiveCount, record.SourceCoverage.AnalyzedCount, record.SourceCoverage.SelectedCount, record.SourceCoverage.OmittedCount, findings)
	if err != nil || set.identity != record.Identity {
		return Set{}, ErrInvalidSetIdentity
	}
	return verifyParsedSetEncoding(set, encoded)
}

func parseSetV4(encoded []byte) (Set, error) {
	var record setRecordV4
	if err := decodeCanonicalSetRecord(encoded, &record); err != nil || record.Contract != "open-trestle/review-diagnostic-set" || record.SchemaVersion != 4 || record.Coverage.VerifiedCount != uint16(len(record.Findings)) {
		return Set{}, ErrInvalidSetEncoding
	}
	scope, findings, err := parseSetContents(record.TenantID, record.RepositoryID, record.ReviewRunID, record.Findings)
	if err != nil {
		return Set{}, err
	}
	summaries := make([]OmissionSummary, len(record.SourceCoverage.Omissions))
	for index, value := range record.SourceCoverage.Omissions {
		reason, reasonErr := parseOmissionReason(value.Reason)
		if reasonErr != nil {
			return Set{}, reasonErr
		}
		summaries[index], err = NewOmissionSummary(reason, value.Count)
		if err != nil {
			return Set{}, err
		}
	}
	set, err := NewSetWithOmissionReasons(scope, record.SnapshotIdentity, record.HeadRevision, record.VerifiedSetIdentity, record.SourceCoverage.VerificationContextIdentity, record.Coverage.CandidateCount, record.Coverage.RejectedCount, record.Coverage.InconclusiveCount, record.SourceCoverage.AnalyzedCount, record.SourceCoverage.SelectedCount, record.SourceCoverage.OmittedCount, summaries, findings)
	if err != nil || set.identity != record.Identity {
		return Set{}, ErrInvalidSetIdentity
	}
	return verifyParsedSetEncoding(set, encoded)
}

func parseSetV5(encoded []byte) (Set, error) {
	var record setRecordV5
	if err := decodeCanonicalSetRecord(encoded, &record); err != nil || record.Contract != "open-trestle/review-diagnostic-set" || record.SchemaVersion != 5 || record.Coverage.VerifiedCount != uint16(len(record.Findings)) || len(record.Checks) != 1 {
		return Set{}, ErrInvalidSetEncoding
	}
	scope, findings, err := parseSetContents(record.TenantID, record.RepositoryID, record.ReviewRunID, record.Findings)
	if err != nil {
		return Set{}, err
	}
	summaries := make([]OmissionSummary, len(record.SourceCoverage.Omissions))
	for index, value := range record.SourceCoverage.Omissions {
		reason, reasonErr := parseOmissionReason(value.Reason)
		if reasonErr != nil {
			return Set{}, reasonErr
		}
		summaries[index], err = NewOmissionSummary(reason, value.Count)
		if err != nil {
			return Set{}, err
		}
	}
	checks := make([]DeterministicCheck, len(record.Checks))
	for index, value := range record.Checks {
		state, stateErr := parseDeterministicCheckState(value.State)
		if stateErr != nil || value.Key != deterministicCheckKey || value.RuleVersion != deterministicCheckRuleVersion {
			return Set{}, ErrInvalidSet
		}
		checks[index], err = NewDeterministicCheck(value.SourceCheckIdentity, value.AnalysisResultIdentity, value.ChangeIdentity, state, value.ApplicableFiles, value.ApplicableRanges, value.CheckedFiles, value.CheckedRanges, value.Matches)
		if err != nil || checks[index].Identity() != value.Identity {
			return Set{}, ErrInvalidSetIdentity
		}
	}
	set, err := NewSetWithDeterministicChecks(scope, record.SnapshotIdentity, record.HeadRevision, record.VerifiedSetIdentity, record.SourceCoverage.VerificationContextIdentity, record.Coverage.CandidateCount, record.Coverage.RejectedCount, record.Coverage.InconclusiveCount, record.SourceCoverage.AnalyzedCount, record.SourceCoverage.SelectedCount, record.SourceCoverage.OmittedCount, summaries, checks, findings)
	if err != nil || set.identity != record.Identity {
		return Set{}, ErrInvalidSetIdentity
	}
	return verifyParsedSetEncoding(set, encoded)
}

func decodeCanonicalSetRecord(encoded []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return ErrInvalidSetEncoding
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return ErrInvalidSetEncoding
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return ErrInvalidSetEncoding
	}
	return nil
}
func parseSetContents(tenantID, repositoryID, reviewRunID string, records []findingRecord) (audit.ReviewScope, []Finding, error) {
	scope, err := audit.NewReviewScope(tenantID, repositoryID, reviewRunID)
	if err != nil {
		return audit.ReviewScope{}, nil, ErrInvalidSetEncoding
	}
	findings := make([]Finding, len(records))
	for index, value := range records {
		severity, parseErr := parseSeverity(value.Severity)
		if parseErr != nil {
			return audit.ReviewScope{}, nil, parseErr
		}
		finding, createErr := NewFinding(value.SourceIdentity, value.Fingerprint, value.Title, value.Message, severity, value.Path, value.StartLine, value.EndLine, value.EvidenceIDs)
		if createErr != nil {
			return audit.ReviewScope{}, nil, createErr
		}
		finding.identity = value.Identity
		findings[index] = finding
	}
	return scope, findings, nil
}
func verifyParsedSetEncoding(set Set, encoded []byte) (Set, error) {
	reencoded, err := EncodeSet(set)
	if err != nil || !bytes.Equal(reencoded, encoded) {
		return Set{}, ErrInvalidSetEncoding
	}
	return set, nil
}
func setToFindingRecords(set Set) []findingRecord {
	findings := make([]findingRecord, len(set.findings))
	for index, value := range set.findings {
		findings[index] = findingRecord{
			Identity: value.identity, SourceIdentity: value.sourceIdentity, Fingerprint: value.fingerprint,
			Title: value.title, Message: value.message, Severity: value.severity.String(), Path: value.path,
			StartLine: value.startLine, EndLine: value.endLine, EvidenceIDs: value.EvidenceIDs(),
		}
	}
	return findings
}
func setToRecord(set Set) setRecord {
	return setRecord{
		Contract: "open-trestle/review-diagnostic-set", SchemaVersion: 1,
		Identity: set.identity, TenantID: set.scope.TenantID(), RepositoryID: set.scope.RepositoryID(),
		ReviewRunID: set.scope.ReviewRunID(), SnapshotIdentity: set.snapshotIdentity,
		HeadRevision: set.headRevision, VerifiedSetIdentity: set.verifiedSetIdentity, Findings: setToFindingRecords(set),
	}
}
func setToRecordV2(set Set) setRecordV2 {
	return setRecordV2{
		Contract: "open-trestle/review-diagnostic-set", SchemaVersion: 2,
		Identity: set.identity, TenantID: set.scope.TenantID(), RepositoryID: set.scope.RepositoryID(),
		ReviewRunID: set.scope.ReviewRunID(), SnapshotIdentity: set.snapshotIdentity,
		HeadRevision: set.headRevision, VerifiedSetIdentity: set.verifiedSetIdentity,
		Coverage: coverageRecord{CandidateCount: set.candidateCount, VerifiedCount: set.VerifiedCount(), RejectedCount: set.rejectedCount, InconclusiveCount: set.inconclusiveCount},
		Findings: setToFindingRecords(set),
	}
}
func setToRecordV3(set Set) setRecordV3 {
	return setRecordV3{
		Contract: "open-trestle/review-diagnostic-set", SchemaVersion: 3,
		Identity: set.identity, TenantID: set.scope.TenantID(), RepositoryID: set.scope.RepositoryID(), ReviewRunID: set.scope.ReviewRunID(),
		SnapshotIdentity: set.snapshotIdentity, HeadRevision: set.headRevision, VerifiedSetIdentity: set.verifiedSetIdentity,
		Coverage:       coverageRecord{CandidateCount: set.candidateCount, VerifiedCount: set.VerifiedCount(), RejectedCount: set.rejectedCount, InconclusiveCount: set.inconclusiveCount},
		SourceCoverage: sourceCoverageRecord{VerificationContextIdentity: set.sourceContextIdentity, AnalyzedCount: set.sourceAnalyzedCount, SelectedCount: set.sourceSelectedCount, OmittedCount: set.sourceOmittedCount},
		Findings:       setToFindingRecords(set),
	}
}

func setToRecordV4(set Set) setRecordV4 {
	summaries := make([]omissionSummaryRecord, len(set.omissionSummaries))
	for index, summary := range set.omissionSummaries {
		summaries[index] = omissionSummaryRecord{Reason: summary.Reason().String(), Count: summary.Count()}
	}
	return setRecordV4{
		Contract: "open-trestle/review-diagnostic-set", SchemaVersion: 4,
		Identity: set.identity, TenantID: set.scope.TenantID(), RepositoryID: set.scope.RepositoryID(), ReviewRunID: set.scope.ReviewRunID(),
		SnapshotIdentity: set.snapshotIdentity, HeadRevision: set.headRevision, VerifiedSetIdentity: set.verifiedSetIdentity,
		Coverage:       coverageRecord{CandidateCount: set.candidateCount, VerifiedCount: set.VerifiedCount(), RejectedCount: set.rejectedCount, InconclusiveCount: set.inconclusiveCount},
		SourceCoverage: sourceCoverageRecordV4{VerificationContextIdentity: set.sourceContextIdentity, AnalyzedCount: set.sourceAnalyzedCount, SelectedCount: set.sourceSelectedCount, OmittedCount: set.sourceOmittedCount, Omissions: summaries},
		Findings:       setToFindingRecords(set),
	}
}

func setToRecordV5(set Set) setRecordV5 {
	summaries := make([]omissionSummaryRecord, len(set.omissionSummaries))
	for index, summary := range set.omissionSummaries {
		summaries[index] = omissionSummaryRecord{Reason: summary.Reason().String(), Count: summary.Count()}
	}
	checks := make([]deterministicCheckRecord, len(set.deterministicChecks))
	for index, check := range set.deterministicChecks {
		checks[index] = deterministicCheckRecord{Identity: check.Identity(), SourceCheckIdentity: check.SourceCheckIdentity(), AnalysisResultIdentity: check.AnalysisResultIdentity(), ChangeIdentity: check.ChangeIdentity(), Key: check.Key(), RuleVersion: check.RuleVersion(), State: check.State().String(), ApplicableFiles: check.ApplicableFiles(), ApplicableRanges: check.ApplicableRanges(), CheckedFiles: check.CheckedFiles(), CheckedRanges: check.CheckedRanges(), Matches: check.MatchCount()}
	}
	return setRecordV5{
		Contract: "open-trestle/review-diagnostic-set", SchemaVersion: 5,
		Identity: set.identity, TenantID: set.scope.TenantID(), RepositoryID: set.scope.RepositoryID(), ReviewRunID: set.scope.ReviewRunID(),
		SnapshotIdentity: set.snapshotIdentity, HeadRevision: set.headRevision, VerifiedSetIdentity: set.verifiedSetIdentity,
		Coverage:       coverageRecord{CandidateCount: set.candidateCount, VerifiedCount: set.VerifiedCount(), RejectedCount: set.rejectedCount, InconclusiveCount: set.inconclusiveCount},
		SourceCoverage: sourceCoverageRecordV4{VerificationContextIdentity: set.sourceContextIdentity, AnalyzedCount: set.sourceAnalyzedCount, SelectedCount: set.sourceSelectedCount, OmittedCount: set.sourceOmittedCount, Omissions: summaries},
		Checks:         checks, Findings: setToFindingRecords(set),
	}
}

func deriveSetIdentity(set Set) string {
	if set.schemaVersion == 5 {
		record := setToRecordV5(set)
		record.Identity = ""
		return hashValue(record)
	}
	if set.schemaVersion == 4 {
		record := setToRecordV4(set)
		record.Identity = ""
		return hashValue(record)
	}
	if set.schemaVersion == 3 {
		record := setToRecordV3(set)
		record.Identity = ""
		return hashValue(record)
	}
	if set.schemaVersion == 2 {
		record := setToRecordV2(set)
		record.Identity = ""
		return hashValue(record)
	}
	record := setToRecord(set)
	record.Identity = ""
	return hashValue(record)
}
func findingLess(a, b Finding) bool {
	if a.path != b.path {
		return a.path < b.path
	}
	if a.startLine != b.startLine {
		return a.startLine < b.startLine
	}
	if a.endLine != b.endLine {
		return a.endLine < b.endLine
	}
	return a.fingerprint < b.fingerprint
}
func parseOmissionReason(value string) (OmissionReason, error) {
	for reason := OmissionAuthorization; reason <= OmissionSelectionLimit; reason++ {
		if reason.String() == value {
			return reason, nil
		}
	}
	return 0, ErrInvalidSet
}
func parseSeverity(value string) (Severity, error) {
	for severity := SeverityError; severity <= SeverityHint; severity++ {
		if severity.String() == value {
			return severity, nil
		}
	}
	return 0, ErrInvalidFinding
}
func validText(value string, limit int) bool {
	if len(value) == 0 || len(value) > limit || !utf8.ValidString(value) {
		return false
	}
	for _, candidate := range value {
		if !unicode.IsPrint(candidate) && candidate != '\n' && candidate != '\t' {
			return false
		}
	}
	return true
}
func validPath(value string) bool {
	validShape := len(value) > 0 && len(value) <= maxDiagnosticPathBytes && utf8.ValidString(value)
	validRelative := !path.IsAbs(value) && path.Clean(value) == value && value != "." && value != ".."
	return validShape && validRelative && !strings.HasPrefix(value, "../") && !strings.ContainsRune(value, '\\')
}
func validEvidenceID(value string) bool {
	if len(value) == 0 || len(value) > 128 || !utf8.ValidString(value) {
		return false
	}
	for index, candidate := range value {
		alphaNumeric := candidate >= 'a' && candidate <= 'z' || candidate >= '0' && candidate <= '9'
		separator := candidate == '-' || candidate == '_' || candidate == '.' || candidate == ':'
		if !alphaNumeric && !(separator && index > 0 && index < len(value)-1) {
			return false
		}
	}
	return true
}

func validRevision(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value && strings.Trim(value, "0") != ""
}
func validDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && strings.Trim(value, "0") != "" && hex.EncodeToString(decoded) == value
}
func hashValue(value any) string {
	encoded, _ := json.Marshal(value)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
func writeFormat(state fmt.State, verb rune, plain, syntax string) {
	value := plain
	if verb == 'q' {
		value = fmt.Sprintf("%q", plain)
	} else if verb == 'v' && state.Flag('#') {
		value = syntax
	}
	_, _ = state.Write([]byte(value))
}
