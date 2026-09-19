package evaluation

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/review"
)

const (
	staticDebugRuleKey     = "static_debug_output"
	staticDebugRuleVersion = uint16(1)
	maximumReportBytes     = 64 << 10
	maximumEvaluationCases = 256
	maximumCaseRanges      = 1024
)

// ErrInvalidStaticDebugEvaluation identifies malformed suite or report state.
var ErrInvalidStaticDebugEvaluation = errors.New("invalid static debug evaluation")

type staticDebugCaseStatus uint8

const (
	staticDebugCasePassed staticDebugCaseStatus = iota + 1
	staticDebugCaseFailed
)

func (s staticDebugCaseStatus) String() string {
	switch s {
	case staticDebugCasePassed:
		return "passed"
	case staticDebugCaseFailed:
		return "failed"
	default:
		return ""
	}
}

type staticDebugRange struct {
	startLine int
	endLine   int
}

type staticDebugCase struct {
	id             string
	path           string
	source         string
	selections     []staticDebugRange
	expectedRanges []staticDebugRange
}

// StaticDebugCaseResult records content-free exact-range counts for one built-in case.
type StaticDebugCaseResult struct {
	id                                              string
	status                                          staticDebugCaseStatus
	expectedCount, observedCount, truePositiveCount uint16
	falsePositiveCount, falseNegativeCount          uint16
}

func (r StaticDebugCaseResult) ID() string                 { return r.id }
func (r StaticDebugCaseResult) Status() string             { return r.status.String() }
func (r StaticDebugCaseResult) Passed() bool               { return r.status == staticDebugCasePassed }
func (r StaticDebugCaseResult) ExpectedCount() uint16      { return r.expectedCount }
func (r StaticDebugCaseResult) ObservedCount() uint16      { return r.observedCount }
func (r StaticDebugCaseResult) TruePositiveCount() uint16  { return r.truePositiveCount }
func (r StaticDebugCaseResult) FalsePositiveCount() uint16 { return r.falsePositiveCount }
func (r StaticDebugCaseResult) FalseNegativeCount() uint16 { return r.falseNegativeCount }

// StaticDebugReport is a content-free exact-range evaluation result.
type StaticDebugReport struct {
	identity, suiteIdentity, evaluatorIdentity                string
	caseCount, passedCount, failedCount                       uint16
	expectedMatchCount, observedMatchCount                    uint32
	truePositiveCount, falsePositiveCount, falseNegativeCount uint32
	precisionNumerator, precisionDenominator                  uint32
	recallNumerator, recallDenominator                        uint32
	cases                                                     []StaticDebugCaseResult
}

func (r StaticDebugReport) Identity() string           { return r.identity }
func (r StaticDebugReport) SuiteIdentity() string      { return r.suiteIdentity }
func (r StaticDebugReport) EvaluatorIdentity() string  { return r.evaluatorIdentity }
func (r StaticDebugReport) CaseCount() uint16          { return r.caseCount }
func (r StaticDebugReport) PassedCount() uint16        { return r.passedCount }
func (r StaticDebugReport) FailedCount() uint16        { return r.failedCount }
func (r StaticDebugReport) ExpectedMatchCount() uint32 { return r.expectedMatchCount }
func (r StaticDebugReport) ObservedMatchCount() uint32 { return r.observedMatchCount }
func (r StaticDebugReport) TruePositiveCount() uint32  { return r.truePositiveCount }
func (r StaticDebugReport) FalsePositiveCount() uint32 { return r.falsePositiveCount }
func (r StaticDebugReport) FalseNegativeCount() uint32 { return r.falseNegativeCount }
func (r StaticDebugReport) Precision() [2]uint32 {
	return [2]uint32{r.precisionNumerator, r.precisionDenominator}
}
func (r StaticDebugReport) Recall() [2]uint32 {
	return [2]uint32{r.recallNumerator, r.recallDenominator}
}
func (r StaticDebugReport) Cases() []StaticDebugCaseResult {
	return append([]StaticDebugCaseResult(nil), r.cases...)
}
func (r StaticDebugReport) Passed() bool { return r.Validate() == nil && r.failedCount == 0 }

type staticDebugDetector func([]byte, string, []evidence.SourceRange) ([]evidence.SourceRange, error)

// EvaluateStaticDebug runs the fixed versioned suite against the maintained detector.
func EvaluateStaticDebug() (StaticDebugReport, error) {
	return evaluateStaticDebugCases(builtInStaticDebugCases(), review.FindStaticDebugOutputRanges)
}

func evaluateStaticDebugCases(cases []staticDebugCase, detector staticDebugDetector) (StaticDebugReport, error) {
	if err := validateStaticDebugCases(cases); err != nil {
		return StaticDebugReport{}, err
	}
	if detector == nil {
		return StaticDebugReport{}, ErrInvalidStaticDebugEvaluation
	}
	report := StaticDebugReport{
		suiteIdentity: deriveStaticDebugSuiteIdentity(cases), evaluatorIdentity: deriveStaticDebugEvaluatorIdentity(),
		caseCount: uint16(len(cases)), cases: make([]StaticDebugCaseResult, len(cases)),
	}
	for index, testCase := range cases {
		selections := make([]evidence.SourceRange, len(testCase.selections))
		for rangeIndex, value := range testCase.selections {
			selection, err := evidence.NewSourceRange(testCase.path, value.startLine, value.endLine)
			if err != nil {
				return StaticDebugReport{}, ErrInvalidStaticDebugEvaluation
			}
			selections[rangeIndex] = selection
		}
		observed, err := detector([]byte(testCase.source), testCase.path, selections)
		if err != nil {
			return StaticDebugReport{}, ErrInvalidStaticDebugEvaluation
		}
		matched := exactRangeMatches(testCase.path, testCase.expectedRanges, observed)
		expected := len(testCase.expectedRanges)
		actual := len(observed)
		if expected > maximumCaseRanges || actual > maximumCaseRanges || matched > expected || matched > actual {
			return StaticDebugReport{}, ErrInvalidStaticDebugEvaluation
		}
		result := StaticDebugCaseResult{
			id: testCase.id, expectedCount: uint16(expected), observedCount: uint16(actual), truePositiveCount: uint16(matched),
			falsePositiveCount: uint16(actual - matched), falseNegativeCount: uint16(expected - matched),
		}
		if result.falsePositiveCount == 0 && result.falseNegativeCount == 0 {
			result.status = staticDebugCasePassed
			report.passedCount++
		} else {
			result.status = staticDebugCaseFailed
			report.failedCount++
		}
		report.expectedMatchCount += uint32(result.expectedCount)
		report.observedMatchCount += uint32(result.observedCount)
		report.truePositiveCount += uint32(result.truePositiveCount)
		report.falsePositiveCount += uint32(result.falsePositiveCount)
		report.falseNegativeCount += uint32(result.falseNegativeCount)
		report.cases[index] = result
	}
	report.precisionNumerator = report.truePositiveCount
	report.precisionDenominator = report.truePositiveCount + report.falsePositiveCount
	report.recallNumerator = report.truePositiveCount
	report.recallDenominator = report.truePositiveCount + report.falseNegativeCount
	report.identity = deriveStaticDebugReportIdentity(report)
	if report.Validate() != nil {
		return StaticDebugReport{}, ErrInvalidStaticDebugEvaluation
	}
	return report, nil
}

func exactRangeMatches(expectedPath string, expected []staticDebugRange, observed []evidence.SourceRange) int {
	matched := 0
	left, right := 0, 0
	for left < len(expected) && right < len(observed) {
		if observed[right].Path() != expectedPath {
			right++
			continue
		}
		comparison := compareStaticDebugRange(expected[left], observed[right])
		switch {
		case comparison < 0:
			left++
		case comparison > 0:
			right++
		default:
			matched++
			left++
			right++
		}
	}
	return matched
}

func compareStaticDebugRange(expected staticDebugRange, observed evidence.SourceRange) int {
	if expected.startLine < observed.StartLine() || expected.startLine == observed.StartLine() && expected.endLine < observed.EndLine() {
		return -1
	}
	if expected.startLine > observed.StartLine() || expected.startLine == observed.StartLine() && expected.endLine > observed.EndLine() {
		return 1
	}
	return 0
}

func validateStaticDebugCases(cases []staticDebugCase) error {
	if len(cases) == 0 || len(cases) > maximumEvaluationCases {
		return ErrInvalidStaticDebugEvaluation
	}
	previousID := ""
	positive, negative := false, false
	for _, testCase := range cases {
		if !validCaseID(testCase.id) || testCase.id <= previousID || !strings.HasSuffix(testCase.path, ".go") || len(testCase.source) == 0 || len(testCase.source) > 1<<20 || len(testCase.selections) == 0 || len(testCase.selections) > maximumCaseRanges || len(testCase.expectedRanges) > maximumCaseRanges {
			return ErrInvalidStaticDebugEvaluation
		}
		lineCount := physicalLineCount(testCase.source)
		if !validRanges(testCase.selections, lineCount, false) || !validRanges(testCase.expectedRanges, lineCount, true) {
			return ErrInvalidStaticDebugEvaluation
		}
		for _, expected := range testCase.expectedRanges {
			overlaps := false
			for _, selection := range testCase.selections {
				overlaps = overlaps || expected.startLine <= selection.endLine && expected.endLine >= selection.startLine
			}
			if !overlaps {
				return ErrInvalidStaticDebugEvaluation
			}
		}
		positive = positive || len(testCase.expectedRanges) > 0
		negative = negative || len(testCase.expectedRanges) == 0
		previousID = testCase.id
	}
	if !positive || !negative {
		return ErrInvalidStaticDebugEvaluation
	}
	return nil
}

func validRanges(ranges []staticDebugRange, lineCount int, allowEmpty bool) bool {
	if !allowEmpty && len(ranges) == 0 {
		return false
	}
	for index, value := range ranges {
		if value.startLine < 1 || value.endLine < value.startLine || value.endLine > lineCount || index > 0 && value.startLine <= ranges[index-1].endLine {
			return false
		}
	}
	return true
}

func physicalLineCount(source string) int {
	count := strings.Count(source, "\n")
	if !strings.HasSuffix(source, "\n") {
		count++
	}
	return count
}

func validCaseID(value string) bool {
	if len(value) == 0 || len(value) > 64 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, current := range []byte(value[1:]) {
		if current != '_' && current != '-' && current != '.' && (current < 'a' || current > 'z') && (current < '0' || current > '9') {
			return false
		}
	}
	return true
}

type staticDebugRangeWire struct {
	StartLine int `json:"start_line"`
	EndLine   int `json:"end_line"`
}
type staticDebugSuiteCaseWire struct {
	ID             string                 `json:"id"`
	Path           string                 `json:"path"`
	Source         string                 `json:"source"`
	Selections     []staticDebugRangeWire `json:"selections"`
	ExpectedRanges []staticDebugRangeWire `json:"expected_ranges"`
}

func deriveStaticDebugSuiteIdentity(cases []staticDebugCase) string {
	wire := struct {
		Contract      string                     `json:"contract"`
		SchemaVersion int                        `json:"schema_version"`
		Cases         []staticDebugSuiteCaseWire `json:"cases"`
	}{"open-trestle/static-debug-evaluation-suite", 1, make([]staticDebugSuiteCaseWire, len(cases))}
	for index, testCase := range cases {
		wire.Cases[index] = staticDebugSuiteCaseWire{ID: testCase.id, Path: testCase.path, Source: testCase.source, Selections: rangeWires(testCase.selections), ExpectedRanges: rangeWires(testCase.expectedRanges)}
	}
	encoded, _ := json.Marshal(wire)
	return digestEvaluation(encoded)
}

func rangeWires(ranges []staticDebugRange) []staticDebugRangeWire {
	result := make([]staticDebugRangeWire, len(ranges))
	for index, value := range ranges {
		result[index] = staticDebugRangeWire{value.startLine, value.endLine}
	}
	return result
}

func deriveStaticDebugEvaluatorIdentity() string {
	encoded, _ := json.Marshal(struct {
		Contract      string `json:"contract"`
		SchemaVersion int    `json:"schema_version"`
		RuleKey       string `json:"rule_key"`
		RuleVersion   uint16 `json:"rule_version"`
		MatchUnit     string `json:"match_unit"`
	}{"open-trestle/static-debug-evaluator", 1, staticDebugRuleKey, staticDebugRuleVersion, "exact_path_start_end_range"})
	return digestEvaluation(encoded)
}

type StaticDebugCaseResultWire struct {
	ID                 string `json:"id"`
	Status             string `json:"status"`
	ExpectedCount      uint16 `json:"expected_count"`
	ObservedCount      uint16 `json:"observed_count"`
	TruePositiveCount  uint16 `json:"true_positive_count"`
	FalsePositiveCount uint16 `json:"false_positive_count"`
	FalseNegativeCount uint16 `json:"false_negative_count"`
}
type staticDebugReportWire struct {
	Contract             string                      `json:"contract"`
	SchemaVersion        int                         `json:"schema_version"`
	Identity             string                      `json:"identity"`
	SuiteIdentity        string                      `json:"suite_identity"`
	EvaluatorIdentity    string                      `json:"evaluator_identity"`
	RuleKey              string                      `json:"rule_key"`
	RuleVersion          uint16                      `json:"rule_version"`
	CaseCount            uint16                      `json:"case_count"`
	PassedCount          uint16                      `json:"passed_count"`
	FailedCount          uint16                      `json:"failed_count"`
	ExpectedMatchCount   uint32                      `json:"expected_match_count"`
	ObservedMatchCount   uint32                      `json:"observed_match_count"`
	TruePositiveCount    uint32                      `json:"true_positive_count"`
	FalsePositiveCount   uint32                      `json:"false_positive_count"`
	FalseNegativeCount   uint32                      `json:"false_negative_count"`
	PrecisionNumerator   uint32                      `json:"precision_numerator"`
	PrecisionDenominator uint32                      `json:"precision_denominator"`
	RecallNumerator      uint32                      `json:"recall_numerator"`
	RecallDenominator    uint32                      `json:"recall_denominator"`
	Cases                []StaticDebugCaseResultWire `json:"cases"`
}

func reportWire(report StaticDebugReport) staticDebugReportWire {
	wire := staticDebugReportWire{
		Contract: "open-trestle/static-debug-evaluation-result", SchemaVersion: 1, Identity: report.identity,
		SuiteIdentity: report.suiteIdentity, EvaluatorIdentity: report.evaluatorIdentity, RuleKey: staticDebugRuleKey, RuleVersion: staticDebugRuleVersion,
		CaseCount: report.caseCount, PassedCount: report.passedCount, FailedCount: report.failedCount,
		ExpectedMatchCount: report.expectedMatchCount, ObservedMatchCount: report.observedMatchCount,
		TruePositiveCount: report.truePositiveCount, FalsePositiveCount: report.falsePositiveCount, FalseNegativeCount: report.falseNegativeCount,
		PrecisionNumerator: report.precisionNumerator, PrecisionDenominator: report.precisionDenominator,
		RecallNumerator: report.recallNumerator, RecallDenominator: report.recallDenominator,
		Cases: make([]StaticDebugCaseResultWire, len(report.cases)),
	}
	for index, result := range report.cases {
		wire.Cases[index] = StaticDebugCaseResultWire{result.id, result.status.String(), result.expectedCount, result.observedCount, result.truePositiveCount, result.falsePositiveCount, result.falseNegativeCount}
	}
	return wire
}

func deriveStaticDebugReportIdentity(report StaticDebugReport) string {
	wire := reportWire(report)
	wire.Identity = ""
	encoded, _ := json.Marshal(wire)
	return digestEvaluation(encoded)
}

func (r StaticDebugReport) Validate() error {
	suite := builtInStaticDebugCases()
	if !validDigest(r.identity) || r.suiteIdentity != deriveStaticDebugSuiteIdentity(suite) || r.evaluatorIdentity != deriveStaticDebugEvaluatorIdentity() || r.caseCount == 0 || r.caseCount > maximumEvaluationCases || int(r.caseCount) != len(r.cases) || len(r.cases) != len(suite) || r.passedCount+r.failedCount != r.caseCount || r.expectedMatchCount > maximumEvaluationCases*maximumCaseRanges || r.observedMatchCount > maximumEvaluationCases*maximumCaseRanges || r.truePositiveCount > maximumEvaluationCases*maximumCaseRanges || r.falsePositiveCount > maximumEvaluationCases*maximumCaseRanges || r.falseNegativeCount > maximumEvaluationCases*maximumCaseRanges || r.expectedMatchCount != r.truePositiveCount+r.falseNegativeCount || r.observedMatchCount != r.truePositiveCount+r.falsePositiveCount || r.precisionNumerator != r.truePositiveCount || r.precisionDenominator != r.truePositiveCount+r.falsePositiveCount || r.recallNumerator != r.truePositiveCount || r.recallDenominator != r.truePositiveCount+r.falseNegativeCount {
		return ErrInvalidStaticDebugEvaluation
	}
	var passed, failed uint16
	var expected, observed, truePositive, falsePositive, falseNegative uint32
	previous := ""
	for index, result := range r.cases {
		suiteCase := suite[index]
		if result.id != suiteCase.id || int(result.expectedCount) != len(suiteCase.expectedRanges) || !validCaseID(result.id) || result.id <= previous || result.status.String() == "" || result.expectedCount > maximumCaseRanges || result.observedCount > maximumCaseRanges || result.truePositiveCount > maximumCaseRanges || result.falsePositiveCount > maximumCaseRanges || result.falseNegativeCount > maximumCaseRanges || result.expectedCount != result.truePositiveCount+result.falseNegativeCount || result.observedCount != result.truePositiveCount+result.falsePositiveCount || result.status == staticDebugCasePassed != (result.falsePositiveCount == 0 && result.falseNegativeCount == 0) {
			return ErrInvalidStaticDebugEvaluation
		}
		if result.status == staticDebugCasePassed {
			passed++
		} else {
			failed++
		}
		expected += uint32(result.expectedCount)
		observed += uint32(result.observedCount)
		truePositive += uint32(result.truePositiveCount)
		falsePositive += uint32(result.falsePositiveCount)
		falseNegative += uint32(result.falseNegativeCount)
		previous = result.id
	}
	if passed != r.passedCount || failed != r.failedCount || expected != r.expectedMatchCount || observed != r.observedMatchCount || truePositive != r.truePositiveCount || falsePositive != r.falsePositiveCount || falseNegative != r.falseNegativeCount || r.identity != deriveStaticDebugReportIdentity(r) {
		return ErrInvalidStaticDebugEvaluation
	}
	return nil
}

// EncodeStaticDebugReport returns the canonical report JSON without transport framing.
func EncodeStaticDebugReport(report StaticDebugReport) ([]byte, error) {
	if report.Validate() != nil {
		return nil, ErrInvalidStaticDebugEvaluation
	}
	encoded, err := json.Marshal(reportWire(report))
	if err != nil || len(encoded) > maximumReportBytes {
		return nil, ErrInvalidStaticDebugEvaluation
	}
	return encoded, nil
}

// ParseStaticDebugReport accepts one canonical report for the known built-in suite.
func ParseStaticDebugReport(encoded []byte) (StaticDebugReport, error) {
	if len(encoded) == 0 || len(encoded) > maximumReportBytes {
		return StaticDebugReport{}, ErrInvalidStaticDebugEvaluation
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var wire staticDebugReportWire
	if decoder.Decode(&wire) != nil || decoder.Decode(&struct{}{}) != io.EOF || wire.Contract != "open-trestle/static-debug-evaluation-result" || wire.SchemaVersion != 1 || wire.RuleKey != staticDebugRuleKey || wire.RuleVersion != staticDebugRuleVersion {
		return StaticDebugReport{}, ErrInvalidStaticDebugEvaluation
	}
	canonical, _ := json.Marshal(wire)
	if !bytes.Equal(encoded, canonical) {
		return StaticDebugReport{}, ErrInvalidStaticDebugEvaluation
	}
	report := StaticDebugReport{
		identity: wire.Identity, suiteIdentity: wire.SuiteIdentity, evaluatorIdentity: wire.EvaluatorIdentity,
		caseCount: wire.CaseCount, passedCount: wire.PassedCount, failedCount: wire.FailedCount,
		expectedMatchCount: wire.ExpectedMatchCount, observedMatchCount: wire.ObservedMatchCount,
		truePositiveCount: wire.TruePositiveCount, falsePositiveCount: wire.FalsePositiveCount, falseNegativeCount: wire.FalseNegativeCount,
		precisionNumerator: wire.PrecisionNumerator, precisionDenominator: wire.PrecisionDenominator,
		recallNumerator: wire.RecallNumerator, recallDenominator: wire.RecallDenominator,
		cases: make([]StaticDebugCaseResult, len(wire.Cases)),
	}
	for index, value := range wire.Cases {
		status := staticDebugCaseStatus(0)
		for candidate := staticDebugCasePassed; candidate <= staticDebugCaseFailed; candidate++ {
			if candidate.String() == value.Status {
				status = candidate
			}
		}
		report.cases[index] = StaticDebugCaseResult{value.ID, status, value.ExpectedCount, value.ObservedCount, value.TruePositiveCount, value.FalsePositiveCount, value.FalseNegativeCount}
	}
	if report.Validate() != nil {
		return StaticDebugReport{}, ErrInvalidStaticDebugEvaluation
	}
	return report, nil
}

func digestEvaluation(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}
func validDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && hex.EncodeToString(decoded) == value && strings.Trim(value, "0") != ""
}

func builtInStaticDebugCases() []staticDebugCase {
	return []staticDebugCase{
		{id: "alias_import", path: "alias_import.go", source: "package fixture\n\nimport f \"fmt\"\n\nfunc run() { f.Println(\"debug\") }\n", selections: []staticDebugRange{{5, 5}}, expectedRanges: []staticDebugRange{{5, 5}}},
		{id: "comment_and_string", path: "comment_and_string.go", source: "package fixture\n\nvar _ = `fmt.Println(\"debug\")` // fmt.Println(\"debug\")\n", selections: []staticDebugRange{{3, 3}}},
		{id: "different_literal", path: "different_literal.go", source: "package fixture\n\nimport \"fmt\"\n\nfunc run() { fmt.Println(\"trace\") }\n", selections: []staticDebugRange{{5, 5}}},
		{id: "direct_call", path: "direct_call.go", source: "package fixture\n\nimport \"fmt\"\n\nfunc run() { fmt.Println(\"debug\") }\n", selections: []staticDebugRange{{5, 5}}, expectedRanges: []staticDebugRange{{5, 5}}},
		{id: "dot_import", path: "dot_import.go", source: "package fixture\n\nimport . \"fmt\"\n\nfunc run() { Println(\"debug\") }\n", selections: []staticDebugRange{{5, 5}}},
		{id: "multiline_call", path: "multiline_call.go", source: "package fixture\n\nimport \"fmt\"\n\nfunc run() {\n\tfmt.Println(\n\t\t\"debug\",\n\t)\n}\n", selections: []staticDebugRange{{6, 8}}, expectedRanges: []staticDebugRange{{6, 8}}},
		{id: "outside_selection", path: "outside_selection.go", source: "package fixture\n\nimport \"fmt\"\n\nfunc run() { fmt.Println(\"debug\") }\n", selections: []staticDebugRange{{3, 3}}},
		{id: "shadowed_fmt", path: "shadowed_fmt.go", source: "package fixture\n\ntype printer struct{}\nfunc (printer) Println(string) {}\nvar fmt printer\nfunc run() { fmt.Println(\"debug\") }\n", selections: []staticDebugRange{{6, 6}}},
	}
}
