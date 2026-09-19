package evaluation

import (
	"bytes"
	"os"
	"testing"

	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/review"
)

func TestEvaluateStaticDebugBuiltInSuite(t *testing.T) {
	if (StaticDebugReport{}).Passed() {
		t.Fatal("zero report passed")
	}
	report, err := EvaluateStaticDebug()
	if err != nil {
		t.Fatal(err)
	}
	if report.Validate() != nil || !report.Passed() || report.CaseCount() != 8 || report.PassedCount() != 8 || report.FailedCount() != 0 || report.ExpectedMatchCount() != 3 || report.ObservedMatchCount() != 3 || report.TruePositiveCount() != 3 || report.FalsePositiveCount() != 0 || report.FalseNegativeCount() != 0 || report.Precision() != [2]uint32{3, 3} || report.Recall() != [2]uint32{3, 3} {
		t.Fatalf("report=%#v", report)
	}
	if report.SuiteIdentity() != "f01adf2b13140ca6958d3d6f5fbce50e1bcf4503069e019e66ba68e24c515c84" || report.EvaluatorIdentity() != "41df5d0d0878b75954482e7bcfa67bdacbefb00a22300c3b61e768ff5914cc48" || report.Identity() != "87af89b956ad96762bdba67dd8be0d7f7f112cf758b7d985fc1d4f9e3bcc791e" {
		t.Fatalf("identities=%q %q %q", report.SuiteIdentity(), report.EvaluatorIdentity(), report.Identity())
	}
	wantCases := []string{"alias_import", "comment_and_string", "different_literal", "direct_call", "dot_import", "multiline_call", "outside_selection", "shadowed_fmt"}
	results := report.Cases()
	if len(results) != len(wantCases) {
		t.Fatalf("cases=%d", len(results))
	}
	for index, want := range wantCases {
		if results[index].ID() != want || !results[index].Passed() {
			t.Fatalf("case[%d]=%#v", index, results[index])
		}
	}
}

func TestEvaluateStaticDebugReportsDetectorMismatch(t *testing.T) {
	detector := func([]byte, string, []evidence.SourceRange) ([]evidence.SourceRange, error) { return nil, nil }
	report, err := evaluateStaticDebugCases(builtInStaticDebugCases(), detector)
	if err != nil || report.Validate() != nil || report.Passed() || report.PassedCount() != 5 || report.FailedCount() != 3 || report.ExpectedMatchCount() != 3 || report.ObservedMatchCount() != 0 || report.TruePositiveCount() != 0 || report.FalsePositiveCount() != 0 || report.FalseNegativeCount() != 3 || report.Precision() != [2]uint32{0, 0} || report.Recall() != [2]uint32{0, 3} {
		t.Fatalf("report=%#v err=%v", report, err)
	}
}

func TestEvaluateStaticDebugRejectsNilDetector(t *testing.T) {
	report, err := evaluateStaticDebugCases(builtInStaticDebugCases(), nil)
	if err != ErrInvalidStaticDebugEvaluation || report.Identity() != "" || report.CaseCount() != 0 || report.Cases() != nil {
		t.Fatalf("report=%#v err=%v", report, err)
	}
}

func TestEvaluateStaticDebugRequiresExactObservedPaths(t *testing.T) {
	detector := func(source []byte, sourcePath string, selections []evidence.SourceRange) ([]evidence.SourceRange, error) {
		ranges, err := review.FindStaticDebugOutputRanges(source, sourcePath, selections)
		if err != nil {
			return nil, err
		}
		for index, sourceRange := range ranges {
			ranges[index], err = evidence.NewSourceRange("wrong.go", sourceRange.StartLine(), sourceRange.EndLine())
			if err != nil {
				return nil, err
			}
		}
		return ranges, nil
	}
	report, err := evaluateStaticDebugCases(builtInStaticDebugCases(), detector)
	if err != nil || report.Validate() != nil || report.Passed() || report.PassedCount() != 5 || report.FailedCount() != 3 || report.ExpectedMatchCount() != 3 || report.ObservedMatchCount() != 3 || report.TruePositiveCount() != 0 || report.FalsePositiveCount() != 3 || report.FalseNegativeCount() != 3 {
		t.Fatalf("report=%#v err=%v", report, err)
	}
}

func TestStaticDebugEvaluationRejectsTampering(t *testing.T) {
	report, err := EvaluateStaticDebug()
	if err != nil {
		t.Fatal(err)
	}
	mutated := report
	mutated.truePositiveCount++
	if mutated.Validate() == nil {
		t.Fatal("tampered count accepted")
	}
	mutated = report
	mutated.identity = "0" + mutated.identity[1:]
	if mutated.Validate() == nil {
		t.Fatal("tampered identity accepted")
	}
	mutated = report
	mutated.suiteIdentity = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	mutated.identity = deriveStaticDebugReportIdentity(mutated)
	if mutated.Validate() == nil {
		t.Fatal("unknown suite accepted")
	}
	mutated = report
	mutated.cases = append([]StaticDebugCaseResult(nil), report.cases...)
	mutated.cases[0].id = "aaa"
	mutated.identity = deriveStaticDebugReportIdentity(mutated)
	unknownCaseAccepted := mutated.Validate() == nil
	mutated = report
	mutated.cases = append([]StaticDebugCaseResult(nil), report.cases...)
	mutated.cases[0].status = staticDebugCaseFailed
	mutated.cases[0].expectedCount++
	mutated.cases[0].falseNegativeCount++
	mutated.passedCount--
	mutated.failedCount++
	mutated.expectedMatchCount++
	mutated.falseNegativeCount++
	mutated.recallDenominator++
	mutated.identity = deriveStaticDebugReportIdentity(mutated)
	forgedExpectationAccepted := mutated.Validate() == nil
	if unknownCaseAccepted || forgedExpectationAccepted {
		t.Fatalf("suite-row tampering accepted: unknown_case=%t forged_expectation=%t", unknownCaseAccepted, forgedExpectationAccepted)
	}
	mutated = report
	mutated.cases = append([]StaticDebugCaseResult(nil), report.cases...)
	mutated.cases[0].status = staticDebugCaseFailed
	if mutated.Validate() == nil {
		t.Fatal("tampered case accepted")
	}
	mutated = report
	mutated.cases = append([]StaticDebugCaseResult(nil), report.cases...)
	mutated.cases[0] = StaticDebugCaseResult{id: mutated.cases[0].id, status: staticDebugCaseFailed, expectedCount: 1025, observedCount: 1, truePositiveCount: 1, falseNegativeCount: 1024}
	mutated.passedCount = 7
	mutated.failedCount = 1
	mutated.expectedMatchCount = 1027
	mutated.falseNegativeCount = 1024
	mutated.recallDenominator = 1027
	mutated.identity = deriveStaticDebugReportIdentity(mutated)
	if mutated.Validate() == nil {
		t.Fatal("over-limit case accepted")
	}
}

func TestEncodeStaticDebugEvaluationIsCanonical(t *testing.T) {
	report, err := EvaluateStaticDebug()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeStaticDebugReport(report)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) == 0 || encoded[len(encoded)-1] == '\n' {
		t.Fatalf("encoded framing=%q", encoded)
	}
	parsed, err := ParseStaticDebugReport(encoded)
	if err != nil || parsed.Identity() != report.Identity() || parsed.Validate() != nil {
		t.Fatalf("parsed=%#v err=%v", parsed, err)
	}
	invalid := [][]byte{
		append(append([]byte(nil), encoded...), '\n'),
		append([]byte{' '}, encoded...),
		append(append([]byte(nil), encoded[:len(encoded)-1]...), []byte(`,"extra":true}`)...),
		bytes.Replace(encoded, []byte(`"contract":"open-trestle/static-debug-evaluation-result"`), []byte(`"contract":"other"`), 1),
		bytes.Replace(encoded, []byte(`"status":"passed"`), []byte(`"status":"failed"`), 1),
		append([]byte(`{"identity":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",`), encoded[1:]...),
	}
	for index, value := range invalid {
		if parsed, err := ParseStaticDebugReport(value); err == nil || parsed.Identity() != "" {
			t.Fatalf("invalid[%d] parsed=%#v err=%v", index, parsed, err)
		}
	}
}

func TestStaticDebugEvaluationMatchesPublishedGolden(t *testing.T) {
	report, err := EvaluateStaticDebug()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeStaticDebugReport(report)
	if err != nil {
		t.Fatal(err)
	}
	golden, err := os.ReadFile("testdata/static-debug-report-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	want := append(append([]byte(nil), encoded...), '\n')
	if !bytes.Equal(golden, want) {
		t.Fatalf("golden does not match canonical report: got %d bytes, want %d", len(golden), len(want))
	}
}
