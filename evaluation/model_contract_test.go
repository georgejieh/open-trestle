package evaluation

import (
	"bytes"
	"testing"
)

func TestModelContractCandidateIsDeterministicAndNotQualityApproval(t *testing.T) {
	first, err := EvaluateModelContractCandidate()
	if err != nil {
		t.Fatal(err)
	}
	second, err := EvaluateModelContractCandidate()
	if err != nil || !bytes.Equal(first, second) {
		t.Fatalf("contract report is not deterministic: %v", err)
	}
	var report modelContractReport
	if err := decodeStrictJSON(first, maximumCorpusReportBytes, &report); err != nil {
		t.Fatal(err)
	}
	if report.Contract != "open-trestle/model-contract-candidate" || report.SchemaVersion != 1 || report.ReviewState != "pending" || report.ReleaseEvidenceEligible || report.QualityMeasured || !report.Passed || len(report.Cases) != 8 || !validCorpusDigest(report.CorpusIdentity) || !validCorpusDigest(report.Identity) {
		t.Fatalf("invalid candidate report: %+v", report)
	}
	for _, result := range report.Cases {
		if !result.Matched || result.Expected != result.Observed {
			t.Fatalf("contract mismatch: %+v", result)
		}
	}
}
