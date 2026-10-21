package evaluation

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
)

type modelContractCase struct {
	ID       string `json:"id"`
	Expected string `json:"expected"`
	Observed string `json:"observed"`
	Matched  bool   `json:"matched"`
}

type modelContractReport struct {
	Contract                string              `json:"contract"`
	SchemaVersion           int                 `json:"schema_version"`
	CorpusIdentity          string              `json:"corpus_identity"`
	ReviewState             string              `json:"review_state"`
	ReleaseEvidenceEligible bool                `json:"release_evidence_eligible"`
	QualityMeasured         bool                `json:"quality_measured"`
	Passed                  bool                `json:"passed"`
	Cases                   []modelContractCase `json:"cases"`
	Identity                string              `json:"identity"`
}

type modelContractFixture struct {
	ID, Candidates, Verdict, Expected string
}

// EvaluateModelContractCandidate checks synthetic response/evidence contracts.
// It makes no model call and does not measure finding correctness or quality.
func EvaluateModelContractCandidate() ([]byte, error) {
	candidate := `{"schema_version":1,"candidates":[{"title":"Unchecked write error","claim":"The write error is discarded.","severity_hint":"high","source_range":{"source_id":"evidence-1","start_line":12,"end_line":13},"evidence_ids":["evidence-1"]}]}`
	verdict := func(outcome, severity, evidenceIDs string) string {
		return fmt.Sprintf(`{"schema_version":1,"verdicts":[{"candidate_id":"CANDIDATE_ID","outcome":%q,"severity":%q,"rationale":"Synthetic contract assertion.","evidence_ids":%s}]}`, outcome, severity, evidenceIDs)
	}
	fixtures := []modelContractFixture{
		{"verified", candidate, verdict("verified", "high", `["evidence-1"]`), "verified"},
		{"rejected", candidate, verdict("rejected", "none", `[]`), "rejected"},
		{"inconclusive", candidate, verdict("inconclusive", "none", `[]`), "inconclusive"},
		{"empty", `{"schema_version":1,"candidates":[]}`, `{"schema_version":1,"verdicts":[]}`, "empty"},
		{"missing-candidate-evidence", strings.ReplaceAll(candidate, "evidence-1", "absent"), "", "candidate_refused"},
		{"range-near-miss", strings.Replace(candidate, `"start_line":12,"end_line":13`, `"start_line":21,"end_line":21`, 1), "", "candidate_refused"},
		{"missing-verdict-evidence", candidate, verdict("verified", "high", `["absent"]`), "verification_refused"},
		{"missing-verdict", candidate, `{"schema_version":1,"verdicts":[]}`, "verification_refused"},
	}
	rangeValue, err := evidence.NewSourceRange("internal/example.go", 10, 20)
	if err != nil {
		return nil, err
	}
	snapshot, err := review.NewReviewSnapshot("workspace", strings.Repeat("a", 64), []evidence.SourceRange{rangeValue})
	if err != nil {
		return nil, err
	}
	item, err := evidence.NewEvidenceItem("evidence-1", evidence.EvidenceKindSource, strings.Repeat("b", 64), rangeValue)
	if err != nil {
		return nil, err
	}
	items := []evidence.EvidenceItem{item}
	provenance, err := json.Marshal(struct {
		Version        int
		Snapshot       string
		EvidenceID     string
		EvidenceDigest string
		EvidencePath   string
		EvidenceStart  int
		EvidenceEnd    int
		Fixtures       []modelContractFixture
	}{1, snapshot.Identity(), item.ID(), item.Digest(), item.SourceRange().Path(), item.SourceRange().StartLine(), item.SourceRange().EndLine(), fixtures})
	if err != nil {
		return nil, err
	}
	report := modelContractReport{Contract: "open-trestle/model-contract-candidate", SchemaVersion: 1, CorpusIdentity: digestBytes(provenance), ReviewState: "pending", Passed: true, Cases: make([]modelContractCase, 0, len(fixtures))}
	for _, fixture := range fixtures {
		response, err := modelContractResponse(fixture.Candidates)
		if err != nil {
			return nil, err
		}
		candidates, err := review.ParseCandidateBatch(response, snapshot, items)
		observed := "unexpected_refusal"
		if errors.Is(err, review.ErrCandidateEvidenceNotAllowed) || errors.Is(err, review.ErrCandidateRangeNotSupported) {
			observed = "candidate_refused"
		}
		if err == nil {
			document := fixture.Verdict
			if findings := candidates.Findings(); len(findings) > 0 {
				document = strings.ReplaceAll(document, "CANDIDATE_ID", findings[0].Identity())
			}
			response, err = modelContractResponse(document)
			if err != nil {
				return nil, err
			}
			batch, parseErr := review.ParseVerificationBatch(response, candidates, items)
			observed = "unexpected_refusal"
			if errors.Is(parseErr, review.ErrVerificationEvidenceNotAllowed) || errors.Is(parseErr, review.ErrVerificationCandidateSetMismatch) {
				observed = "verification_refused"
			}
			if parseErr == nil {
				observed = "empty"
				if results := batch.Results(); len(results) > 0 {
					observed = results[0].Outcome().String()
				}
			}
		}
		matched := observed == fixture.Expected
		report.Passed = report.Passed && matched
		report.Cases = append(report.Cases, modelContractCase{fixture.ID, fixture.Expected, observed, matched})
	}
	preimage, err := json.Marshal(report)
	if err != nil {
		return nil, err
	}
	report.Identity = digestBytes(preimage)
	return json.Marshal(report)
}

func modelContractResponse(document string) (provider.Response, error) {
	part, err := provider.NewResponsePart(provider.ResponsePartStructuredData, "application/json", []byte(document))
	if err != nil {
		return provider.Response{}, err
	}
	return provider.NewResponse(provider.CapabilityReviewV1, provider.ResponseFinishStop, []provider.ResponsePart{part}, provider.NewUnknownRouteTokenUsage())
}
