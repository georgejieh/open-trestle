package evaluation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/memory"
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
	// Schema is the candidate batch schema: 1 for the recorded-readback
	// contract, 2 for the executable version 7 generation contract.
	Schema int
}

// modelContractV7 is the executable generation contract fixture: one changed
// source and one repository_context instruction source in a version 7 context.
type modelContractV7 struct {
	payload  []byte
	snapshot review.ReviewSnapshot
	items    []evidence.EvidenceItem
}

func newModelContractV7() (modelContractV7, error) {
	reviewScope, err := audit.NewReviewScope("tenant", "repository", "model-contract")
	if err != nil {
		return modelContractV7{}, err
	}
	memoryScope, err := memory.NewScope("tenant", "repository", "evaluator", memory.RefVisibilityExact, strings.Repeat("a", 64), []string{"."})
	if err != nil {
		return modelContractV7{}, err
	}
	type sourceFixture struct {
		stage          review.ContextStage
		id, path, text string
		start, end     int
	}
	fixtures := []sourceFixture{
		{review.ContextStageChangedHunk, "evidence-1", "internal/example.go", strings.Repeat("x()\n", 11), 10, 20},
		{review.ContextStageRepositoryContext, "instructions-1", "AGENTS.md", "Prefer explicit error handling.\n", 1, 1},
	}
	ranges := make([]evidence.SourceRange, len(fixtures))
	sources := make([]review.ContextSource, len(fixtures))
	items := make([]evidence.EvidenceItem, len(fixtures))
	for index, fixture := range fixtures {
		if ranges[index], err = evidence.NewSourceRange(fixture.path, fixture.start, fixture.end); err != nil {
			return modelContractV7{}, err
		}
		digest := sha256.Sum256([]byte(fixture.text))
		if items[index], err = evidence.NewEvidenceItem(fixture.id, evidence.EvidenceKindSource, hex.EncodeToString(digest[:]), ranges[index]); err != nil {
			return modelContractV7{}, err
		}
		if sources[index], err = review.NewContextSource(fixture.stage, memory.TaintRepositoryControlled, items[index], []byte(fixture.text)); err != nil {
			return modelContractV7{}, err
		}
	}
	snapshot, err := review.NewReviewSnapshot("workspace", strings.Repeat("c", 64), ranges)
	if err != nil {
		return modelContractV7{}, err
	}
	query, err := memory.NewLexicalQuery(memoryScope, "internal/example.go", []string{"error"}, nil, time.UnixMilli(200), 1)
	if err != nil {
		return modelContractV7{}, err
	}
	retrieval, err := memory.NewLexicalIndex().Search(context.Background(), memoryScope, query)
	if err != nil {
		return modelContractV7{}, err
	}
	limits, err := review.NewContextLimits(1<<16, 1)
	if err != nil {
		return modelContractV7{}, err
	}
	packet, err := review.NewContextPacket(reviewScope, memoryScope, snapshot, review.ContextTaskCandidateGeneration, sources, retrieval, limits)
	if err != nil {
		return modelContractV7{}, err
	}
	request, err := packet.ProviderRequest()
	if err != nil {
		return modelContractV7{}, err
	}
	return modelContractV7{payload: request.Payload(), snapshot: snapshot, items: packet.EvidenceItems()}, nil
}

// EvaluateModelContractCandidate checks synthetic response/evidence contracts.
// It makes no model call and does not measure finding correctness or quality.
func EvaluateModelContractCandidate() ([]byte, error) {
	candidate := `{"schema_version":1,"candidates":[{"title":"Unchecked write error","claim":"The write error is discarded.","severity_hint":"high","source_range":{"source_id":"evidence-1","start_line":12,"end_line":13},"evidence_ids":["evidence-1"]}]}`
	verdict := func(outcome, severity, evidenceIDs string) string {
		return fmt.Sprintf(`{"schema_version":1,"verdicts":[{"candidate_id":"CANDIDATE_ID","outcome":%q,"severity":%q,"rationale":"Synthetic contract assertion.","evidence_ids":%s}]}`, outcome, severity, evidenceIDs)
	}
	fixtures := []modelContractFixture{
		{"verified", candidate, verdict("verified", "high", `["evidence-1"]`), "verified", 1},
		{"rejected", candidate, verdict("rejected", "none", `[]`), "rejected", 1},
		{"inconclusive", candidate, verdict("inconclusive", "none", `[]`), "inconclusive", 1},
		{"empty", `{"schema_version":1,"candidates":[]}`, `{"schema_version":1,"verdicts":[]}`, "empty", 1},
		{"missing-candidate-evidence", strings.ReplaceAll(candidate, "evidence-1", "absent"), "", "candidate_refused", 1},
		{"range-near-miss", strings.Replace(candidate, `"start_line":12,"end_line":13`, `"start_line":21,"end_line":21`, 1), "", "candidate_refused", 1},
		{"missing-verdict-evidence", candidate, verdict("verified", "high", `["absent"]`), "verification_refused", 1},
		{"missing-verdict", candidate, `{"schema_version":1,"verdicts":[]}`, "verification_refused", 1},
	}
	candidateV2 := `{"schema_version":2,"candidates":[{"title":"Unchecked write error","claim":"The write error is discarded.","category":"correctness","fix":"Return the write error.","severity_hint":"high","source_range":{"source_id":"evidence-1","start_line":12,"end_line":13},"evidence_ids":["evidence-1"]}]}`
	fixtures = append(fixtures,
		modelContractFixture{"v2-verified", candidateV2, verdict("verified", "high", `["evidence-1"]`), "verified", 2},
		modelContractFixture{"v2-empty", `{"schema_version":2,"candidates":[]}`, `{"schema_version":1,"verdicts":[]}`, "empty", 2},
		modelContractFixture{"v2-unknown-category", strings.Replace(candidateV2, `"category":"correctness"`, `"category":"bug"`, 1), "", "candidate_refused", 2},
		modelContractFixture{"v2-repository-context-anchor", strings.Replace(candidateV2, `"source_id":"evidence-1","start_line":12,"end_line":13},"evidence_ids":["evidence-1"]`, `"source_id":"instructions-1","start_line":1,"end_line":1},"evidence_ids":["instructions-1"]`, 1), `{"schema_version":1,"verdicts":[]}`, "repository_context_omitted", 2},
	)
	v7, err := newModelContractV7()
	if err != nil {
		return nil, err
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
		V7Context      string
	}{1, snapshot.Identity(), item.ID(), item.Digest(), item.SourceRange().Path(), item.SourceRange().StartLine(), item.SourceRange().EndLine(), fixtures, digestBytes(v7.payload)})
	if err != nil {
		return nil, err
	}
	report := modelContractReport{Contract: "open-trestle/model-contract-candidate", SchemaVersion: 1, CorpusIdentity: digestBytes(provenance), ReviewState: "pending", Passed: true, Cases: make([]modelContractCase, 0, len(fixtures))}
	for _, fixture := range fixtures {
		response, err := modelContractResponse(fixture.Candidates)
		if err != nil {
			return nil, err
		}
		caseItems := items
		var candidates review.CandidateBatch
		if fixture.Schema == 2 {
			caseItems = v7.items
			candidates, err = review.ParseContextCandidateBatch(response, v7.payload, v7.snapshot, caseItems)
		} else {
			candidates, err = review.ParseCandidateBatch(response, snapshot, items)
		}
		observed := "unexpected_refusal"
		if errors.Is(err, review.ErrCandidateEvidenceNotAllowed) || errors.Is(err, review.ErrCandidateRangeNotSupported) || errors.Is(err, review.ErrInvalidCandidateCategory) {
			observed = "candidate_refused"
		}
		if err == nil && candidates.SchemaVersion() != fixture.Schema {
			observed, err = "unexpected_schema", errors.New("candidate schema mismatch")
		}
		if err == nil && candidates.RepositoryContextAnchorOmittedCount() > 0 && len(candidates.Findings()) == 0 {
			observed, err = "repository_context_omitted", errors.New("candidate dropped")
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
			batch, parseErr := review.ParseVerificationBatch(response, candidates, caseItems)
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
