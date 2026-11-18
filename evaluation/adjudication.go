package evaluation

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"time"
)

var ErrInvalidAdjudication = errors.New("invalid deterministic corpus human adjudication")

type adjudicationUnit struct {
	CaseID    string `json:"case_id"`
	TargetKey string `json:"target_key"`
	Decision  string `json:"decision"`
}

type humanAdjudication struct {
	Contract                string             `json:"contract"`
	SchemaVersion           int                `json:"schema_version"`
	CorpusIdentity          string             `json:"corpus_identity"`
	LabelSetIdentity        string             `json:"label_set_identity"`
	EvaluatorIdentity       string             `json:"evaluator_identity"`
	ObservedReportIdentity  string             `json:"observed_report_identity"`
	ObservedSHA256          string             `json:"observed_sha256"`
	ReviewerIdentifier      string             `json:"reviewer_identifier"`
	FixtureAuthorIdentifier string             `json:"fixture_author_identifier"`
	ReviewDate              string             `json:"review_date"`
	Method                  string             `json:"method"`
	SourceFirst             bool               `json:"source_first"`
	PriorResultExposure     string             `json:"prior_result_exposure"`
	Conflicts               string             `json:"conflicts"`
	ReviewedMaterial        []string           `json:"reviewed_material"`
	Units                   []adjudicationUnit `json:"units"`
}

type adjudicationReport struct {
	Contract                string                      `json:"contract"`
	SchemaVersion           int                         `json:"schema_version"`
	Identity                string                      `json:"identity"`
	ScorerIdentity          string                      `json:"scorer_identity"`
	CorpusIdentity          string                      `json:"corpus_identity"`
	TruthIdentity           string                      `json:"truth_identity"`
	EvaluatorIdentity       string                      `json:"evaluator_identity"`
	AdjudicationSHA256      string                      `json:"adjudication_sha256"`
	ObservedSHA256          string                      `json:"observed_sha256"`
	ObservedReportIdentity  string                      `json:"observed_report_identity"`
	ProvenanceStatus        string                      `json:"provenance_status"`
	AcceptanceStatus        string                      `json:"acceptance_status"`
	ReleaseEvidenceEligible bool                        `json:"release_evidence_eligible"`
	ExecutionStatus         string                      `json:"execution_status"`
	Targets                 []deterministicTargetResult `json:"targets"`
	Cases                   []deterministicCaseResult   `json:"cases"`
}

// EvaluateAdjudication imports declared human review, not authenticated approval, of the existing deterministic labels.
func EvaluateAdjudication(adjudicationBytes, observedBytes []byte, expectedAdjudicationSHA256 string) ([]byte, error) {
	if len(adjudicationBytes) == 0 || len(adjudicationBytes) > maximumCorpusDocumentBytes || !validCorpusDigest(expectedAdjudicationSHA256) || digestBytes(adjudicationBytes) != expectedAdjudicationSHA256 || len(observedBytes) == 0 || len(observedBytes) > maximumCorpusReportBytes+1 {
		return nil, ErrInvalidAdjudication
	}
	var human humanAdjudication
	if decodeStrictJSON(adjudicationBytes, maximumCorpusDocumentBytes, &human) != nil || !strictAdjudicationTokens(adjudicationBytes) {
		return nil, ErrInvalidAdjudication
	}
	observed, err := ParseDeterministicCorpusReport(bytes.TrimSuffix(observedBytes, []byte{'\n'}))
	if err != nil {
		return nil, ErrInvalidAdjudication
	}
	corpus, err := loadDeterministicCorpus(corpusFiles, corpusRoot)
	if err != nil || human.Contract != "open-trestle/deterministic-corpus-human-adjudication" || human.SchemaVersion != 1 || human.CorpusIdentity != corpus.manifest.CorpusIdentity || human.LabelSetIdentity != deriveLabelSetIdentity(corpus.manifest) || human.EvaluatorIdentity != observed.evaluatorIdentity || human.ObservedReportIdentity != observed.Identity() || human.ObservedSHA256 != digestBytes(observedBytes) || !validCaseID(human.ReviewerIdentifier) || !validCaseID(human.FixtureAuthorIdentifier) || human.ReviewerIdentifier == human.FixtureAuthorIdentifier || human.Method != "independent_human_review" || !human.SourceFirst || human.PriorResultExposure != "none_declared" || human.Conflicts != "none_declared" {
		return nil, ErrInvalidAdjudication
	}
	date, err := time.Parse("2006-01-02", human.ReviewDate)
	if err != nil || date.Format("2006-01-02") != human.ReviewDate {
		return nil, ErrInvalidAdjudication
	}
	expectedMaterial := []string{"base_head_sources", "changed_ranges", "positive_labels", "negative_and_near_miss_labels", "expected_coverage", "recorded_mismatches"}
	if len(human.ReviewedMaterial) != len(expectedMaterial) {
		return nil, ErrInvalidAdjudication
	}
	for index, material := range expectedMaterial {
		if human.ReviewedMaterial[index] != material {
			return nil, ErrInvalidAdjudication
		}
	}
	unitIndex := 0
	for _, item := range corpus.cases {
		for _, target := range item.labels.Targets {
			if unitIndex >= len(human.Units) || human.Units[unitIndex] != (adjudicationUnit{item.manifest.ID, target.Key, "confirmed"}) {
				return nil, ErrInvalidAdjudication
			}
			unitIndex++
		}
	}
	if len(human.Units) != unitIndex {
		return nil, ErrInvalidAdjudication
	}
	report := adjudicationReport{
		Contract: "open-trestle/evaluation-adjudication-result", SchemaVersion: 1,
		ScorerIdentity: digestBytes([]byte("open-trestle/deterministic-adjudication-scorer/v1;exact-existing-labels;original-target-set-scores;externally-asserted-provenance;no-acceptance")),
		CorpusIdentity: corpus.manifest.CorpusIdentity, TruthIdentity: deriveLabelSetIdentity(corpus.manifest), EvaluatorIdentity: observed.evaluatorIdentity,
		AdjudicationSHA256: expectedAdjudicationSHA256, ObservedSHA256: digestBytes(observedBytes), ObservedReportIdentity: observed.Identity(),
		ProvenanceStatus: "externally_asserted", AcceptanceStatus: "not_decided", ReleaseEvidenceEligible: false,
		ExecutionStatus: observed.ExecutionStatus(), Targets: observed.Targets(), Cases: observed.Cases(),
	}
	preimage, err := json.Marshal(report)
	if err != nil {
		return nil, ErrInvalidAdjudication
	}
	report.Identity = digestBytes(preimage)
	encoded, err := json.Marshal(report)
	if err != nil || len(encoded) > maximumCorpusReportBytes {
		return nil, ErrInvalidAdjudication
	}
	return encoded, nil
}

func strictAdjudicationTokens(encoded []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	var scan func() bool
	scan = func() bool {
		token, err := decoder.Token()
		if err != nil || token == nil {
			return false
		}
		delimiter, compound := token.(json.Delim)
		if !compound {
			return true
		}
		if delimiter != '{' && delimiter != '[' {
			return false
		}
		for decoder.More() {
			if delimiter == '{' {
				keyToken, err := decoder.Token()
				key, ok := keyToken.(string)
				if err != nil || !ok || key == "" {
					return false
				}
				for _, character := range key {
					if character != '_' && (character < 'a' || character > 'z') && (character < '0' || character > '9') {
						return false
					}
				}
			}
			if !scan() {
				return false
			}
		}
		closing, err := decoder.Token()
		return err == nil && (delimiter == '{' && closing == json.Delim('}') || delimiter == '[' && closing == json.Delim(']'))
	}
	if !scan() {
		return false
	}
	_, err := decoder.Token()
	return err == io.EOF
}
