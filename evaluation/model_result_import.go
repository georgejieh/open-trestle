package evaluation

import (
	"encoding/json"
	"errors"

	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/scm"
	"github.com/georgejieh/open-trestle/localreview"
)

var ErrInvalidModelResultImport = errors.New("invalid completed model result or corpus source binding")

type modelResultReviewUnit struct {
	Kind     string `json:"kind"`
	Identity string `json:"identity"`
	Decision string `json:"decision"`
}

type modelResultObservation struct {
	Known    bool    `json:"known"`
	Value    *uint64 `json:"value"`
	Unit     string  `json:"unit"`
	Boundary string  `json:"boundary"`
}

type modelResultImportReport struct {
	Contract                     string                  `json:"contract"`
	SchemaVersion                int                     `json:"schema_version"`
	Identity                     string                  `json:"identity"`
	ImporterIdentity             string                  `json:"importer_identity"`
	CorpusIdentity               string                  `json:"corpus_identity"`
	LabelSetIdentity             string                  `json:"label_set_identity"`
	CaseID                       string                  `json:"case_id"`
	CaseLabelsSHA256             string                  `json:"case_labels_sha256"`
	CorpusReviewState            string                  `json:"corpus_review_state"`
	SourceExecutionIdentity      string                  `json:"source_execution_identity"`
	BaseManifestIdentity         string                  `json:"base_manifest_identity"`
	HeadManifestIdentity         string                  `json:"head_manifest_identity"`
	ResultSHA256                 string                  `json:"result_sha256"`
	ProvenanceStatus             string                  `json:"provenance_status"`
	ReviewState                  string                  `json:"review_state"`
	AcceptanceStatus             string                  `json:"acceptance_status"`
	ReleaseEvidenceEligible      bool                    `json:"release_evidence_eligible"`
	QualityMeasured              bool                    `json:"quality_measured"`
	Result                       json.RawMessage         `json:"result"`
	DeterministicCandidateReport json.RawMessage         `json:"deterministic_candidate_report"`
	AdjudicationUnits            []modelResultReviewUnit `json:"adjudication_units"`
	Cost                         modelResultObservation  `json:"cost"`
	Latency                      modelResultObservation  `json:"latency"`
	CPU                          modelResultObservation  `json:"cpu"`
	PeakRSS                      modelResultObservation  `json:"peak_rss"`
}

// ImportModelResult binds a captured completed review to exact existing corpus sources.
// It supplies no human labels, model-quality scores, thresholds or approval.
// It observes the result (localreview.ObserveCompletedResult): a run whose
// disposition its recorded pre-existing class relaxed imports, and the
// import never trusts that relaxation for a gate.
func ImportModelResult(encoded []byte, expectedSHA256, caseID string, source scm.LocalGitChangeExecution) ([]byte, error) {
	if !validCorpusDigest(expectedSHA256) || digestBytes(encoded) != expectedSHA256 || !validCorpusDigest(source.Identity()) {
		return nil, ErrInvalidModelResultImport
	}
	metadata, err := localreview.ObserveCompletedResult(encoded)
	if err != nil {
		return nil, ErrInvalidModelResultImport
	}
	pair := source.AcquisitionPair()
	base, head := pair.BaseEnvelope().EvidenceBinding(), pair.HeadEnvelope().EvidenceBinding()
	if !pair.HasManifests() || metadata.RepositoryIdentity != base.RepositoryIdentity() || metadata.RepositoryIdentity != head.RepositoryIdentity() || metadata.BaseRevisionIdentity != base.RevisionIdentity() || metadata.HeadRevisionIdentity != head.RevisionIdentity() {
		return nil, ErrInvalidModelResultImport
	}
	corpus, err := loadDeterministicCorpus(corpusFiles, corpusRoot)
	if err != nil {
		return nil, err
	}
	var item *deterministicCorpusCase
	for i := range corpus.cases {
		if corpus.cases[i].manifest.ID == caseID {
			item = &corpus.cases[i]
			break
		}
	}
	if item == nil || !modelResultManifestMatches(pair.BaseManifest(), item.manifest, "base") || !modelResultManifestMatches(pair.HeadManifest(), item.manifest, "head") {
		return nil, ErrInvalidModelResultImport
	}
	deterministic, err := EvaluateDeterministicCorpusCandidate()
	if err != nil {
		return nil, err
	}
	deterministicJSON, err := EncodeDeterministicCorpusReport(deterministic)
	if err != nil {
		return nil, err
	}
	units := []modelResultReviewUnit{}
	for _, id := range metadata.CandidateIDs {
		units = append(units, modelResultReviewUnit{"candidate", id, ""})
	}
	units = append(units, modelResultReviewUnit{"verified_set", metadata.Diagnostics.VerifiedSetIdentity(), ""})
	for _, finding := range metadata.Diagnostics.Findings() {
		units = append(units, modelResultReviewUnit{"diagnostic", finding.Identity(), ""})
	}
	report := modelResultImportReport{
		Contract: "open-trestle/model-result-evaluation", SchemaVersion: 1,
		ImporterIdentity: digestBytes([]byte("open-trestle/model-result-import/v1;canonical-completed-local-result-v1;exact-corpus-source-manifests;blank-human-decisions;no-model-score;no-acceptance")),
		CorpusIdentity:   corpus.manifest.CorpusIdentity, LabelSetIdentity: deriveLabelSetIdentity(corpus.manifest), CaseID: caseID, CaseLabelsSHA256: item.manifest.LabelsSHA256, CorpusReviewState: corpus.adjudication.ReviewState,
		SourceExecutionIdentity: source.Identity(), BaseManifestIdentity: pair.BaseManifest().Identity(), HeadManifestIdentity: pair.HeadManifest().Identity(), ResultSHA256: expectedSHA256,
		ProvenanceStatus: "externally_asserted_capture", ReviewState: "pending", AcceptanceStatus: "not_decided",
		Result: json.RawMessage(encoded), DeterministicCandidateReport: deterministicJSON, AdjudicationUnits: units,
		Cost:    modelResultObservation{Known: metadata.UsageKnown, Unit: "micro_usd", Boundary: "completed_review_route_reconciliation"},
		Latency: modelResultObservation{Unit: "nanoseconds", Boundary: "not_recorded_in_result"}, CPU: modelResultObservation{Unit: "microseconds", Boundary: "not_recorded_in_result"}, PeakRSS: modelResultObservation{Unit: "bytes", Boundary: "not_recorded_in_result"},
	}
	if metadata.UsageKnown {
		cost := metadata.ActualCostMicroUSD
		report.Cost.Value = &cost
	}
	preimage, err := json.Marshal(report)
	if err != nil {
		return nil, err
	}
	report.Identity = digestBytes(preimage)
	output, err := json.Marshal(report)
	if err != nil || len(output) > maximumCorpusReportBytes {
		return nil, ErrInvalidModelResultImport
	}
	return output, nil
}

func modelResultManifestMatches(manifest evidence.RepositoryManifest, item corpusCaseManifest, side string) bool {
	count := 0
	for _, file := range item.Files {
		if file.Side != side {
			continue
		}
		count++
		actual, ok := manifest.File(file.Path)
		if !ok || actual.Digest() != file.SHA256 || actual.SizeBytes() != file.Bytes {
			return false
		}
	}
	return manifest.FileCount() == count
}
