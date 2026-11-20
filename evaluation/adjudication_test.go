package evaluation

import (
	"bytes"
	"encoding/json"
	"testing"
)

func syntheticAdjudicationInputs(t *testing.T) (DeterministicCorpusReport, []byte, []byte) {
	t.Helper()
	candidate, err := EvaluateDeterministicCorpusCandidate()
	if err != nil {
		t.Fatal(err)
	}
	observed, err := EncodeDeterministicCorpusReport(candidate)
	if err != nil {
		t.Fatal(err)
	}
	corpus, err := loadDeterministicCorpus(deterministicCorpusFiles, corpusRoot)
	if err != nil {
		t.Fatal(err)
	}
	units := make([]map[string]string, 0)
	for _, item := range corpus.cases {
		for _, target := range item.labels.Targets {
			units = append(units, map[string]string{"case_id": item.manifest.ID, "target_key": target.Key, "decision": "confirmed"})
		}
	}
	document := map[string]any{
		"contract": "open-trestle/deterministic-corpus-human-adjudication", "schema_version": 1,
		"corpus_identity": candidate.corpusIdentity, "label_set_identity": candidate.labelSetIdentity,
		"evaluator_identity": candidate.evaluatorIdentity, "observed_report_identity": candidate.Identity(),
		"observed_sha256":     digestBytes(observed),
		"reviewer_identifier": "synthetic-test-reviewer", "fixture_author_identifier": "synthetic-test-author",
		"review_date": "2026-10-26", "method": "independent_human_review", "source_first": true,
		"prior_result_exposure": "none_declared", "conflicts": "none_declared",
		"reviewed_material": []string{"base_head_sources", "changed_ranges", "positive_labels", "negative_and_near_miss_labels", "expected_coverage", "recorded_mismatches"},
		"units":             units,
	}
	adjudication, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return candidate, observed, adjudication
}

func TestEvaluateAdjudicationRetainsObservedScoresWithoutApproval(t *testing.T) {
	candidate, observed, adjudication := syntheticAdjudicationInputs(t)
	original := append([]byte(nil), observed...)
	encoded, err := EvaluateAdjudication(adjudication, observed, digestBytes(adjudication))
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Contract                string                      `json:"contract"`
		SchemaVersion           int                         `json:"schema_version"`
		ProvenanceStatus        string                      `json:"provenance_status"`
		AcceptanceStatus        string                      `json:"acceptance_status"`
		ReleaseEvidenceEligible bool                        `json:"release_evidence_eligible"`
		ExecutionStatus         string                      `json:"execution_status"`
		ObservedReportIdentity  string                      `json:"observed_report_identity"`
		AdjudicationSHA256      string                      `json:"adjudication_sha256"`
		Targets                 []deterministicTargetResult `json:"targets"`
	}
	if err := json.Unmarshal(encoded, &result); err != nil {
		t.Fatal(err)
	}
	if result.Contract != "open-trestle/evaluation-adjudication-result" || result.SchemaVersion != 1 || result.ProvenanceStatus != "externally_asserted" || result.AcceptanceStatus != "not_decided" || result.ReleaseEvidenceEligible || result.ExecutionStatus != "matched" || result.ObservedReportIdentity != candidate.Identity() || result.AdjudicationSHA256 != digestBytes(adjudication) {
		t.Fatal("import inferred approval or lost its observed/adjudication binding")
	}
	found := false
	for _, target := range result.Targets {
		if target.Key == "syntactic_reference_candidate" {
			found = true
			if target.TruePositiveCount != 2 || target.FalsePositiveCount != 0 || target.FalseNegativeCount != 0 {
				t.Fatal("human review import changed the observed scores")
			}
		}
	}
	if !found || !bytes.Equal(observed, original) {
		t.Fatal("import lost target scores or mutated the pending report")
	}
}

func TestEvaluateAdjudicationRefusesUnboundOrIncompleteDeclaredReview(t *testing.T) {
	_, observed, adjudication := syntheticAdjudicationInputs(t)
	var original humanAdjudication
	if err := json.Unmarshal(adjudication, &original); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*humanAdjudication){
		"corpus":             func(v *humanAdjudication) { v.CorpusIdentity = digestBytes([]byte("other")) },
		"labels":             func(v *humanAdjudication) { v.LabelSetIdentity = digestBytes([]byte("other")) },
		"evaluator":          func(v *humanAdjudication) { v.EvaluatorIdentity = digestBytes([]byte("other")) },
		"report":             func(v *humanAdjudication) { v.ObservedReportIdentity = digestBytes([]byte("other")) },
		"observed bytes":     func(v *humanAdjudication) { v.ObservedSHA256 = digestBytes([]byte("other")) },
		"self review":        func(v *humanAdjudication) { v.ReviewerIdentifier = v.FixtureAuthorIdentifier },
		"no reviewer":        func(v *humanAdjudication) { v.ReviewerIdentifier = "" },
		"no author":          func(v *humanAdjudication) { v.FixtureAuthorIdentifier = "" },
		"invalid date":       func(v *humanAdjudication) { v.ReviewDate = "2026-02-30" },
		"model review":       func(v *humanAdjudication) { v.Method = "model_review" },
		"not source first":   func(v *humanAdjudication) { v.SourceFirst = false },
		"exposure":           func(v *humanAdjudication) { v.PriorResultExposure = "exposed" },
		"conflicts":          func(v *humanAdjudication) { v.Conflicts = "unresolved" },
		"missing material":   func(v *humanAdjudication) { v.ReviewedMaterial = v.ReviewedMaterial[:5] },
		"duplicate material": func(v *humanAdjudication) { v.ReviewedMaterial[5] = v.ReviewedMaterial[0] },
		"missing unit":       func(v *humanAdjudication) { v.Units = v.Units[:len(v.Units)-1] },
		"extra unit":         func(v *humanAdjudication) { v.Units = append(v.Units, v.Units[0]) },
		"duplicate unit":     func(v *humanAdjudication) { v.Units[1] = v.Units[0] },
		"wrong target":       func(v *humanAdjudication) { v.Units[0].TargetKey = "unknown" },
		"wrong case":         func(v *humanAdjudication) { v.Units[0].CaseID = "unknown" },
		"rejected":           func(v *humanAdjudication) { v.Units[0].Decision = "rejected" },
		"unresolved":         func(v *humanAdjudication) { v.Units[0].Decision = "unresolved" },
	} {
		t.Run(name, func(t *testing.T) {
			value := original
			value.ReviewedMaterial = append([]string(nil), original.ReviewedMaterial...)
			value.Units = append([]adjudicationUnit(nil), original.Units...)
			mutate(&value)
			encoded, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			if result, err := EvaluateAdjudication(encoded, observed, digestBytes(encoded)); err == nil || result != nil {
				t.Fatal("unbound or incomplete declaration produced a score")
			}
		})
	}
	if result, err := EvaluateAdjudication(adjudication, observed, digestBytes([]byte("wrong pin"))); err == nil || result != nil {
		t.Fatal("wrong external pin produced a score")
	}
}

func TestEvaluateAdjudicationRejectsAmbiguousDocumentsAndForgedObservedScores(t *testing.T) {
	_, observed, adjudication := syntheticAdjudicationInputs(t)
	for name, encoded := range map[string][]byte{
		"empty": nil, "null": []byte("null"), "malformed": []byte("{"),
		"oversize":     bytes.Repeat([]byte{' '}, maximumCorpusDocumentBytes+1),
		"unknown":      bytes.Replace(adjudication, []byte(`"schema_version":1`), []byte(`"schema_version":1,"unknown":true`), 1),
		"duplicate":    bytes.Replace(adjudication, []byte(`"schema_version":1`), []byte(`"schema_version":1,"schema_version":1`), 1),
		"case variant": bytes.Replace(adjudication, []byte(`"source_first"`), []byte(`"Source_first"`), 1),
		"null field":   bytes.Replace(adjudication, []byte(`"source_first":true`), []byte(`"source_first":null`), 1),
		"null array":   bytes.Replace(adjudication, []byte(`"units":[`), []byte(`"units":[null,`), 1),
		"trailing":     append(append([]byte(nil), adjudication...), []byte(" {}")...),
	} {
		t.Run(name, func(t *testing.T) {
			if result, err := EvaluateAdjudication(encoded, observed, digestBytes(encoded)); err == nil || result != nil {
				t.Fatal("invalid adjudication produced a score")
			}
		})
	}
	var forged deterministicReportWire
	if err := json.Unmarshal(observed, &forged); err != nil {
		t.Fatal(err)
	}
	forged.Cases[0].TruePositiveCount++
	encoded, err := json.Marshal(forged)
	if err != nil {
		t.Fatal(err)
	}
	var declaration humanAdjudication
	if err := json.Unmarshal(adjudication, &declaration); err != nil {
		t.Fatal(err)
	}
	declaration.ObservedSHA256 = digestBytes(encoded)
	changed, err := json.Marshal(declaration)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := EvaluateAdjudication(changed, encoded, digestBytes(changed)); err == nil || result != nil {
		t.Fatal("forged observed score produced a score")
	}
}

func TestEvaluateAdjudicationAllowsPinnedJSONFormatting(t *testing.T) {
	_, observed, adjudication := syntheticAdjudicationInputs(t)
	var indented bytes.Buffer
	if err := json.Indent(&indented, adjudication, "", "  "); err != nil {
		t.Fatal(err)
	}
	for name, formatted := range map[string][]byte{
		"leading":  append([]byte(" \n\t"), adjudication...),
		"trailing": append(append([]byte(nil), adjudication...), []byte(" \n\t")...),
		"indented": indented.Bytes(),
	} {
		t.Run(name, func(t *testing.T) {
			encoded, err := EvaluateAdjudication(formatted, observed, digestBytes(formatted))
			if err != nil {
				t.Fatal(err)
			}
			var result map[string]any
			if err := json.Unmarshal(encoded, &result); err != nil || result["adjudication_sha256"] != digestBytes(formatted) {
				t.Fatal("formatted document lost its exact-byte binding")
			}
			if result, err := EvaluateAdjudication(formatted, observed, digestBytes(adjudication)); err == nil || result != nil {
				t.Fatal("formatting accepted with the original document pin")
			}
		})
	}
}

func TestEvaluateAdjudicationBindsTransportBytesAndRemainsDeterministic(t *testing.T) {
	_, observed, adjudication := syntheticAdjudicationInputs(t)
	first, err := EvaluateAdjudication(adjudication, observed, digestBytes(adjudication))
	if err != nil {
		t.Fatal(err)
	}
	second, err := EvaluateAdjudication(adjudication, observed, digestBytes(adjudication))
	if err != nil || !bytes.Equal(first, second) {
		t.Fatal("unstable adjudication score")
	}
	withNewline := append(append([]byte(nil), observed...), '\n')
	if result, err := EvaluateAdjudication(adjudication, withNewline, digestBytes(adjudication)); err == nil || result != nil {
		t.Fatal("unpinned transport bytes accepted")
	}
	var declaration humanAdjudication
	if err := json.Unmarshal(adjudication, &declaration); err != nil {
		t.Fatal(err)
	}
	declaration.ObservedSHA256 = digestBytes(withNewline)
	changed, err := json.Marshal(declaration)
	if err != nil {
		t.Fatal(err)
	}
	third, err := EvaluateAdjudication(changed, withNewline, digestBytes(changed))
	if err != nil || bytes.Equal(first, third) {
		t.Fatal("changed transport binding lost from report identity")
	}
}
