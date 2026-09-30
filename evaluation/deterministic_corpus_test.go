package evaluation

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"testing"
	"testing/fstest"
)

func TestDeterministicCorpusCandidateIsPendingAndBounded(t *testing.T) {
	report, err := EvaluateDeterministicCorpusCandidate()
	if err != nil {
		t.Fatal(err)
	}
	if report.Validate() != nil || report.ReviewState() != "pending" || report.ExecutionStatus() != "mismatch" || report.CaseCount() != 6 || report.TargetCount() != 8 || report.ReleaseEvidenceEligible() {
		t.Fatalf("report=%#v", report)
	}
	for _, target := range report.Targets() {
		if target.Key == "syntactic_reference_candidate" {
			if target.TruePositiveCount != 2 || target.FalsePositiveCount != 2 || target.FalseNegativeCount != 0 || target.CoverageNumerator != 3 || target.CoverageDenominator != 3 {
				t.Fatalf("reference target=%#v", target)
			}
		} else if target.FalsePositiveCount != 0 || target.FalseNegativeCount != 0 {
			t.Fatalf("unexpected target mismatch=%#v", target)
		}
	}
	encoded, err := EncodeDeterministicCorpusReport(report)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(`"reviewer_identifier"`)) || bytes.Contains(encoded, []byte(`"review_date"`)) || bytes.Contains(encoded, []byte(`"review_state":"accepted"`)) {
		t.Fatalf("candidate contains adjudication claim: %s", encoded)
	}
	parsed, err := ParseDeterministicCorpusReport(encoded)
	if err != nil || parsed.Identity() != report.Identity() {
		t.Fatalf("parsed=%#v err=%v", parsed, err)
	}
}

func TestScoreCanonicalSetsCountsExactDifferences(t *testing.T) {
	score := scoreCanonicalSets([]string{"a", "b"}, []string{"b", "c", "c"})
	if score.TruePositive != 1 || score.FalsePositive != 1 || score.FalseNegative != 1 || score.Expected != 2 || score.Observed != 2 || score.Precision != [2]uint32{1, 2} || score.Recall != [2]uint32{1, 2} {
		t.Fatalf("score=%#v", score)
	}
	zero := scoreCanonicalSets([]string(nil), []string(nil))
	if zero.Precision != [2]uint32{0, 0} || zero.Recall != [2]uint32{0, 0} {
		t.Fatalf("zero=%#v", zero)
	}
}

func TestCoverageEquationsExcludeUnsupportedAndNotApplicable(t *testing.T) {
	coverage := summarizeCoverage([]coverageObservation{
		{Outcome: "analyzed", Reason: "none"},
		{Outcome: "abstained", Reason: "parse_failure"},
		{Outcome: "unsupported", Reason: "unsupported_language"},
		{Outcome: "not_applicable", Reason: "no_positive_head_ranges"},
	})
	if coverage.ApplicableUnits != 2 || coverage.AnalyzedUnits != 1 || coverage.AbstainedUnits != 1 || coverage.UnsupportedUnits != 1 || coverage.NotApplicableUnits != 1 || coverage.Coverage != [2]uint32{1, 2} || coverage.AbstentionRate != [2]uint32{1, 2} || len(coverage.AbstentionReasons) != 1 || coverage.AbstentionReasons[0].Reason != "parse_failure" {
		t.Fatalf("coverage=%#v", coverage)
	}
}

func TestDeterministicCorpusCandidateIsByteStable(t *testing.T) {
	first, err := EvaluateDeterministicCorpusCandidate()
	if err != nil {
		t.Fatal(err)
	}
	second, err := EvaluateDeterministicCorpusCandidate()
	if err != nil {
		t.Fatal(err)
	}
	firstBytes, _ := EncodeDeterministicCorpusReport(first)
	secondBytes, _ := EncodeDeterministicCorpusReport(second)
	if !bytes.Equal(firstBytes, secondBytes) {
		t.Fatal("candidate report is not deterministic")
	}
}

func TestDeterministicCorpusPublishedSchemasRemainPendingOnly(t *testing.T) {
	for _, name := range []string{
		"../schemas/evaluation/deterministic-corpus-candidate-result-v1.schema.json",
		"../schemas/evaluation/deterministic-corpus-performance-observation-v1.schema.json",
	} {
		encoded, err := os.ReadFile(name)
		if err != nil || !json.Valid(encoded) || !bytes.Contains(encoded, []byte(`"release_evidence_eligible"`)) || !bytes.Contains(encoded, []byte(`"const": false`)) {
			t.Fatalf("schema %s invalid: %v", name, err)
		}
	}
	candidate, _ := os.ReadFile("../schemas/evaluation/deterministic-corpus-candidate-result-v1.schema.json")
	if !bytes.Contains(candidate, []byte(`"const": "pending"`)) || bytes.Contains(candidate, []byte(`"accepted"`)) {
		t.Fatal("candidate schema permits adjudication")
	}
	var schema struct {
		Required   []string                   `json:"required"`
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if json.Unmarshal(candidate, &schema) != nil {
		t.Fatal("candidate schema did not decode")
	}
	report, err := EvaluateDeterministicCorpusCandidate()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeDeterministicCorpusReport(report)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]json.RawMessage
	if json.Unmarshal(encoded, &document) != nil {
		t.Fatal("candidate report did not decode")
	}
	if len(document) != len(schema.Required) || len(schema.Properties) != len(schema.Required) {
		t.Fatalf("candidate report/schema key counts differ: %d %d %d", len(document), len(schema.Required), len(schema.Properties))
	}
	for _, key := range schema.Required {
		if _, ok := document[key]; !ok {
			t.Fatalf("candidate report lacks schema field %q", key)
		}
		if _, ok := schema.Properties[key]; !ok {
			t.Fatalf("candidate schema lacks required property %q", key)
		}
	}
}

func TestDeterministicCorpusLoaderRejectsTamperAndForgedAdjudication(t *testing.T) {
	copyCorpus := func() fstest.MapFS {
		result := fstest.MapFS{}
		err := fs.WalkDir(deterministicCorpusFiles, corpusRoot, func(name string, entry fs.DirEntry, err error) error {
			if err != nil || entry.IsDir() {
				return err
			}
			content, readErr := fs.ReadFile(deterministicCorpusFiles, name)
			if readErr != nil {
				return readErr
			}
			result[name] = &fstest.MapFile{Data: append([]byte(nil), content...)}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	for _, mutate := range []func(fstest.MapFS){
		func(files fstest.MapFS) {
			files[corpusRoot+"/cases/debug_direct_and_multiline/head/main.go"].Data[0] ^= 1
		},
		func(files fstest.MapFS) {
			name := corpusRoot + "/adjudication.json"
			files[name].Data = bytes.Replace(files[name].Data, []byte(`"decision": "pending"`), []byte(`"decision": "pending", "reviewer_identifier": "unapproved"`), 1)
		},
		func(files fstest.MapFS) {
			name := corpusRoot + "/adjudication.json"
			files[name].Data = bytes.Replace(files[name].Data, []byte(`"review_state": "pending"`), []byte(`"review_state": "accepted"`), 1)
		},
	} {
		files := copyCorpus()
		mutate(files)
		if _, err := loadDeterministicCorpus(files, corpusRoot); err == nil {
			t.Fatal("tampered corpus loaded")
		}
	}
}

func TestDeterministicCorpusStrictDocumentsRejectUnknownAndDuplicateFields(t *testing.T) {
	invalid := [][]byte{
		[]byte(`{"schema_version":1,"case_id":"case","changes":[],"targets":[],"unknown":true}`),
		[]byte(`{"schema_version":1,"schema_version":1,"case_id":"case","changes":[],"targets":[]}`),
	}
	for _, encoded := range invalid {
		var labels corpusCaseLabels
		if decodeStrictJSON(encoded, maximumCorpusDocumentBytes, &labels) == nil {
			t.Fatalf("invalid labels decoded: %s", encoded)
		}
	}
	corpus, err := loadDeterministicCorpus(deterministicCorpusFiles, corpusRoot)
	if err != nil {
		t.Fatal(err)
	}
	manifest := corpus.manifest
	manifest.Cases = append([]corpusCaseManifest(nil), manifest.Cases...)
	manifest.Cases[0].Files = append([]corpusFixtureFile(nil), manifest.Cases[0].Files...)
	manifest.Cases[0].Files[0].Path = "../escape"
	if validateManifest(manifest) == nil {
		t.Fatal("traversal path accepted")
	}
	manifest = corpus.manifest
	manifest.Targets = append([]corpusTarget(nil), manifest.Targets...)
	manifest.Targets[0].Version = 2
	if validateManifest(manifest) == nil {
		t.Fatal("unknown target version accepted")
	}
}

func TestDeterministicCorpusParserRejectsRehashedForgeries(t *testing.T) {
	report, err := evaluateDeterministicCorpusCandidateUnchecked()
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*DeterministicCorpusReport){
		func(value *DeterministicCorpusReport) {
			value.cases = append([]deterministicCaseResult(nil), value.cases...)
			value.cases[0].ID = "classification_boundariez"
		},
		func(value *DeterministicCorpusReport) {
			value.targets = append([]deterministicTargetResult(nil), value.targets...)
			value.targets[len(value.targets)-1].UnsupportedUnits = 123
		},
	} {
		forged := report
		mutate(&forged)
		forged.identity = deriveDeterministicReportIdentity(forged)
		encoded, marshalErr := json.Marshal(deterministicWire(forged))
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		if parsed, parseErr := ParseDeterministicCorpusReport(encoded); parseErr == nil || parsed.Identity() != "" {
			t.Fatalf("forged report parsed: %#v %v", parsed, parseErr)
		}
	}
}

func TestDeterministicCorpusLabelsRequireRealBoundedSourcesAndCompleteCoverage(t *testing.T) {
	corpus, err := loadDeterministicCorpus(deterministicCorpusFiles, corpusRoot)
	if err != nil {
		t.Fatal(err)
	}
	var source deterministicCorpusCase
	for _, item := range corpus.cases {
		if item.manifest.ID == "semantic_api_and_references" {
			source = item
		}
	}
	clone := source
	clone.labels.Targets = append([]corpusCaseTarget(nil), source.labels.Targets...)
	clone.labels.Targets[0].Expected = append([]corpusLabel(nil), source.labels.Targets[0].Expected...)
	clone.labels.Targets[0].Expected[0].Path = "ghost.go"
	if validateCaseLabels(corpus.manifest, clone) == nil {
		t.Fatal("ghost label path accepted")
	}
	clone = source
	clone.labels.Targets = append([]corpusCaseTarget(nil), source.labels.Targets...)
	clone.labels.Targets[2].Expected = append([]corpusLabel(nil), source.labels.Targets[2].Expected...)
	clone.labels.Targets[2].Expected[0].Line = 999
	if validateCaseLabels(corpus.manifest, clone) == nil {
		t.Fatal("out-of-source reference accepted")
	}
	clone = source
	clone.labels.Targets = append([]corpusCaseTarget(nil), source.labels.Targets...)
	clone.labels.Targets[2].ExpectedCoverage = append([]expectedCoverage(nil), source.labels.Targets[2].ExpectedCoverage[:2]...)
	if validateCaseLabels(corpus.manifest, clone) == nil {
		t.Fatal("incomplete coverage universe accepted")
	}
}
