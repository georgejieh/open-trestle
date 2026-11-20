package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/evaluation"
)

func TestRunEvaluateAdjudicationReadsExplicitInputs(t *testing.T) {
	const sentinel = "ADJUDICATION_PRIVATE_INPUT_SENTINEL"
	missing := filepath.Join(t.TempDir(), sentinel+".json")
	var stdout, stderr bytes.Buffer
	code := run([]string{"evaluate", "adjudication", "--adjudication", missing, "--adjudication-sha256", strings.Repeat("a", 64), "--observed", missing}, &stdout, &stderr)
	if code != 1 || stdout.Len() != 0 || stderr.Len() == 0 {
		t.Fatalf("supported adjudication input refusal code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if strings.Contains(stderr.String(), missing) || strings.Contains(stderr.String(), sentinel) {
		t.Fatal("adjudication input failure echoed private input")
	}
}

func syntheticCLIAdjudicationInputs(t *testing.T) ([]byte, []byte) {
	t.Helper()
	candidate, err := evaluation.EvaluateDeterministicCorpusCandidate()
	if err != nil {
		t.Fatal(err)
	}
	observed, err := evaluation.EncodeDeterministicCorpusReport(candidate)
	if err != nil {
		t.Fatal(err)
	}
	var subject struct {
		CorpusIdentity    string `json:"corpus_identity"`
		LabelSetIdentity  string `json:"label_set_identity"`
		EvaluatorIdentity string `json:"evaluator_identity"`
		Cases             []struct {
			ID     string `json:"id"`
			Target string `json:"target_key"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(observed, &subject); err != nil {
		t.Fatal(err)
	}
	units := make([]map[string]string, 0, len(subject.Cases))
	for _, item := range subject.Cases {
		units = append(units, map[string]string{"case_id": item.ID, "target_key": item.Target, "decision": "confirmed"})
	}
	document := map[string]any{
		"contract": "open-trestle/deterministic-corpus-human-adjudication", "schema_version": 1,
		"corpus_identity": subject.CorpusIdentity, "label_set_identity": subject.LabelSetIdentity,
		"evaluator_identity": subject.EvaluatorIdentity, "observed_report_identity": candidate.Identity(), "observed_sha256": adjudicationTestDigest(observed),
		"reviewer_identifier": "synthetic-test-reviewer", "fixture_author_identifier": "synthetic-test-author",
		"review_date": "2026-10-26", "method": "independent_human_review", "source_first": true,
		"prior_result_exposure": "none_declared", "conflicts": "none_declared",
		"reviewed_material": []string{"base_head_sources", "changed_ranges", "positive_labels", "negative_and_near_miss_labels", "expected_coverage", "recorded_mismatches"}, "units": units,
	}
	adjudication, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return adjudication, observed
}

func adjudicationTestDigest(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func TestRunEvaluateAdjudicationImportsSyntheticReviewWithoutApproval(t *testing.T) {
	adjudication, observed := syntheticCLIAdjudicationInputs(t)
	dir := t.TempDir()
	adjudicationPath, observedPath := filepath.Join(dir, "human.json"), filepath.Join(dir, "observed.json")
	for path, value := range map[string][]byte{adjudicationPath: adjudication, observedPath: observed} {
		if err := os.WriteFile(path, value, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	args := []string{"evaluate", "adjudication", "--adjudication", adjudicationPath, "--adjudication-sha256", adjudicationTestDigest(adjudication), "--observed", observedPath}
	var stdout, stderr bytes.Buffer
	if code := run(args, &stdout, &stderr); code != 4 || stderr.Len() != 0 {
		t.Fatalf("import code=%d stderr=%q", code, stderr.String())
	}
	expected, err := evaluation.EvaluateAdjudication(adjudication, observed, adjudicationTestDigest(adjudication))
	if err != nil || !bytes.Equal(stdout.Bytes(), append(expected, '\n')) {
		t.Fatal("CLI did not preserve canonical scoring output")
	}
	for _, forbidden := range []string{"synthetic-test-reviewer", "synthetic-test-author", adjudicationPath, observedPath, `"passed"`, `"release_evidence_eligible":true`} {
		if strings.Contains(stdout.String(), forbidden) {
			t.Fatal("score echoed private metadata or approval")
		}
	}
	for path, expected := range map[string][]byte{adjudicationPath: adjudication, observedPath: observed} {
		actual, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(actual, expected) {
			t.Fatal("import mutated an input file")
		}
	}
	for _, writer := range []io.Writer{shortNilWriter{}, evaluationErrorWriter{}} {
		stderr.Reset()
		if code := run(args, writer, &stderr); code != 1 {
			t.Fatal("incomplete output accepted")
		}
	}
	badPin := append([]string(nil), args...)
	badPin[5] = strings.Repeat("f", 64)
	stdout.Reset()
	stderr.Reset()
	if code := run(badPin, &stdout, &stderr); code != 1 || stdout.Len() != 0 {
		t.Fatal("wrong pin accepted")
	}
	duplicate := append([]string(nil), args...)
	duplicate[6] = "--adjudication"
	for _, invalid := range [][]string{{"evaluate", "adjudication"}, append(append([]string(nil), args...), "private-extra"), duplicate} {
		stdout.Reset()
		stderr.Reset()
		if code := run(invalid, &stdout, &stderr); code != 2 || stdout.Len() != 0 {
			t.Fatal("invalid arguments accepted")
		}
		if strings.Contains(stderr.String(), "private-extra") || strings.Contains(stderr.String(), adjudicationPath) {
			t.Fatal("usage echoed input")
		}
	}
}
