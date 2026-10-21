package main

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestRunEvaluateStaticDebugWritesVersionedReport(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"evaluate", "static-debug"}, &stdout, &stderr); code != 0 || stderr.Len() != 0 || !bytes.Contains(stdout.Bytes(), []byte(`"contract":"open-trestle/static-debug-evaluation-result"`)) || !bytes.Contains(stdout.Bytes(), []byte(`"failed_count":0`)) || bytes.Count(stdout.Bytes(), []byte{'\n'}) != 1 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestRunEvaluateStaticDebugExitClasses(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
		run  staticDebugEvaluationRunner
		out  io.Writer
		want int
	}{
		{"usage", []string{"other"}, nil, &bytes.Buffer{}, 2},
		{"evaluation error", []string{"static-debug"}, func() ([]byte, bool, error) { return nil, false, errors.New("failed") }, &bytes.Buffer{}, 1},
		{"write error", []string{"static-debug"}, func() ([]byte, bool, error) { return []byte(`{}`), true, nil }, evaluationErrorWriter{}, 1},
		{"mismatch", []string{"static-debug"}, func() ([]byte, bool, error) { return []byte(`{"failed_count":1}`), false, nil }, &bytes.Buffer{}, 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stderr bytes.Buffer
			if code := runEvaluateWithRunner(test.args, test.out, &stderr, test.run); code != test.want {
				t.Fatalf("code=%d want=%d stderr=%q", code, test.want, stderr.String())
			}
		})
	}
}

type evaluationErrorWriter struct{}

func (evaluationErrorWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestRunEvaluateDeterministicCorpusCandidateRefusesReleaseStatus(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"evaluate", "deterministic-corpus-candidate"}, &stdout, &stderr)
	if code != 3 || stderr.Len() != 0 || bytes.Count(stdout.Bytes(), []byte{'\n'}) != 1 || !bytes.Contains(stdout.Bytes(), []byte(`"review_state":"pending"`)) || !bytes.Contains(stdout.Bytes(), []byte(`"release_evidence_eligible":false`)) || !bytes.Contains(stdout.Bytes(), []byte(`"golden_status":"prohibited_pending_human_review"`)) {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestRunDeterministicCorpusCandidateExitClasses(t *testing.T) {
	for _, test := range []struct {
		name string
		run  deterministicCorpusCandidateRunner
		out  io.Writer
		want int
	}{
		{"evaluation error", func() ([]byte, string, error) { return nil, "", errors.New("failed") }, &bytes.Buffer{}, 1},
		{"write error", func() ([]byte, string, error) { return []byte(`{}`), "matched", nil }, evaluationErrorWriter{}, 1},
		{"mismatch", func() ([]byte, string, error) { return []byte(`{}`), "mismatch", nil }, &bytes.Buffer{}, 3},
		{"matched but pending", func() ([]byte, string, error) { return []byte(`{}`), "matched", nil }, &bytes.Buffer{}, 4},
		{"invalid status", func() ([]byte, string, error) { return []byte(`{}`), "invalid", nil }, &bytes.Buffer{}, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stderr bytes.Buffer
			if code := runDeterministicCorpusCandidate(test.out, &stderr, test.run); code != test.want {
				t.Fatalf("code=%d want=%d stderr=%q", code, test.want, stderr.String())
			}
		})
	}
}

func TestRunEvaluateModelContractCandidatePreservesPendingReview(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"evaluate", "model-contract-candidate"}, &stdout, &stderr)
	if code != 4 || stderr.Len() != 0 || bytes.Count(stdout.Bytes(), []byte{'\n'}) != 1 || !bytes.Contains(stdout.Bytes(), []byte(`"release_evidence_eligible":false`)) || !bytes.Contains(stdout.Bytes(), []byte(`"quality_measured":false`)) || !bytes.Contains(stdout.Bytes(), []byte(`"review_state":"pending"`)) {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}
