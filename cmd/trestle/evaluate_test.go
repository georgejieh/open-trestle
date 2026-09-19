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
