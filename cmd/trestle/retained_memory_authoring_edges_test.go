package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

type retainedMemoryInputShortStringWriter struct {
	bytes.Buffer
}

func (w *retainedMemoryInputShortStringWriter) WriteString(s string) (int, error) {
	if len(s) == 0 {
		return 0, nil
	}
	_, _ = w.Buffer.WriteString(s[:len(s)-1])
	return len(s) - 1, nil
}

var errRetainedMemoryInputTextReceiptSink = errors.New("retained memory input text receipt sink failed")

type retainedMemoryInputErrorStringWriter struct{}

func (retainedMemoryInputErrorStringWriter) Write(p []byte) (int, error) {
	return len(p), nil
}

func (retainedMemoryInputErrorStringWriter) WriteString(string) (int, error) {
	return 0, errRetainedMemoryInputTextReceiptSink
}

func rmiArgsWithFormat(args []string, format string) []string {
	result := append([]string(nil), args...)
	return append(result, "--format", format)
}

func rmiTextReceiptFields(t *testing.T, text string) map[string]string {
	t.Helper()
	if text == "" || !strings.HasSuffix(text, "\n") {
		t.Fatalf("text receipt is not newline-terminated: %q", text)
	}
	fields := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		key, value, ok := strings.Cut(line, ": ")
		if !ok || key == "" || value == "" || fields[key] != "" {
			t.Fatalf("malformed text receipt line: %q in %q", line, text)
		}
		fields[key] = value
	}
	return fields
}

func TestRunLocalGitRetainedMemoryInputTextFormatWritesLoadableFile(t *testing.T) {
	f := newLocalModelFixture(t, localModelFixtureOptions{})
	feedback := rmiFeedbackFile(t, map[string]string{"a.go": rmiAdvice, "caller.go": "second bounded note"})
	output := rmiOutputPath(t)
	var stdout, stderr bytes.Buffer
	code := runWithContext(context.Background(), append([]string{"local-git", "retained-memory-input"}, rmiArgsWithFormat(rmiArgs(f, feedback, output), "text")...), &stdout, &stderr)
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("text authoring exit=%d stderr=%q", code, stderr.String())
	}
	if _, err := os.Lstat(output); err != nil {
		t.Fatalf("text authoring did not create output: %v", err)
	}
	rmiNoLeak(t, stdout.String()+stderr.String(), feedback, output, f.inventoryPath, f.policyPath, f.objects, rmiAdvice, localModelKey, localModelSecret)
	loaded, encoded, policy, repository, scope := rmiLoadOutput(t, f, output)
	fields := rmiTextReceiptFields(t, stdout.String())
	if len(fields) != 9 || fields["status"] != "authored" || fields["retained_memory_input_identity"] != loaded.Identity() || fields["scope_identity"] != scope.Identity() || fields["repository_identity"] != repository.Identity() || fields["head_revision_identity"] != scope.RefSetIdentity() || fields["runtime_policy_identity"] != policy.Identity() || fields["record_count"] != "2" || fields["path_count"] != "2" {
		t.Fatalf("text receipt drift: %#v", fields)
	}
	expires, err := strconv.ParseInt(fields["expires_at_unix_ms"], 10, 64)
	if err != nil || expires <= time.Now().UTC().UnixMilli() {
		t.Fatalf("text receipt expiry drift: value=%q err=%v", fields["expires_at_unix_ms"], err)
	}
	if !loaded.MatchesEncoding(encoded) {
		t.Fatal("text authoring loader readback did not preserve canonical bytes")
	}
	rmCLINoCalls(t, f)
}

func TestRunLocalGitRetainedMemoryInputJSONReceiptUsesFrozenElevenFieldKeySet(t *testing.T) {
	f := newLocalModelFixture(t, localModelFixtureOptions{})
	feedback := rmiFeedbackFile(t, map[string]string{"a.go": rmiAdvice})
	output := rmiOutputPath(t)
	_, stdout, stderr := rmiRun(t, context.Background(), rmiArgs(f, feedback, output), 0)
	if stderr != "" {
		t.Fatalf("json authoring wrote stderr: %q", stderr)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(stdout), &fields); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"contract":                       true,
		"schema_version":                 true,
		"status":                         true,
		"retained_memory_input_identity": true,
		"scope_identity":                 true,
		"repository_identity":            true,
		"head_revision_identity":         true,
		"runtime_policy_identity":        true,
		"record_count":                   true,
		"path_count":                     true,
		"expires_at_unix_ms":             true,
	}
	if len(fields) != len(want) {
		t.Fatalf("json receipt key count=%d want=%d fields=%v", len(fields), len(want), fields)
	}
	for key := range fields {
		if !want[key] {
			t.Fatalf("json receipt has unexpected key %q in %v", key, fields)
		}
	}
	rmiLoadOutput(t, f, output)
	rmCLINoCalls(t, f)
}

func TestRunLocalGitRetainedMemoryInputTextShortWriteLeavesLoadableFile(t *testing.T) {
	f := newLocalModelFixture(t, localModelFixtureOptions{})
	feedback := rmiFeedbackFile(t, map[string]string{"a.go": rmiAdvice})
	output := rmiOutputPath(t)
	stdout := &retainedMemoryInputShortStringWriter{}
	var stderr bytes.Buffer
	code := runLocalGitRetainedMemoryInput(context.Background(), rmiArgsWithFormat(rmiArgs(f, feedback, output), "text"), stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "may remain") {
		t.Fatalf("text short receipt failure code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	rmiNoLeak(t, stdout.String()+stderr.String(), feedback, output, f.inventoryPath, f.policyPath, f.objects, rmiAdvice, localModelKey, localModelSecret)
	loaded, encoded, _, _, _ := rmiLoadOutput(t, f, output)
	if loaded.Identity() == "" || !loaded.MatchesEncoding(encoded) {
		t.Fatal("text short receipt failure did not leave stable loadable output")
	}
	rmCLINoCalls(t, f)
}

func TestWriteLocalGitRetainedMemoryInputTextReceiptPropagatesStringWriterError(t *testing.T) {
	err := writeLocalGitRetainedMemoryInputReceipt("text", localGitRetainedMemoryInputReceipt{Status: "authored"}, retainedMemoryInputErrorStringWriter{})
	if !errors.Is(err, errRetainedMemoryInputTextReceiptSink) || errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("text receipt writer error=%v, want sink error only", err)
	}
}
