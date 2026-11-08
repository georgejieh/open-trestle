package main

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestBuildInfoCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"build-info"}, &stdout, &stderr); code != 0 || stderr.Len() != 0 {
		t.Fatalf("build-info: code=%d stderr=%s", code, &stderr)
	}
	var document map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	if document["program"] != "trestle" || document["contract"] != "open-trestle/build-info" {
		t.Fatalf("unexpected build-info: %s", &stdout)
	}
	stdout.Reset()
	if code := run([]string{"build-info", "--listen=:1"}, &stdout, &stderr); code != 2 || stdout.Len() != 0 {
		t.Fatal("extra build-info arguments accepted")
	}
}
