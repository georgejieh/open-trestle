package main

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
)

func TestDaemonBuildInfoDoesNotLoadRuntime(t *testing.T) {
	var stdout, stderr bytes.Buffer
	getenv := func(string) string { t.Fatal("build-info accessed runtime credentials"); return "" }
	if err := runDaemon(context.Background(), []string{"build-info"}, getenv, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	if document["program"] != "trestled" || document["contract"] != "open-trestle/build-info" || stderr.Len() != 0 {
		t.Fatalf("unexpected build-info: %s stderr=%s", &stdout, &stderr)
	}
	stdout.Reset()
	if err := runDaemon(context.Background(), []string{"build-info", "--listen=:1"}, getenv, &stdout, &stderr); err == nil || stdout.Len() != 0 {
		t.Fatal("extra build-info arguments accepted")
	}
}
