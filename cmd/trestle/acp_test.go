package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestRunACPInitializesReadOnlyAgent(t *testing.T) {
	t.Setenv("OPEN_TRESTLE_API_TOKEN", "01234567890123456789012345678901")
	request, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{"protocolVersion": 1, "clientCapabilities": map[string]any{}}})
	request = append(request, '\n')
	var stdout, stderr bytes.Buffer
	exit := runACP([]string{"--tenant", "tenant-a", "--repository", "repo-a", "--run", "run-a"}, bytes.NewReader(request), &stdout, &stderr)
	if exit != 0 || stderr.Len() != 0 || !strings.Contains(stdout.String(), `"protocolVersion":1`) {
		t.Fatalf("run=(%d,%q,%q)", exit, stdout.String(), stderr.String())
	}
}
func TestRunACPRequiresScopeAndCredential(t *testing.T) {
	t.Setenv("OPEN_TRESTLE_API_TOKEN", "")
	var stdout, stderr bytes.Buffer
	if exit := runACP(nil, bytes.NewReader(nil), &stdout, &stderr); exit != 2 || stdout.Len() != 0 {
		t.Fatalf("run=(%d,%q,%q)", exit, stdout.String(), stderr.String())
	}
}
