package main

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestConfigCodexSessionStatusIsObservational(t *testing.T) {
	var out, diagnostics bytes.Buffer
	if code := runConfigCodexSession([]string{"status"}, &out, &diagnostics); code != 0 {
		t.Fatalf("exit %d: %s", code, diagnostics.String())
	}
	var got struct {
		Status      string   `json:"status"`
		Profile     string   `json:"profile"`
		Available   bool     `json:"runtime_available"`
		Blocker     string   `json:"blocker"`
		Limitations []string `json:"limitations"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Limitations) == 0 {
		t.Fatal("missing non-authentication limitation")
	}
	if got.Status != "blocked" || got.Profile != "codex_chatgpt_session_v1" || got.Available || got.Blocker != "hard_output_bound_unavailable" {
		t.Fatalf("%+v", got)
	}
	for _, args := range [][]string{nil, {"login"}, {"status", "--token", "synthetic"}} {
		out.Reset()
		diagnostics.Reset()
		if code := runConfigCodexSession(args, &out, &diagnostics); code != 2 || out.Len() != 0 {
			t.Fatalf("args %v exit %d", args, code)
		}
	}
}
