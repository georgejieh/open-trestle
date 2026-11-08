package localreview

import (
	"bytes"
	"strings"
	"testing"
)

// Counts of reviewed repository AI material are attention signals: they are
// encoded and printed when present, omitted when zero, and never change status.
func TestResultReportsRepositoryAIMaterialCounts(t *testing.T) {
	result := emptyResult("no_candidates")
	plain, err := EncodeResult(result)
	if err != nil {
		t.Fatal(err)
	}
	var plainText bytes.Buffer
	if err := RenderResult(&plainText, result); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(plain, []byte("agent_configuration_sources")) || bytes.Contains(plain, []byte("instruction_like_sources")) || strings.Contains(plainText.String(), "ai material") {
		t.Fatal("zero AI material counts were reported")
	}
	result.wire.AgentConfigurationSources, result.wire.InstructionLikeSources = 2, 1
	encoded, err := EncodeResult(result)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(encoded, []byte(`"agent_configuration_sources":2,"instruction_like_sources":1`)) {
		t.Fatalf("result JSON lacks AI material counts: %s", encoded)
	}
	var text bytes.Buffer
	if err := RenderResult(&text, result); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text.String(), "ai material in review context: agent_configuration=2 instruction_like=1 (reviewed as code, never followed)\n") {
		t.Fatalf("text output lacks AI material line: %q", text.String())
	}
	if result.wire.Status != "no_candidates" || result.CIDisposition() != "inconclusive" {
		t.Fatal("AI material counts changed the result status")
	}
	report, err := result.Report()
	if err != nil || report.AgentConfigurationSources != 2 || report.InstructionLikeSources != 1 {
		t.Fatalf("report lacks AI material counts: %+v %v", report, err)
	}
}
