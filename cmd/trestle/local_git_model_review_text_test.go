package main

import (
	"bytes"
	"testing"

	"github.com/georgejieh/open-trestle/localreview"
)

func TestWriteLocalModelResultTextPreservesVerifiedExplanationAndEvidence(t *testing.T) {
	_, captured := modelResultCorpusCapture(t, false, false)
	result, err := localreview.ParseCompletedResult(captured)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := result.CompletedMetadata()
	if err != nil {
		t.Fatal(err)
	}
	findings := metadata.Diagnostics.Findings()
	if len(findings) != 1 || findings[0].Message() == "" || len(findings[0].EvidenceIDs()) == 0 {
		t.Fatal("fixture must contain one verified explanation and evidence")
	}
	var text, stderr bytes.Buffer
	if code := writeLocalModelResult("text", result, &text, &stderr); code != result.ExitCode() || stderr.Len() != 0 {
		t.Fatalf("text exit=%d stderr=%s", code, &stderr)
	}
	finding := findings[0]
	if !bytes.Contains(text.Bytes(), []byte(finding.Message())) {
		t.Error("text omitted canonical verified explanation")
	}
	for _, id := range finding.EvidenceIDs() {
		if !bytes.Contains(text.Bytes(), []byte(id)) {
			t.Errorf("text omitted canonical verified evidence reference %q", id)
		}
	}
	encoded, err := localreview.EncodeResult(result)
	if err != nil || !bytes.Equal(encoded, captured) {
		t.Fatal("text rendering changed canonical result JSON")
	}
}
