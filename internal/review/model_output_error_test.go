package review

import (
	"errors"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/provider"
)

// Every document below is a synthetic fixture. A parse failure the model's
// answer caused is marked ErrModelOutputInvalid and keeps its specific error;
// a host input that fails its own check is never marked.

func stoppedResponse(t *testing.T, kind provider.ResponsePartKind, payload string) provider.Response {
	t.Helper()
	mediaType := "text/plain; charset=utf-8"
	if kind == provider.ResponsePartStructuredData {
		mediaType = "application/json"
	}
	part, err := provider.NewResponsePart(kind, mediaType, []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	response, err := provider.NewResponse(provider.CapabilityReviewV1, provider.ResponseFinishStop, []provider.ResponsePart{part}, provider.NewUnknownRouteTokenUsage())
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func TestCandidateParseMarksFailuresTheAnswerCaused(t *testing.T) {
	_, snapshot, items := candidateFixture(t, validCandidateDocument())
	wrapped := "<|start|>assistant<|channel|>final <|constrain|>json<|message|>" + validCandidateDocument() + "<|return|>"
	for _, test := range []struct {
		name     string
		response provider.Response
		specific error
	}{
		{"chat-template tokens around the JSON", stoppedResponse(t, provider.ResponsePartAssistantText, wrapped), ErrInvalidCandidateResponseEnvelope},
		{"a control character inside a JSON string", stoppedResponse(t, provider.ResponsePartAssistantText, strings.Replace(validCandidateDocument(), "discarded.", "discarded.\x01", 1)), ErrInvalidCandidateResponseEnvelope},
		{"a refusal", stoppedResponse(t, provider.ResponsePartRefusal, "I cannot review this."), ErrInvalidCandidateResponseEnvelope},
		{"the wrong shape", stoppedResponse(t, provider.ResponsePartStructuredData, `{"schema_version":1,"findings":[]}`), ErrInvalidCandidateDocumentShape},
		{"a location outside the request", stoppedResponse(t, provider.ResponsePartStructuredData, strings.Replace(validCandidateDocument(), `"start_line":12,"end_line":13`, `"start_line":21,"end_line":21`, 1)), ErrCandidateRangeNotSupported},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseCandidateBatch(test.response, snapshot, items)
			if !errors.Is(err, ErrModelOutputInvalid) || !errors.Is(err, test.specific) {
				t.Fatalf("err=%v, want %v marked as a model output failure", err, test.specific)
			}
		})
	}
	// A host evidence set that fails its own check is not the model's doing.
	response, _, _ := candidateFixture(t, validCandidateDocument())
	duplicate := append(append([]evidence.EvidenceItem{}, items...), items...)
	if _, err := ParseCandidateBatch(response, snapshot, duplicate); err == nil || errors.Is(err, ErrModelOutputInvalid) {
		t.Fatalf("a host input failure was marked: %v", err)
	}
	if _, err := ParseCandidateBatch(response, ReviewSnapshot{}, items); err == nil || errors.Is(err, ErrModelOutputInvalid) {
		t.Fatalf("an invalid snapshot was marked: %v", err)
	}
	if _, err := ParseCandidateBatch(response, snapshot, items); err != nil {
		t.Fatalf("a valid answer was refused: %v", err)
	}
}

func TestVerificationParseMarksFailuresTheAnswerCaused(t *testing.T) {
	_, candidates, items := verificationFixture(t, `{"schema_version":1,"verdicts":[]}`)
	document := validVerificationDocument(candidates.Findings()[0].Identity())
	for _, test := range []struct {
		name     string
		response provider.Response
		specific error
	}{
		{"chat-template tokens around the JSON", stoppedResponse(t, provider.ResponsePartAssistantText, "<|channel|>final<|message|>"+document+"<|return|>"), ErrInvalidVerificationResponseEnvelope},
		{"the wrong shape", stoppedResponse(t, provider.ResponsePartStructuredData, `{"schema_version":1,"results":[]}`), ErrInvalidVerificationDocumentShape},
		{"a missing verdict", stoppedResponse(t, provider.ResponsePartStructuredData, `{"schema_version":1,"verdicts":[]}`), ErrVerificationCandidateSetMismatch},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseVerificationBatch(test.response, candidates, items)
			if !errors.Is(err, ErrModelOutputInvalid) || !errors.Is(err, test.specific) {
				t.Fatalf("err=%v, want %v marked as a model output failure", err, test.specific)
			}
		})
	}
	valid := stoppedResponse(t, provider.ResponsePartStructuredData, document)
	if _, err := ParseVerificationBatch(valid, CandidateBatch{}, items); err == nil || errors.Is(err, ErrModelOutputInvalid) {
		t.Fatalf("an invalid candidate batch was marked: %v", err)
	}
	if _, err := ParseVerificationBatch(valid, candidates, items); err != nil {
		t.Fatalf("a valid answer was refused: %v", err)
	}
}
