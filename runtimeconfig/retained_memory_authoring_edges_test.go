package runtimeconfig

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/provider"
)

func TestEncodeRetainedMemoryInputRejectsValidNonLoopbackPolicy(t *testing.T) {
	scope, repository, head, _, feedback, observed, until, _ := rmaInputs(t)
	remotePolicy := rmPolicy(t, provider.ProviderZonePrivateRemote, "https://provider-a.example/v1", false)
	encoded, err := EncodeRetainedMemoryInput(context.Background(), scope, repository, head, remotePolicy, feedback, observed, until)
	if !errors.Is(err, ErrInvalidRetainedMemoryInput) || encoded != nil {
		t.Fatalf("non-loopback policy encode result len=%d err=%v", len(encoded), err)
	}
}

func TestLoadProtectedRetainedMemoryFeedbackAcceptsEscapedValidSurrogatePair(t *testing.T) {
	feedback, err := LoadProtectedRetainedMemoryFeedback(context.Background(), rmFeedbackFile(t, bytesForRawJSON(`[{"path":"src/\ud83d\ude00.go","text":"keep \ud83d\ude00 note"}]`)))
	if err != nil {
		t.Fatal(err)
	}
	if len(feedback) != 1 || feedback[0].Path != "src/😀.go" || feedback[0].Text != "keep 😀 note" {
		t.Fatalf("valid surrogate pair did not round-trip: %#v", feedback)
	}
}

func TestLoadProtectedRetainedMemoryFeedbackRejects1025BytePath(t *testing.T) {
	tooLongPath := strings.Repeat("a", 1022) + ".go"
	if len(tooLongPath) != 1025 {
		t.Fatalf("path fixture length=%d", len(tooLongPath))
	}
	_, err := LoadProtectedRetainedMemoryFeedback(context.Background(), rmFeedbackFile(t, []byte(`[{"path":"`+tooLongPath+`","text":"ok"}]`)))
	rmError(t, err)
}

func TestLoadProtectedRetainedMemoryFeedbackRejectsKnownTextKeyAtDecodedScannerBudget(t *testing.T) {
	oversizedText := strings.Repeat("x", 32769)
	_, err := LoadProtectedRetainedMemoryFeedback(context.Background(), rmFeedbackFile(t, []byte(`[{"path":"a.go","text":"`+oversizedText+`"}]`)))
	rmError(t, err)
}
