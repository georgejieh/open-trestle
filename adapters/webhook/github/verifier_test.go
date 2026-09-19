package github

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/georgejieh/open-trestle/webhook"
	"strings"
	"testing"
	"time"
)

func TestVerifierAcceptsGitHubDocumentedSignatureVector(t *testing.T) {
	err := verifySignature(
		[]byte("It's a Secret to Everybody"),
		"sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17",
		[]byte("Hello, World!"),
	)
	if err != nil {
		t.Fatal(err)
	}
}

func TestNewVerifierRejectsUppercaseIdentity(t *testing.T) {
	if _, err := NewVerifier([]byte("01234567890123456789012345678901"), strings.Repeat("A", 64), map[string][]string{"pull_request": {"opened"}}); err == nil {
		t.Fatal("expected uppercase identity rejection")
	}
}

func TestVerifierFiltersSignatureEventAndAction(t *testing.T) {
	verifier, _ := NewVerifier([]byte("01234567890123456789012345678901"), strings.Repeat("a", 64), map[string][]string{"pull_request": {"opened", "synchronize"}})
	scope, _ := webhook.NewRepositoryScope("tenant-a", "repo-a")
	payload := []byte(`{"action":"opened"}`)
	signature := signatureForTest([]byte("01234567890123456789012345678901"), payload)
	tests := []struct {
		name, event, signature string
		payload                []byte
		want                   error
	}{{"signature", "pull_request", "sha256=" + strings.Repeat("0", 64), payload, ErrSignatureMismatch}, {"event", "push", signature, payload, ErrEventNotAllowed}, {"action", "pull_request", "", []byte(`{"action":"closed"}`), ErrActionNotAllowed}, {"duplicate action", "pull_request", signatureForTest([]byte("01234567890123456789012345678901"), []byte(`{"action":"opened","action":"synchronize"}`)), []byte(`{"action":"opened","action":"synchronize"}`), ErrInvalidPayload}}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			testSignature := test.signature
			if testSignature == "" {
				testSignature = signatureForTest([]byte("01234567890123456789012345678901"), test.payload)
			}
			got, err := verifier.Verify(scope, "delivery-1", test.event, testSignature, test.payload, time.UnixMilli(1))
			if !errors.Is(err, test.want) || got.Identity() != "" {
				t.Fatalf("delivery=(%#v,%v)", got, err)
			}
		})
	}
}

func signatureForTest(secret, payload []byte) string {
	digest := hmac.New(sha256.New, secret)
	_, _ = digest.Write(payload)
	return "sha256=" + hex.EncodeToString(digest.Sum(nil))
}

func TestVerifierCloseClearsSecretAndFailsClosed(t *testing.T) {
	verifier, err := NewVerifier([]byte("01234567890123456789012345678901"), strings.Repeat("a", 64), map[string][]string{"pull_request": {"opened"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.Close(); err != nil {
		t.Fatal(err)
	}
	for _, value := range verifier.secret {
		if value != 0 {
			t.Fatal("secret was not cleared")
		}
	}
	scope, _ := webhook.NewRepositoryScope("tenant-a", "repo-a")
	payload := []byte(`{"action":"opened"}`)
	if _, err := verifier.Verify(scope, "delivery-1", "pull_request", signatureForTest([]byte("01234567890123456789012345678901"), payload), payload, time.UnixMilli(1000)); !errors.Is(err, ErrInvalidVerifier) {
		t.Fatalf("verify error=%v", err)
	}
	if verifier.Identity() != "" {
		t.Fatal("closed verifier retained an active identity")
	}
	if err := verifier.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestVerifierCloseIsSafeDuringVerification(t *testing.T) {
	verifier, err := NewVerifier([]byte("01234567890123456789012345678901"), strings.Repeat("a", 64), map[string][]string{"pull_request": {"opened"}})
	if err != nil {
		t.Fatal(err)
	}
	scope, _ := webhook.NewRepositoryScope("tenant-a", "repo-a")
	payload := []byte(`{"action":"opened"}`)
	signature := signatureForTest([]byte("01234567890123456789012345678901"), payload)
	started := make(chan struct{})
	done := make(chan error)
	go func() {
		close(started)
		_, verifyErr := verifier.Verify(scope, "delivery-1", "pull_request", signature, payload, time.UnixMilli(1000))
		done <- verifyErr
	}()
	<-started
	if err := verifier.Close(); err != nil {
		t.Fatal(err)
	}
	if verifyErr := <-done; verifyErr != nil && !errors.Is(verifyErr, ErrInvalidVerifier) {
		t.Fatalf("verify error=%v", verifyErr)
	}
}
