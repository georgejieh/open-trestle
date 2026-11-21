package github

import (
	"errors"
	"strings"
	"testing"
)

func TestRuntimeWebhookSecretPolicyRejectsMalformedAndTrivialValues(t *testing.T) {
	valid := []byte("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
	if err := ValidateRuntimeSecret(valid); err != nil {
		t.Fatal(err)
	}
	for _, value := range [][]byte{
		[]byte("short"),
		[]byte(strings.Repeat("a", 64)),
		[]byte(strings.Repeat("0", 64)),
		[]byte(strings.Repeat("0123456789abcdef", 4)),
		[]byte("9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08"),
		[]byte(strings.Repeat("a", 63) + "b"),
	} {
		if err := ValidateRuntimeSecret(value); !errors.Is(err, ErrInvalidVerifier) {
			t.Fatalf("accepted %q: %v", value, err)
		}
	}
}
