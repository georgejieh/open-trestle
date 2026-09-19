package config_test

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/review"
)

func TestLocalModelReviewInvestigationPolicyExample(t *testing.T) {
	document, err := os.ReadFile(filepath.Join("..", "..", "docs", "local-model-review.md"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(document)
	if !strings.Contains(text, "--investigation-policy /protected/investigation.json") {
		t.Fatal("missing investigation opt-in documentation")
	}
	pattern := regexp.MustCompile(`(?m)^printf '%s' '([^'\r\n]+)' > /protected/investigation\.json$`)
	matches := pattern.FindAllStringSubmatch(text, -1)
	if len(matches) != 1 {
		t.Fatalf("canonical policy examples=%d, want one", len(matches))
	}
	encoded := []byte(matches[0][1])
	policy, err := review.ParseInvestigationPolicy(encoded)
	if err != nil {
		t.Fatalf("documented policy rejected by actual parser: %v", err)
	}
	roundTrip, err := review.EncodeInvestigationPolicy(policy)
	if err != nil || !bytes.Equal(roundTrip, encoded) {
		t.Fatalf("documented policy is not canonical: %v", err)
	}
	if policy.MaxModelTurns() != 5 || policy.MaxToolCalls() != 3 || policy.MaxCostMicroUSD() != 1000000 {
		t.Fatal("policy example differs from the documented turn/tool/cost explanation")
	}
}

func TestLocalModelReviewRetainedMemoryAuthoringDocumentation(t *testing.T) {
	document, err := os.ReadFile(filepath.Join("..", "..", "docs", "local-model-review.md"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(document)
	for _, fragment := range []string{
		"trestle local-git retained-memory-input",
		"--feedback-input",
		"--output",
		"--valid-for",
		"--egress local-only",
		"trestle local-git model-review",
		"--retained-memory-input",
	} {
		if !strings.Contains(text, fragment) {
			t.Fatalf("missing retained-memory authoring documentation fragment %q", fragment)
		}
	}
	if strings.Contains(text, "retained-memory-input --objects-root") || strings.Contains(text, "> /protected/retained-memory-input.json") || strings.Contains(text, "--provider") {
		t.Fatal("retained-memory authoring documentation grants source-root, stdout-redirection, or provider authority")
	}
}
