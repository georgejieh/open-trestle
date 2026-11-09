package routehint

import (
	"os"
	"strings"
	"testing"
)

const consoleHint = "the review needs up to 14282 tokens (a byte-based upper bound: 10186 input plus 4096 output) but the route declares max_context_tokens 4097; raise max_context_tokens on the route and the model server's context length to at least 14282 (docs/named-local-runtimes.md#context-length)"

// The console test pins the same text for the same counts.
func TestContextShortfallMatchesConsole(t *testing.T) {
	if got := ContextShortfall(14282, 10186, 4096, 4097); got != consoleHint {
		t.Fatalf("hint = %q", got)
	}
	test, err := os.ReadFile("../../web/src/api.test.ts")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(test), `"`+consoleHint+`"`) {
		t.Fatal("web/src/api.test.ts no longer pins the shared hint text")
	}
}

// The console labels each reason with the same explanation.
func TestReasonTextMatchesConsole(t *testing.T) {
	app, err := os.ReadFile("../../web/src/App.tsx")
	if err != nil {
		t.Fatal(err)
	}
	for label, text := range map[string]string{"Route context insufficient: ": RouteContextInsufficient, "No eligible route: ": NoEligibleRoute} {
		if !strings.Contains(string(app), `"`+label+text+`"`) {
			t.Fatalf("web/src/App.tsx lacks %q", label+text)
		}
	}
}
