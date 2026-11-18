package pinnedpatterns

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the host's pinned pattern table from the ruleset")

// tablePath is the table the helper embeds, in the scanner module.
var tablePath = filepath.Join("..", "..", "..", "internal", "regexhost", "pinned-patterns.json")

func TestHostTableEqualsRulesetPatterns(t *testing.T) {
	patterns, err := Collect()
	if err != nil {
		t.Fatal(err)
	}
	if len(patterns) == 0 {
		t.Fatal("ruleset produced no patterns")
	}
	for _, pattern := range patterns {
		if len(pattern) == 0 || len(pattern) > 4096 {
			t.Fatalf("pattern of %d bytes is outside the host bound", len(pattern))
		}
	}
	want, err := Encode(patterns)
	if err != nil {
		t.Fatal(err)
	}
	if *update {
		if err := os.WriteFile(tablePath, want, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(tablePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s differs from the ruleset's %d patterns; rerun this test with -update and update PinnedPatternsSHA256", tablePath, len(patterns))
	}
}

func TestCollectIsDeterministic(t *testing.T) {
	first, err := Collect()
	if err != nil {
		t.Fatal(err)
	}
	second, err := Collect()
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != len(second) {
		t.Fatalf("collected %d then %d patterns", len(first), len(second))
	}
	for index := range first {
		if first[index] != second[index] {
			t.Fatalf("pattern %d differs between runs", index)
		}
	}
}
