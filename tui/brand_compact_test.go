package tui

import (
	"strings"
	"testing"
)

// The compact mark keeps the full mark's identity: two X-braced towers at the
// same columns on every line, a cable leaving each tower, and the deck.
func TestCompactBridgeMarkKeepsTheTowersAligned(t *testing.T) {
	width := len(AmbassadorBridgeCompactMark[0])
	towers := -1
	for index, line := range AmbassadorBridgeCompactMark {
		for _, r := range line {
			if r > 127 {
				t.Fatalf("line %d is not ASCII: %q", index+1, line)
			}
		}
		if len(line) != width || width > minimumWidth/2 {
			t.Fatalf("line %d width %d (want %d, at most %d): %q", index+1, len(line), width, minimumWidth/2, line)
		}
		first, last := strings.Index(line, "|X|"), strings.LastIndex(line, "|X|")
		if first < 0 || last == first || strings.Count(line, "|X|") != 2 {
			t.Fatalf("line %d lacks two towers: %q", index+1, line)
		}
		if towers < 0 {
			towers = first*100 + last
		} else if first*100+last != towers {
			t.Fatalf("line %d moves a tower: %q", index+1, line)
		}
	}
	if !strings.Contains(AmbassadorBridgeCompactMark[0], `|X|\`) || !strings.Contains(AmbassadorBridgeCompactMark[0], `/|X|`) || !strings.HasPrefix(AmbassadorBridgeCompactMark[2], "===") {
		t.Fatalf("the compact mark lost its cables or deck: %q", AmbassadorBridgeCompactMark)
	}
}
