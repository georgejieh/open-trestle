package localreview

import "testing"

func TestLocalReadinessDispositionPreservesTerminalMeaning(t *testing.T) {
	tests := []struct {
		name                                        string
		verified, omitted, inconclusive, candidates uint32
		status, ci                                  string
	}{
		{"verified", 1, 0, 0, 1, "findings", "blocked"},
		{"omitted", 0, 1, 0, 0, "incomplete", "inconclusive"},
		{"inconclusive", 0, 0, 1, 1, "incomplete", "inconclusive"},
		{"no candidates", 0, 0, 0, 0, "no_candidates", "inconclusive"},
		{"rejected", 0, 0, 0, 1, "incomplete", "inconclusive"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			status, ci := localReadinessDisposition(test.verified, test.omitted, test.inconclusive, test.candidates)
			if status != test.status || ci != test.ci {
				t.Fatalf("disposition=(%s,%s) want=(%s,%s)", status, ci, test.status, test.ci)
			}
		})
	}
}
