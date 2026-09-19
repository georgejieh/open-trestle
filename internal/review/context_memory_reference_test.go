package review

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/internal/memory"
)

func TestContextMemoryReferencesPreserveNative128ByteBoundary(t *testing.T) {
	scope, err := memory.NewScope("tenant", "repository", "local-reviewer", memory.RefVisibilityExact, strings.Repeat("a", 64), []string{"."})
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{1, 64, 65, 78, 127, 128, 129} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			ref := strings.Repeat("r", n)
			if n == 78 {
				ref = "operator-note:" + strings.Repeat("a", 64)
			}
			_, nativeErr := memory.NewRecord(scope, memory.RecordInput{Kind: memory.RecordHumanFeedback, Taint: memory.TaintUserControlled, Path: "a.go", Text: "Operator advice, not acquired evidence.", EvidenceIDs: []string{ref}, ProducerIdentity: strings.Repeat("b", 64), ObservedAt: time.UnixMilli(1700000000000).UTC(), ValidFrom: time.UnixMilli(1700000000000).UTC(), ValidUntil: time.UnixMilli(1700000060000).UTC()})
			want := n <= 128
			if (nativeErr == nil) != want {
				t.Fatal("native memory reference boundary changed")
			}
			if got := validContextMemoryStrings([]string{ref}, 32, 128, true); got != want {
				t.Fatalf("memory wire reference bytes=%d accepted=%v want=%v", n, got, want)
			}
			if got := validCandidateReference(ref); got != (n <= 64) {
				t.Fatal("candidate reference boundary changed")
			}
		})
	}
	for _, ref := range []string{"", ":first", "_first", ".first", "-first", "a/b", "a b", "a\t", "a\n", "a\u0000", "é", "aé", "a\"b"} {
		if validContextMemoryStrings([]string{ref}, 32, 128, true) {
			t.Errorf("invalid reference accepted: %q", ref)
		}
	}
	for _, refs := range [][]string{{"a", "a"}, {"b", "a"}} {
		if validContextMemoryStrings(refs, 32, 128, true) {
			t.Fatal("duplicate or unsorted references accepted")
		}
	}
	refs := make([]string, 33)
	for i := range refs {
		refs[i] = fmt.Sprintf("ref-%02d", i)
	}
	if !validContextMemoryStrings(refs[:32], 32, 128, true) || validContextMemoryStrings(refs, 32, 128, true) {
		t.Fatal("reference count boundary changed")
	}
	if !validContextMemoryStrings([]string{"λ"}, 32, 256, false) {
		t.Fatal("symbol path incorrectly restricted to reference syntax")
	}
	if validContextMemoryStrings([]string{strings.Repeat("r", 65)}, 32, 64, true) {
		t.Fatal("explicit smaller bound ignored")
	}
}
