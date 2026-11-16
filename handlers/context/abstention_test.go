package context

import (
	"fmt"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/review"
)

func TestContextAbstentionOmissionBounds(t *testing.T) {
	one, err := review.NewCountedContextSourceOmission("a.go", 0, 0, "semantic_candidate_limit", 32768)
	if err != nil {
		t.Fatal(err)
	}
	two, err := review.NewCountedContextSourceOmission("b.go", 0, 0, "semantic_candidate_limit", 32768)
	if err != nil {
		t.Fatal(err)
	}
	values, count, err := canonicalContextAbstentionOmissions([]review.ContextSourceOmission{two, one})
	if err != nil || count != 65536 || len(values) != 2 || values[0].Path != "a.go" || values[1].Path != "b.go" {
		t.Fatalf("boundary values=%+v count=%d err=%v", values, count, err)
	}
	if _, err = review.NewCountedContextSourceOmission("c.go", 0, 0, "semantic_candidate_limit", 32769); err == nil {
		t.Fatal("per-omission 32769 accepted")
	}
	extra, _ := review.NewContextSourceOmission("c.go", 0, 0, "source_size_limit")
	if _, _, err = canonicalContextAbstentionOmissions([]review.ContextSourceOmission{one, two, extra}); err == nil {
		t.Fatal("aggregate 65537 accepted")
	}
	entries := make([]review.ContextSourceOmission, 16384)
	for index := range entries {
		entry, err := review.NewContextSourceOmission(fmt.Sprintf("path-%05d.go", index), 0, 0, "source_size_limit")
		if err != nil {
			t.Fatal(err)
		}
		entries[index] = entry
	}
	if got, count, err := canonicalContextAbstentionOmissions(entries); err != nil || count != 16384 || len(got) != 16384 {
		t.Fatalf("16384-entry boundary count=%d entries=%d err=%v", count, len(got), err)
	}
	entries = append(entries, extra)
	if _, _, err := canonicalContextAbstentionOmissions(entries); err == nil {
		t.Fatal("16385 entries accepted")
	}
	duplicate, _ := review.NewContextSourceOmission("z.go", 2, 2, "packet_budget")
	got, count, err := canonicalContextAbstentionOmissions([]review.ContextSourceOmission{duplicate, duplicate})
	if err != nil || count != 2 || len(got) != 1 || got[0].Count != 2 {
		t.Fatalf("duplicate count=%d entries=%+v err=%v", count, got, err)
	}
	if strings.Contains(fmt.Sprintf("%+v", got), "content") {
		t.Fatal("abstention metadata contains content")
	}
}
