package review

import (
	"testing"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

func TestNewReviewRequestAcceptsValidLocalSnapshot(t *testing.T) {
	sourceRange, err := evidence.NewSourceRange("internal/review/review.go", 1, 12)
	if err != nil {
		t.Fatalf("evidence.NewSourceRange() error = %v", err)
	}
	snapshot, err := NewReviewSnapshot("workspace", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", []evidence.SourceRange{sourceRange})
	if err != nil {
		t.Fatalf("NewReviewSnapshot() error = %v", err)
	}

	request, err := NewReviewRequest("review-1", snapshot)
	if err != nil {
		t.Fatalf("NewReviewRequest() error = %v", err)
	}

	if request.ID() != "review-1" {
		t.Fatalf("ID() = %q, want %q", request.ID(), "review-1")
	}
	if request.Snapshot().Workspace() != "workspace" {
		t.Fatalf("Snapshot().Workspace() = %q, want %q", request.Snapshot().Workspace(), "workspace")
	}
	if request.Snapshot().Revision() != "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" {
		t.Fatalf("Snapshot().Revision() = %q, want %q", request.Snapshot().Revision(), "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	}
	if request.Snapshot().Identity() == "" {
		t.Fatal("Snapshot().Identity() is empty")
	}
	if got := request.Snapshot().Ranges(); len(got) != 1 || got[0] != sourceRange {
		t.Fatalf("Snapshot().Ranges() = %#v, want %#v", got, []evidence.SourceRange{sourceRange})
	}
}

func TestNewReviewSnapshotRejectsInvalidRevision(t *testing.T) {
	sourceRange, err := evidence.NewSourceRange("main.go", 1, 1)
	if err != nil {
		t.Fatalf("evidence.NewSourceRange() error = %v", err)
	}

	for _, revision := range []string{
		"revision",
		"ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789",
		"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
	} {
		if _, err := NewReviewSnapshot("workspace", revision, []evidence.SourceRange{sourceRange}); err == nil {
			t.Errorf("NewReviewSnapshot() error = nil for revision %q, want validation error", revision)
		}
	}
}

func TestReviewContractsRejectMissingIdentityAndSnapshotData(t *testing.T) {
	sourceRange, err := evidence.NewSourceRange("main.go", 1, 1)
	if err != nil {
		t.Fatalf("evidence.NewSourceRange() error = %v", err)
	}

	testCases := []struct {
		name      string
		workspace string
		revision  string
		ranges    []evidence.SourceRange
	}{
		{name: "missing workspace", revision: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", ranges: []evidence.SourceRange{sourceRange}},
		{name: "missing revision", workspace: "workspace", ranges: []evidence.SourceRange{sourceRange}},
		{name: "missing ranges", workspace: "workspace", revision: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
		{name: "invalid range", workspace: "workspace", revision: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", ranges: []evidence.SourceRange{{}}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := NewReviewSnapshot(testCase.workspace, testCase.revision, testCase.ranges); err == nil {
				t.Fatal("NewReviewSnapshot() error = nil, want validation error")
			}
		})
	}

	snapshot, err := NewReviewSnapshot("workspace", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", []evidence.SourceRange{sourceRange})
	if err != nil {
		t.Fatalf("NewReviewSnapshot() error = %v", err)
	}
	if _, err := NewReviewRequest("", snapshot); err == nil {
		t.Fatal("NewReviewRequest() error = nil, want missing ID error")
	}
	if _, err := NewReviewRequest("review-1", ReviewSnapshot{}); err == nil {
		t.Fatal("NewReviewRequest() error = nil, want invalid snapshot error")
	}
	forged := snapshot
	forged.identity = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	if forged.Validate() == nil {
		t.Fatal("forged snapshot identity accepted")
	}
	if _, err := NewReviewRequest("review-1", forged); err == nil {
		t.Fatal("request accepted forged snapshot")
	}
}
