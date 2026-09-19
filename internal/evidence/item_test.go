package evidence

import "testing"

func TestNewEvidenceItemAcceptsContentAddressedSourceEvidence(t *testing.T) {
	sourceRange, err := NewSourceRange("main.go", 2, 4)
	if err != nil {
		t.Fatalf("NewSourceRange() error = %v", err)
	}
	digest := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	item, err := NewEvidenceItem("evidence-1", EvidenceKindSource, digest, sourceRange)
	if err != nil {
		t.Fatalf("NewEvidenceItem() error = %v", err)
	}

	if item.ID() != "evidence-1" || item.Kind() != EvidenceKindSource || item.Digest() != digest {
		t.Fatalf("NewEvidenceItem() = (%q, %q, %q), want supplied values", item.ID(), item.Kind(), item.Digest())
	}
	if item.SourceRange() != sourceRange {
		t.Fatalf("SourceRange() = %#v, want %#v", item.SourceRange(), sourceRange)
	}
}

func TestNewEvidenceItemRejectsInvalidIdentityKindDigestAndRange(t *testing.T) {
	sourceRange, err := NewSourceRange("main.go", 1, 1)
	if err != nil {
		t.Fatalf("NewSourceRange() error = %v", err)
	}
	digest := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	testCases := []struct {
		name        string
		id          string
		kind        EvidenceKind
		digest      string
		sourceRange SourceRange
	}{
		{name: "missing identity", kind: EvidenceKindSource, digest: digest, sourceRange: sourceRange},
		{name: "unknown kind", id: "evidence-1", kind: EvidenceKind("unknown"), digest: digest, sourceRange: sourceRange},
		{name: "short digest", id: "evidence-1", kind: EvidenceKindSource, digest: "0123", sourceRange: sourceRange},
		{name: "uppercase digest", id: "evidence-1", kind: EvidenceKindSource, digest: "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789", sourceRange: sourceRange},
		{name: "missing range", id: "evidence-1", kind: EvidenceKindSource, digest: digest},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := NewEvidenceItem(testCase.id, testCase.kind, testCase.digest, testCase.sourceRange); err == nil {
				t.Fatal("NewEvidenceItem() error = nil, want validation error")
			}
		})
	}
}
