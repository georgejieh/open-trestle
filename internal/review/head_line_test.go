package review

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/memory"
)

// headLinePacket is the removed-guard packet with the removed_lines source
// naming the given head line of its deletion point.
func headLinePacket(t *testing.T, headLine int) (ContextPacket, ReviewSnapshot, []byte) {
	t.Helper()
	reviewScope, _ := audit.NewReviewScope("tenant", "repository", "review-run")
	memoryScope, _ := memory.NewScope("tenant", "repository", "actor", memory.RefVisibilityExact, strings.Repeat("a", 64), []string{"."})
	window := boundSource(t, ContextStageChangedHunk, "calc.go", removedGuardHead, 1, 5)
	plain := boundSource(t, ContextStageRemovedLines, "calc.go", removedGuardBase, 4, 6)
	removed, err := NewRemovedLinesContextSource(plain.EvidenceItem(), plain.Content(), plain.SliceBinding(), headLine)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := NewReviewSnapshot("workspace", strings.Repeat("b", 64), []evidence.SourceRange{window.EvidenceItem().SourceRange()})
	if err != nil {
		t.Fatal(err)
	}
	query, _ := memory.NewLexicalQuery(memoryScope, "calc.go", nil, nil, time.UnixMilli(200), 5)
	retrieval, err := memory.NewLexicalIndex().Search(context.Background(), memoryScope, query)
	if err != nil {
		t.Fatal(err)
	}
	limits, _ := NewContextLimits(1<<20, 5)
	packet, err := NewContextPacketWithAccounting(reviewScope, memoryScope, snapshot, ContextTaskCandidateGeneration, []ContextSource{removed, window}, []memory.LexicalRetrieval{retrieval}, nil, limits)
	if err != nil {
		t.Fatal(err)
	}
	request, err := packet.ProviderRequest()
	if err != nil {
		t.Fatal(err)
	}
	return packet, snapshot, request.Payload()
}

func TestRemovedLinesHeadLineIsBoundToItsDeletionPoint(t *testing.T) {
	packet, snapshot, payload := headLinePacket(t, 3)
	if !bytes.Contains(payload, []byte(`"head_line":3`)) || bytes.Count(payload, []byte(`"head_line"`)) != 1 {
		t.Fatalf("head line not recorded once on the removed_lines source: %s", payload)
	}
	validate := func(payload []byte) error {
		return ValidateRecordedContextPacketRequest(payload, modelContractDigest(payload), packet.ReviewScopeIdentity(), packet.MemoryScopeIdentity(), packet.MemoryIdentity(), snapshot, packet.EvidenceItems())
	}
	if err := ValidateContextPacketRequest(payload, packet.Identity(), packet.ReviewScopeIdentity(), packet.MemoryScopeIdentity(), packet.MemoryIdentity(), snapshot, packet.EvidenceItems()); err != nil {
		t.Fatalf("head line inside the deletion-point window rejected: %v", err)
	}
	// A head line outside every changed hunk of the file names no deletion
	// point of this packet.
	_, outsideSnapshot, outside := headLinePacket(t, 9)
	if outsideSnapshot.Identity() != snapshot.Identity() || validate(outside) == nil {
		t.Fatal("head line outside the deletion-point window accepted")
	}
	// Only a removed_lines source carries a head line.
	onHead := bytes.Replace(payload, []byte(`"end_line":5,"risk_flags"`), []byte(`"end_line":5,"head_line":3,"risk_flags"`), 1)
	if bytes.Equal(onHead, payload) || validate(onHead) == nil {
		t.Fatal("head line on a changed_hunk source accepted")
	}
	window := boundSource(t, ContextStageChangedHunk, "calc.go", removedGuardHead, 1, 5)
	if _, err := NewRemovedLinesContextSource(window.EvidenceItem(), window.Content(), window.SliceBinding(), -1); !errors.Is(err, ErrInvalidContextSource) {
		t.Fatalf("negative head line accepted: %v", err)
	}
}
