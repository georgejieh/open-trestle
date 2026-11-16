package context

import (
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
)

// A change that only removes a file is reviewed from the file's removed text:
// the packet holds its removed_lines source, which names no head line, the
// review snapshot has no head range, and the removed-file gap still marks the
// review as not full clearance.
func TestChangeThatOnlyRemovesAFileIsReviewable(t *testing.T) {
	gone := "package gone\n\nfunc Helper() int { return 1 }\n"
	result := assembleTextFallback(t, map[string][]byte{"gone.go": []byte(gone), "keep.txt": []byte("keep\n")}, map[string][]byte{"keep.txt": []byte("keep\n")})
	if result.failure != 0 || result.abstention != nil {
		t.Fatalf("removed-only change refused: failure=%s", result.failure)
	}
	removed, ok := result.sources["gone.go|removed_lines"]
	if !ok || string(removed.Content()) != gone || removed.HeadLine() != 0 {
		t.Fatalf("removed file text not supplied: %v", result.sources)
	}
	if rangeValue := removed.EvidenceItem().SourceRange(); rangeValue.StartLine() != 1 || rangeValue.EndLine() != 3 {
		t.Fatalf("removed file text at %d-%d", rangeValue.StartLine(), rangeValue.EndLine())
	}
	if ranges := result.assembly.Snapshot.Ranges(); len(ranges) != 0 {
		t.Fatalf("snapshot ranges=%v, want none", ranges)
	}
	if !result.omissionSet["gone.go|analysis_removed_file"] {
		t.Fatalf("removed-file gap lost: %v", result.omissionSet)
	}
	packet := result.assembly.Packet
	payload := result.request.Payload()
	if err := review.ValidateContextPacketRequest(payload, packet.Identity(), packet.ReviewScopeIdentity(), packet.MemoryScopeIdentity(), packet.MemoryIdentity(), result.assembly.Snapshot, packet.EvidenceItems()); err != nil {
		t.Fatalf("removed-only packet rejected: %v", err)
	}
	// A finding about the removed code is a base-side finding on its lines.
	document := `{"schema_version":2,"candidates":[{"title":"Removed helper","claim":"Callers of Helper no longer compile.","category":"correctness","severity_hint":"high","source_range":{"source_id":"` + removed.ReferenceID() + `","start_line":3,"end_line":3},"evidence_ids":["` + removed.ReferenceID() + `"]}]}`
	part, _ := provider.NewResponsePart(provider.ResponsePartStructuredData, "application/json", []byte(document))
	response, _ := provider.NewResponse(provider.CapabilityReviewV1, provider.ResponseFinishStop, []provider.ResponsePart{part}, provider.NewUnknownRouteTokenUsage())
	candidates, err := review.ParseContextCandidateBatch(response, payload, result.assembly.Snapshot, packet.EvidenceItems())
	if err != nil || len(candidates.Findings()) != 1 || candidates.Findings()[0].Side() != review.LineSideBase || candidates.Findings()[0].HeadLine() != 0 {
		t.Fatalf("base-side finding on a removed file: %v", err)
	}
	if _, err := review.NewVerificationRequestContext(payload, packet.Identity(), packet.ReviewScopeIdentity(), packet.MemoryScopeIdentity(), packet.MemoryIdentity(), result.assembly.Snapshot, packet.EvidenceItems(), candidates); err != nil {
		t.Fatalf("verification request for a removed file: %v", err)
	}
}

// A removed binary file has no reviewable text, so a change that only removes
// it still abstains.
func TestChangeThatOnlyRemovesAnUnreadableFileAbstains(t *testing.T) {
	result := assembleTextFallback(t, map[string][]byte{"blob.txt": []byte(strings.Repeat("\x00\x01", 8) + "\n"), "keep.txt": []byte("keep\n")}, map[string][]byte{"keep.txt": []byte("keep\n")})
	if result.abstention == nil || result.failure == 0 {
		t.Fatalf("unreadable removed file produced a packet: failure=%s", result.failure)
	}
}
