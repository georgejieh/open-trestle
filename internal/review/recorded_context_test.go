package review

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/memory"
	"github.com/georgejieh/open-trestle/internal/sourceoutput"
)

func TestParseRecordedContextBindsCanonicalHeadSnapshot(t *testing.T) {
	scope, memoryScope, _, source, retrieval := contextPacketFixture(t, "content")
	content := []byte(strings.Repeat("line\n", 9) + "content")
	file, _ := evidence.NewRepositoryFile("internal/example.go", content)
	manifest, _ := evidence.NewRepositoryManifest([]evidence.RepositoryFile{file})
	snapshot, err := NewAcquiredReviewPipelineSnapshot(scope.ReviewRunID(), manifest, []evidence.SourceRange{source.EvidenceItem().SourceRange()})
	if err != nil {
		t.Fatal(err)
	}
	limits, _ := NewContextLimits(1<<20, 5)
	omission, _ := NewCountedContextSourceOmission("other.bin", 0, 0, "semantic_candidate_limit", 172)
	packet, err := NewContextPacketWithAccounting(scope, memoryScope, snapshot, ContextTaskCandidateGeneration, []ContextSource{source}, []memory.LexicalRetrieval{retrieval}, []ContextSourceOmission{omission}, limits)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := packet.ProviderRequest()
	head, err := sourceoutput.NewSnapshot(strings.Repeat("c", 64), strings.Repeat("1", 64), strings.Repeat("2", 64), strings.Repeat("3", 64), strings.Repeat("4", 64), strings.Repeat("5", 64), strings.Repeat("6", 64), manifest.Identity(), []sourceoutput.FileReference{sourceoutput.NewFileReference(file.Path(), file.Digest(), file.SizeBytes(), strings.Repeat("7", 64))})
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := sourceoutput.EncodeSnapshot(head)
	value, err := artifact.New(scope, artifact.KindSourceSnapshot, "application/json", artifact.ClassificationConfidential, artifact.OriginRepository, artifact.ProtectionProcessPrivate, []string{strings.Repeat("3", 64)}, encoded, time.UnixMilli(10), time.UnixMilli(1000))
	if err != nil {
		t.Fatal(err)
	}
	head, err = sourceoutput.ParseSnapshotArtifact(value)
	if err != nil {
		t.Fatal(err)
	}
	invalidHead, err := sourceoutput.NewSnapshot(strings.Repeat("c", 64), strings.Repeat("1", 64), strings.Repeat("2", 64), strings.Repeat("3", 64), strings.Repeat("4", 64), strings.Repeat("5", 64), strings.Repeat("6", 64), strings.Repeat("9", 64), head.Files())
	if err != nil {
		t.Fatal(err)
	}
	invalidEncoded, _ := sourceoutput.EncodeSnapshot(invalidHead)
	invalidValue, err := artifact.New(scope, artifact.KindSourceSnapshot, "application/json", artifact.ClassificationConfidential, artifact.OriginRepository, artifact.ProtectionProcessPrivate, []string{strings.Repeat("3", 64)}, invalidEncoded, time.UnixMilli(10), time.UnixMilli(1000))
	if err != nil {
		t.Fatal(err)
	}
	invalidHead, err = sourceoutput.ParseSnapshotArtifact(invalidValue)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseRecordedContext(request.Payload(), scope, invalidHead); err == nil {
		t.Fatal("head manifest metadata mismatch accepted")
	}
	recorded, err := ParseRecordedContext(request.Payload(), scope, head)
	if err != nil || recorded.Analyzed() != 173 || recorded.Selected() != 1 || recorded.Omitted() != 172 || recorded.Identity() != packet.Identity() || recorded.Snapshot().Identity() != snapshot.Identity() {
		t.Fatalf("recorded=%#v err=%v", recorded, err)
	}
	for _, mutate := range []func(*contextPacketWire){
		func(w *contextPacketWire) { w.SourceCoverage.Selected = 0 },
		func(w *contextPacketWire) {
			w.SourceCoverage.Available = 129
			w.SourceCoverage.Analyzed = 301
			w.SourceCoverage.Omitted = 300
		},
		func(w *contextPacketWire) { w.Sources[0].Content = "tamper" },
		func(w *contextPacketWire) { w.SnapshotIdentity = strings.Repeat("9", 64) },
		func(w *contextPacketWire) { w.SourceOmissions[0].Count = 0 },
		func(w *contextPacketWire) { w.Memory.RetrievalIdentity = strings.Repeat("9", 64) },
		func(w *contextPacketWire) { w.SchemaVersion = 999 },
	} {
		wire, _ := decodeGenerationContextWire(request.Payload())
		mutate(&wire)
		payload, _ := json.Marshal(wire)
		if got, err := ParseRecordedContext(payload, scope, head); err == nil || got.Identity() != "" {
			t.Fatalf("corrupt packet accepted: %v", err)
		}
	}
	if _, err := ParseRecordedContext(append(request.Payload(), ' '), scope, head); err == nil {
		t.Fatal("noncanonical packet accepted")
	}
	legacy, _ := decodeGenerationContextWire(request.Payload())
	legacy.SchemaVersion = 2
	legacy.Instructions = ""
	legacy.OutputSchema = nil
	legacyPayload, _ := json.Marshal(legacy)
	legacyResult, err := ParseRecordedContext(legacyPayload, scope, head)
	sum := sha256.Sum256(legacyPayload)
	if err != nil || legacyResult.Identity() != hex.EncodeToString(sum[:]) {
		t.Fatalf("legacy readback: %v", err)
	}
}
