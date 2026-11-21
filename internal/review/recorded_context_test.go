package review

import (
	"encoding/json"
	"fmt"
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
}

func BenchmarkParseRecordedContextRepositoryIndex(b *testing.B) {
	for _, fileCount := range []int{100, 10000} {
		b.Run(fmt.Sprintf("files_%d", fileCount), func(b *testing.B) {
			scope, memoryScope, _, source, retrieval := contextPacketFixture(b, "content")
			content := []byte(strings.Repeat("line\n", 9) + "content")
			selected, err := evidence.NewRepositoryFile("internal/example.go", content)
			if err != nil {
				b.Fatal(err)
			}
			files := []evidence.RepositoryFile{selected}
			refs := []sourceoutput.FileReference{sourceoutput.NewFileReference(selected.Path(), selected.Digest(), selected.SizeBytes(), strings.Repeat("7", 64))}
			for i := 1; i < fileCount; i++ {
				file, err := evidence.NewRepositoryFile(fmt.Sprintf("unselected/%05d.go", i), []byte("package example\n"))
				if err != nil {
					b.Fatal(err)
				}
				files = append(files, file)
				refs = append(refs, sourceoutput.NewFileReference(file.Path(), file.Digest(), file.SizeBytes(), fmt.Sprintf("%064x", i)))
			}
			manifest, err := evidence.NewRepositoryManifest(files)
			if err != nil {
				b.Fatal(err)
			}
			snapshot, err := NewAcquiredReviewPipelineSnapshot(scope.ReviewRunID(), manifest, []evidence.SourceRange{source.EvidenceItem().SourceRange()})
			if err != nil {
				b.Fatal(err)
			}
			limits, _ := NewContextLimits(1<<20, 5)
			packet, err := NewContextPacket(scope, memoryScope, snapshot, ContextTaskCandidateGeneration, []ContextSource{source}, retrieval, limits)
			if err != nil {
				b.Fatal(err)
			}
			request, err := packet.ProviderRequest()
			if err != nil {
				b.Fatal(err)
			}
			head, err := sourceoutput.NewSnapshot(strings.Repeat("c", 64), strings.Repeat("1", 64), strings.Repeat("2", 64), strings.Repeat("3", 64), strings.Repeat("4", 64), strings.Repeat("5", 64), strings.Repeat("6", 64), manifest.Identity(), refs)
			if err != nil {
				b.Fatal(err)
			}
			encoded, err := sourceoutput.EncodeSnapshot(head)
			if err != nil {
				b.Fatal(err)
			}
			value, err := artifact.New(scope, artifact.KindSourceSnapshot, "application/json", artifact.ClassificationConfidential, artifact.OriginRepository, artifact.ProtectionProcessPrivate, []string{strings.Repeat("3", 64)}, encoded, time.UnixMilli(10), time.UnixMilli(1000))
			if err != nil {
				b.Fatal(err)
			}
			head, err = sourceoutput.ParseSnapshotArtifact(value)
			if err != nil {
				b.Fatal(err)
			}
			payload := request.Payload()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				result, err := ParseRecordedContext(payload, scope, head)
				if err != nil || result.Selected() != 1 || result.Snapshot().Identity() != snapshot.Identity() {
					b.Fatalf("recorded context changed: %v", err)
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(fileCount), "indexed_files/op")
		})
	}
}
