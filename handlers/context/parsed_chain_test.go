package context

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/analysiscodec"
	"github.com/georgejieh/open-trestle/internal/changecodec"
	"github.com/georgejieh/open-trestle/internal/memorycodec"
	"github.com/georgejieh/open-trestle/internal/sourceoutput"
)

func TestParsedContextChainMatchesIndependentCodecs(t *testing.T) {
	authority, request, _, store, _, closeFixture, _ := newPacketWriterFixture(t, false, false, false, false, false)
	defer closeFixture()
	at := time.UnixMilli(230)
	h := &Handler{store: store, packetOnly: true}
	assembly, _, abstention, failure := h.assembleAt(context.Background(), request, at, at)
	if failure != 0 || abstention != nil || authority.ownerRoot == "" {
		t.Fatalf("assembly failure=%v", failure)
	}
	base, err := sourceoutput.ParseSnapshotArtifact(assembly.BaseSnapshotArtifact)
	if err != nil {
		t.Fatal(err)
	}
	head, err := sourceoutput.ParseSnapshotArtifact(assembly.HeadSnapshotArtifact)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(assembly.base, base) || !reflect.DeepEqual(assembly.head, head) {
		t.Fatal("assembly snapshots differ from independent decoding")
	}
	exposed := assembly.head.Files()
	if len(exposed) == 0 {
		t.Fatal("head snapshot has no files")
	}
	exposed[0] = sourceoutput.FileReference{}
	if !reflect.DeepEqual(assembly.head, head) {
		t.Fatal("snapshot accessor changed assembly")
	}
	change, err := changecodec.ParseResultArtifactWithSnapshots(assembly.ChangeArtifact, base, head)
	if err != nil {
		t.Fatal(err)
	}
	analysis, err := analysiscodec.ParseResultArtifactWithChange(assembly.AnalysisArtifact, assembly.ChangeArtifact, change)
	if err != nil {
		t.Fatal(err)
	}
	wantAnalysis, err := analysiscodec.ParseResultArtifact(assembly.AnalysisArtifact, assembly.ChangeArtifact, assembly.BaseSnapshotArtifact, assembly.HeadSnapshotArtifact)
	if err != nil || !reflect.DeepEqual(analysis, wantAnalysis) {
		t.Fatalf("analysis parity: %v", err)
	}
	memory, err := memorycodec.ParseResultArtifactWithChange(assembly.MemoryArtifact, assembly.ChangeArtifact, change)
	if err != nil {
		t.Fatal(err)
	}
	wantMemory, err := memorycodec.ParseResultArtifact(assembly.MemoryArtifact, assembly.ChangeArtifact, assembly.BaseSnapshotArtifact, assembly.HeadSnapshotArtifact)
	if err != nil || !reflect.DeepEqual(memory, wantMemory) {
		t.Fatalf("memory parity: %v", err)
	}
	for _, value := range []artifact.Artifact{{}, assembly.BaseSnapshotArtifact, assembly.HeadSnapshotArtifact, assembly.AnalysisArtifact} {
		if _, err := analysiscodec.ParseResultArtifactWithChange(assembly.AnalysisArtifact, value, change); !errors.Is(err, analysiscodec.ErrInvalidResult) {
			t.Fatalf("mismatched analysis change: %v", err)
		}
		if _, err := memorycodec.ParseResultArtifactWithChange(assembly.MemoryArtifact, value, change); !errors.Is(err, memorycodec.ErrInvalidResult) {
			t.Fatalf("mismatched memory change: %v", err)
		}
	}
	if _, err := analysiscodec.ParseResultArtifactWithChange(assembly.AnalysisArtifact, assembly.ChangeArtifact, changecodec.Result{}); !errors.Is(err, analysiscodec.ErrInvalidResult) {
		t.Fatal("zero change accepted by analysis")
	}
	if _, err := memorycodec.ParseResultArtifactWithChange(assembly.MemoryArtifact, assembly.ChangeArtifact, changecodec.Result{}); !errors.Is(err, memorycodec.ErrInvalidResult) {
		t.Fatal("zero change accepted by memory")
	}

	for _, field := range []string{"scope", "classification", "protection", "provenance", "payload", "expiry"} {
		t.Run(field, func(t *testing.T) {
			value := assembly.ChangeArtifact
			scope, classification, protection, provenance, payload, expiry := value.Scope(), value.Classification(), value.Protection(), value.Provenance(), value.Payload(), value.ExpiresAt()
			switch field {
			case "scope":
				scope, err = audit.NewReviewScope("tenant", "repository", "foreign")
			case "classification":
				classification = artifact.ClassificationPublic
			case "protection":
				protection = artifact.ProtectionEnvelopeEncrypted
			case "provenance":
				provenance = []string{base.Identity()}
			case "payload":
				payload = append(payload, ' ')
			case "expiry":
				expiry = expiry.Add(time.Millisecond)
			}
			if err != nil {
				t.Fatal(err)
			}
			foreign, err := artifact.New(scope, value.Kind(), value.MediaType(), classification, value.Origin(), protection, provenance, payload, value.CreatedAt(), expiry)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := analysiscodec.ParseResultArtifactWithChange(assembly.AnalysisArtifact, foreign, change); !errors.Is(err, analysiscodec.ErrInvalidResult) {
				t.Fatalf("foreign analysis chain accepted: %v", err)
			}
			if _, err := memorycodec.ParseResultArtifactWithChange(assembly.MemoryArtifact, foreign, change); !errors.Is(err, memorycodec.ErrInvalidResult) {
				t.Fatalf("foreign memory chain accepted: %v", err)
			}
		})
	}
	independentAllocations := testing.AllocsPerRun(5, func() {
		if _, err := changecodec.ParseResultArtifact(assembly.ChangeArtifact, assembly.BaseSnapshotArtifact, assembly.HeadSnapshotArtifact); err != nil {
			t.Fatal(err)
		}
		if _, err := analysiscodec.ParseResultArtifact(assembly.AnalysisArtifact, assembly.ChangeArtifact, assembly.BaseSnapshotArtifact, assembly.HeadSnapshotArtifact); err != nil {
			t.Fatal(err)
		}
		if _, err := memorycodec.ParseResultArtifact(assembly.MemoryArtifact, assembly.ChangeArtifact, assembly.BaseSnapshotArtifact, assembly.HeadSnapshotArtifact); err != nil {
			t.Fatal(err)
		}
		if _, err := sourceoutput.ParseSnapshotArtifact(assembly.HeadSnapshotArtifact); err != nil {
			t.Fatal(err)
		}
	})
	reusedAllocations := testing.AllocsPerRun(5, func() {
		base, err := sourceoutput.ParseSnapshotArtifact(assembly.BaseSnapshotArtifact)
		if err != nil {
			t.Fatal(err)
		}
		head, err := sourceoutput.ParseSnapshotArtifact(assembly.HeadSnapshotArtifact)
		if err != nil {
			t.Fatal(err)
		}
		change, err := changecodec.ParseResultArtifactWithSnapshots(assembly.ChangeArtifact, base, head)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := analysiscodec.ParseResultArtifactWithChange(assembly.AnalysisArtifact, assembly.ChangeArtifact, change); err != nil {
			t.Fatal(err)
		}
		if _, err := memorycodec.ParseResultArtifactWithChange(assembly.MemoryArtifact, assembly.ChangeArtifact, change); err != nil {
			t.Fatal(err)
		}
	})
	t.Logf("snapshot_files=%d independent_allocations=%g reused_allocations=%g", head.FileCount(), independentAllocations, reusedAllocations)
}
