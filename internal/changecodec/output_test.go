package changecodec

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/sourceoutput"
)

func deletionResult(t *testing.T, before, after string) (Result, artifact.Artifact, artifact.Artifact, evidence.RepositoryFileDeltaExecution) {
	t.Helper()
	repository, _ := evidence.NewRepositoryIdentity("github.com", []string{"owner"}, "repo")
	baseRevision, _ := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("1", 40))
	headRevision, _ := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("2", 40))
	baseFile, _ := evidence.NewRepositoryFile("a.txt", []byte(before))
	headFile, _ := evidence.NewRepositoryFile("a.txt", []byte(after))
	baseManifest, _ := evidence.NewRepositoryManifest([]evidence.RepositoryFile{baseFile})
	headManifest, _ := evidence.NewRepositoryManifest([]evidence.RepositoryFile{headFile})
	delta, err := evidence.NewRepositoryManifestDelta(baseManifest, headManifest)
	if err != nil || len(delta.Entries()) != 1 {
		t.Fatalf("delta: %v", err)
	}
	execution, err := evidence.ExecuteRepositoryFileDelta(delta.Entries()[0], evidence.RepositoryFileDeltaContent{Present: true, Content: []byte(before)}, evidence.RepositoryFileDeltaContent{Present: true, Content: []byte(after)})
	if err != nil || execution.Status() != evidence.RepositoryFileDeltaExecutionStatusSupported || len(execution.FileChange().ChangedRanges()) != 0 {
		t.Fatalf("expected supported zero-range execution: %v", err)
	}
	scope, _ := audit.NewReviewScope("tenant", "repository", "deletion")
	snapshot := func(file evidence.RepositoryFile, manifest evidence.RepositoryManifest, revision evidence.RevisionIdentity, marker string) (artifact.Artifact, sourceoutput.Snapshot) {
		t.Helper()
		index, err := sourceoutput.NewSnapshot("", strings.Repeat(marker, 64), strings.Repeat(marker, 64), strings.Repeat(marker, 64), repository.Identity(), revision.Identity(), strings.Repeat("a", 64), manifest.Identity(), []sourceoutput.FileReference{sourceoutput.NewFileReference(file.Path(), file.Digest(), file.SizeBytes(), strings.Repeat(marker, 64))})
		if err != nil {
			t.Fatal(err)
		}
		payload, err := sourceoutput.EncodeSnapshot(index)
		if err != nil {
			t.Fatal(err)
		}
		value, err := artifact.New(scope, artifact.KindSourceSnapshot, "application/json", artifact.ClassificationConfidential, artifact.OriginRepository, artifact.ProtectionProcessPrivate, []string{strings.Repeat(marker, 64)}, payload, time.UnixMilli(100), time.UnixMilli(10000))
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := sourceoutput.ParseSnapshotArtifact(value)
		if err != nil {
			t.Fatal(err)
		}
		return value, parsed
	}
	base, baseSnapshot := snapshot(baseFile, baseManifest, baseRevision, "b")
	head, headSnapshot := snapshot(headFile, headManifest, headRevision, "c")
	result, err := NewResult(base, head, baseSnapshot, headSnapshot, repository, baseRevision, headRevision, delta, []evidence.RepositoryFileDeltaExecution{execution}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return result, base, head, execution
}

func changeArtifact(t *testing.T, result Result, base, head artifact.Artifact, payload []byte) artifact.Artifact {
	t.Helper()
	value, err := artifact.New(base.Scope(), artifact.KindChangeModel, "application/json", base.Classification(), artifact.OriginDeterministicTool, base.Protection(), []string{base.Identity(), head.Identity()}, payload, time.UnixMilli(200), base.ExpiresAt())
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestNoChangedHeadLinesProjectionAndVersionedRejections(t *testing.T) {
	for _, tc := range []struct{ name, before, after string }{
		{"first", "guard\nkeep\n", "keep\n"},
		{"interior", "first\nguard\nlast\n", "first\nlast\n"},
		{"last", "keep\nguard\n", "keep\n"},
		{"empty", "guard\n", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, base, head, execution := deletionResult(t, tc.before, tc.after)
			entry := result.entries[0]
			if result.SchemaVersion() != 2 || entry.status != "unsupported" || entry.reason != "no_changed_head_lines" || entry.kind != "modified" || len(entry.ranges) != 0 || entry.fileChangeIdentity != "" || entry.lineMapIdentity != "" || entry.executionIdentity != execution.Identity() || entry.baseIdentity == "" || entry.headIdentity == "" || entry.headSize != len(tc.after) {
				t.Fatalf("invalid review omission: %#v", entry)
			}
			if execution.Status() != evidence.RepositoryFileDeltaExecutionStatusSupported || execution.FileChange().Identity() == "" || execution.LineMap().Identity() == "" {
				t.Fatal("core execution evidence changed")
			}
			payload, err := EncodeResult(result)
			if err != nil {
				t.Fatal(err)
			}
			value := changeArtifact(t, result, base, head, payload)
			parsed, err := ParseResultArtifact(value, base, head)
			if err != nil || parsed.Identity() != result.Identity() || parsed.SchemaVersion() != 2 {
				t.Fatalf("parse: %v", err)
			}
			roundTrip, err := EncodeResult(parsed)
			if err != nil || !bytes.Equal(roundTrip, payload) {
				t.Fatalf("round trip: %v", err)
			}
			if b, h, err := ResultArtifactReferences(value); err != nil || b != base.Identity() || h != head.Identity() {
				t.Fatalf("references: %v", err)
			}
			for _, mutation := range []struct {
				name  string
				apply func(*resultWire)
			}{
				{"legacy version", func(w *resultWire) { w.SchemaVersion = 1 }},
				{"unknown version", func(w *resultWire) { w.SchemaVersion = 3 }},
				{"added", func(w *resultWire) {
					w.Entries[0].Kind = "added"
					w.Entries[0].BaseIdentity = ""
					w.Entries[0].BaseDigest = ""
					w.Entries[0].BaseSize = 0
				}},
				{"removed", func(w *resultWire) {
					w.Entries[0].Kind = "removed"
					w.Entries[0].HeadIdentity = ""
					w.Entries[0].HeadDigest = ""
					w.Entries[0].HeadSize = 0
				}},
				{"ranges", func(w *resultWire) { w.Entries[0].Ranges = []rangeWire{{1, 1}} }},
				{"file identity", func(w *resultWire) { w.Entries[0].FileChangeIdentity = execution.FileChange().Identity() }},
				{"line map identity", func(w *resultWire) { w.Entries[0].LineMapIdentity = execution.LineMap().Identity() }},
				{"supported zero ranges", func(w *resultWire) {
					w.Entries[0].Status = "supported"
					w.Entries[0].Reason = "none"
					w.Entries[0].FileChangeIdentity = execution.FileChange().Identity()
					w.Entries[0].LineMapIdentity = execution.LineMap().Identity()
				}},
			} {
				t.Run(mutation.name, func(t *testing.T) {
					wire := toWire(result)
					mutation.apply(&wire)
					wire.Identity = ""
					unsigned, _ := json.Marshal(wire)
					digest := sha256.Sum256(unsigned)
					wire.Identity = hex.EncodeToString(digest[:])
					invalid, _ := json.Marshal(wire)
					if _, err := ParseResultArtifact(changeArtifact(t, result, base, head, invalid), base, head); !errors.Is(err, ErrInvalidResult) {
						t.Fatalf("accepted rehashed invalid shape: %v", err)
					}
				})
			}
		})
	}
}
