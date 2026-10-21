package sourceoutput_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/sourceoutput"
)

func snapshotFileFixture(t testing.TB, count int) (sourceoutput.Snapshot, sourceoutput.Snapshot, artifact.Artifact, sourceoutput.FileReference) {
	t.Helper()
	scope, err := audit.NewReviewScope("tenant-a", "repo-a", "source-parser")
	if err != nil {
		t.Fatal(err)
	}
	execution := strings.Repeat("3", 64)
	refs := make([]sourceoutput.FileReference, count)
	var selected artifact.Artifact
	for i := range refs {
		content := []byte("owned source bytes\n")
		file, err := evidence.NewRepositoryFile(fmt.Sprintf("file-%05d.txt", i), content)
		if err != nil {
			t.Fatal(err)
		}
		payload, err := sourceoutput.EncodeFile(execution, file, content)
		if err != nil {
			t.Fatal(err)
		}
		value, err := artifact.New(scope, artifact.KindSourceFile, "application/json", artifact.ClassificationConfidential, artifact.OriginRepository, artifact.ProtectionProcessPrivate, []string{execution}, payload, time.UnixMilli(100), time.UnixMilli(10000))
		if err != nil {
			t.Fatal(err)
		}
		refs[i] = sourceoutput.NewFileReference(file.Path(), file.Digest(), file.SizeBytes(), value.Identity())
		selected = value
	}
	unbound, err := sourceoutput.NewSnapshot("", strings.Repeat("1", 64), strings.Repeat("2", 64), execution, strings.Repeat("4", 64), strings.Repeat("5", 64), strings.Repeat("6", 64), strings.Repeat("7", 64), refs)
	if err != nil {
		t.Fatal(err)
	}
	selectedRef := refs[len(refs)-1]
	refs[len(refs)-1] = sourceoutput.FileReference{}
	payload, err := sourceoutput.EncodeSnapshot(unbound)
	if err != nil {
		t.Fatal(err)
	}
	value, err := artifact.New(scope, artifact.KindSourceSnapshot, "application/json", artifact.ClassificationConfidential, artifact.OriginRepository, artifact.ProtectionProcessPrivate, []string{execution}, payload, time.UnixMilli(100), time.UnixMilli(10000))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := sourceoutput.ParseSnapshotArtifact(value)
	if err != nil {
		t.Fatal(err)
	}
	return unbound, parsed, selected, selectedRef
}

func TestParseFileArtifactRequiresParsedImmutableSnapshot(t *testing.T) {
	unbound, parsed, value, ref := snapshotFileFixture(t, 2)
	for _, snapshot := range []sourceoutput.Snapshot{{}, unbound} {
		if _, err := sourceoutput.ParseFileArtifact(value, snapshot, ref); err == nil {
			t.Fatal("unbound snapshot accepted")
		}
	}
	files := parsed.Files()
	files[len(files)-1] = sourceoutput.FileReference{}
	file, err := sourceoutput.ParseFileArtifact(value, parsed, ref)
	if err != nil || file.ArtifactIdentity() != value.Identity() {
		t.Fatalf("parsed snapshot changed through caller slice: %v", err)
	}
	foreign := sourceoutput.NewFileReference(ref.Path(), strings.Repeat("8", 64), ref.SizeBytes(), ref.ArtifactIdentity())
	if _, err := sourceoutput.ParseFileArtifact(value, parsed, foreign); err == nil {
		t.Fatal("foreign reference accepted")
	}
	otherScope, err := audit.NewReviewScope("tenant-a", "repo-a", "other-run")
	if err != nil {
		t.Fatal(err)
	}
	foreignValue, err := artifact.New(otherScope, value.Kind(), value.MediaType(), value.Classification(), value.Origin(), value.Protection(), value.Provenance(), value.Payload(), value.CreatedAt(), value.ExpiresAt())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sourceoutput.ParseFileArtifact(foreignValue, parsed, ref); err == nil {
		t.Fatal("foreign artifact accepted")
	}
}

func BenchmarkParseFileArtifactSnapshotSize(b *testing.B) {
	for _, count := range []int{100, 1000} {
		b.Run(fmt.Sprintf("files-%d", count), func(b *testing.B) {
			_, parsed, value, ref := snapshotFileFixture(b, count)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if _, err := sourceoutput.ParseFileArtifact(value, parsed, ref); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
