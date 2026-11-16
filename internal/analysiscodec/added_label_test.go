package analysiscodec

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/changecodec"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/sourceoutput"
	"github.com/georgejieh/open-trestle/semanticimpact"
)

// addedFileAnalysis builds a change that adds added.bin with the given
// content and, with removed, also removes gone.txt, whose removed text is one
// unread whole-entry limit gap so that the result is version 7. The added
// entry gets the whole-entry gap label.
func addedFileAnalysis(t *testing.T, content []byte, removed bool, label string) (artifact.Artifact, artifact.Artifact, artifact.Artifact, artifact.Artifact, Result, changecodec.Entry) {
	t.Helper()
	repository, _ := evidence.NewRepositoryIdentity("github.com", []string{"owner"}, "repo")
	baseRevision, _ := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("1", 40))
	headRevision, _ := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("2", 40))
	added, _ := evidence.NewRepositoryFile("added.bin", content)
	gone, _ := evidence.NewRepositoryFile("gone.txt", []byte("gone\n"))
	baseFiles, headFiles := []evidence.RepositoryFile{}, []evidence.RepositoryFile{added}
	contents := map[string][]byte{"added.bin": content, "gone.txt": []byte("gone\n")}
	if removed {
		baseFiles = append(baseFiles, gone)
	}
	baseManifest, err := evidence.NewRepositoryManifest(baseFiles)
	if err != nil {
		t.Fatal(err)
	}
	headManifest, err := evidence.NewRepositoryManifest(headFiles)
	if err != nil {
		t.Fatal(err)
	}
	delta, err := evidence.NewRepositoryManifestDelta(baseManifest, headManifest)
	if err != nil {
		t.Fatal(err)
	}
	executions := make([]evidence.RepositoryFileDeltaExecution, len(delta.Entries()))
	for index, entry := range delta.Entries() {
		var base, head evidence.RepositoryFileDeltaContent
		if _, ok := entry.BaseFile(); ok {
			base = evidence.RepositoryFileDeltaContent{Present: true, Content: contents[entry.Path()]}
		}
		if _, ok := entry.HeadFile(); ok {
			head = evidence.RepositoryFileDeltaContent{Present: true, Content: contents[entry.Path()]}
		}
		executions[index], err = evidence.ExecuteRepositoryFileDelta(entry, base, head)
		if err != nil {
			t.Fatal(err)
		}
	}
	scope, _ := audit.NewReviewScope("tenant", "repository", "added")
	snapshot := func(files []evidence.RepositoryFile, manifest evidence.RepositoryManifest, revision evidence.RevisionIdentity, marker string) (artifact.Artifact, sourceoutput.Snapshot) {
		t.Helper()
		references := make([]sourceoutput.FileReference, 0, len(files))
		for _, file := range files {
			references = append(references, sourceoutput.NewFileReference(file.Path(), file.Digest(), file.SizeBytes(), strings.Repeat(marker, 64)))
		}
		index, err := sourceoutput.NewSnapshot("", strings.Repeat(marker, 64), strings.Repeat(marker, 64), strings.Repeat(marker, 64), repository.Identity(), revision.Identity(), strings.Repeat("a", 64), manifest.Identity(), references)
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
	base, baseSnapshot := snapshot(baseFiles, baseManifest, baseRevision, "b")
	head, headSnapshot := snapshot(headFiles, headManifest, headRevision, "c")
	change, err := changecodec.NewResult(base, head, baseSnapshot, headSnapshot, repository, baseRevision, headRevision, delta, executions, nil)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := changecodec.EncodeResult(change)
	if err != nil {
		t.Fatal(err)
	}
	changeArtifact, err := artifact.New(scope, artifact.KindChangeModel, "application/json", base.Classification(), artifact.OriginDeterministicTool, base.Protection(), []string{base.Identity(), head.Identity()}, payload, time.UnixMilli(200), base.ExpiresAt())
	if err != nil {
		t.Fatal(err)
	}
	change, err = changecodec.ParseResultArtifact(changeArtifact, base, head)
	if err != nil {
		t.Fatal(err)
	}
	input, _ := semanticimpact.NewInput(change.BaseSnapshotIdentity(), change.HeadSnapshotIdentity(), change.Identity(), nil, nil, nil)
	profile, err := semanticimpact.AnalyzeGo(input)
	if err != nil {
		t.Fatal(err)
	}
	check, _ := NewDeterministicCheck(change.Identity(), CheckNotApplicable, 0, 0, 0, 0, 0)
	var addedEntry changecodec.Entry
	gaps := []Gap{}
	for _, entry := range change.Entries() {
		if entry.Path() == "added.bin" {
			addedEntry = entry
			gaps = append(gaps, NewGap(entry, 0, 0, label))
			continue
		}
		gaps = append(gaps, NewGap(entry, 0, 0, "removed_file"), NewGap(entry, 0, 0, RemovedLinesLimitReason))
	}
	result, err := NewResultWithRemovedLines(changeArtifact, change, head, headSnapshot, nil, nil, gaps, []DeterministicCheck{check}, nil, profile)
	if err != nil {
		t.Fatalf("added %s labelled %s refused: %v", addedEntry.Reason(), label, err)
	}
	encoded, err := EncodeResult(result)
	if err != nil {
		t.Fatal(err)
	}
	output, err := artifact.New(scope, artifact.KindDeterministicEvidence, "application/json", base.Classification(), artifact.OriginDeterministicTool, base.Protection(), []string{changeArtifact.Identity(), change.Identity(), head.Identity(), change.HeadSnapshotIdentity()}, encoded, time.UnixMilli(300), base.ExpiresAt())
	if err != nil {
		t.Fatal(err)
	}
	return output, changeArtifact, base, head, result, addedEntry
}

// From version 4 an added file's whole-entry gap names why it has no range,
// and empty_added_file is admitted only for an added file with zero bytes: a
// result that labels a binary or oversized added file empty is refused.
func TestEmptyAddedFileLabelIsOnlyForAZeroByteFile(t *testing.T) {
	for _, removed := range []bool{true, false} {
		version := 4
		if removed {
			version = 7
		}
		for _, tc := range []struct {
			name, reason string
			content      []byte
		}{
			{"empty", "empty_added_file", []byte{}},
			{"small binary", "unsupported_content", []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\xff\xfe")},
			{"over the size limit", "resource_limit", bytes.Repeat([]byte{0, 1, 2, 3}, 512<<10)},
		} {
			output, change, base, head, result, entry := addedFileAnalysis(t, tc.content, removed, tc.reason)
			if result.SchemaVersion() != version {
				t.Fatalf("%s: version %d, want %d", tc.name, result.SchemaVersion(), version)
			}
			if _, err := ParseResultArtifact(output, change, base, head); err != nil {
				t.Fatalf("%s v%d: correctly labelled added file refused: %v", tc.name, version, err)
			}
			if tc.reason == "empty_added_file" {
				continue
			}
			mislabelled := canonicalMutation(t, result, func(r *Result) {
				for index, gap := range r.gaps {
					if gap.path == entry.Path() {
						r.gaps[index] = NewGap(entry, 0, 0, "empty_added_file")
					}
				}
			})
			rejectResult(t, output, change, base, head, mislabelled)
		}
	}
}
