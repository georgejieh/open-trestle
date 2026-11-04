package analysiscodec

import (
	"bytes"
	"errors"
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

func deletionChange(t *testing.T, before, after string) (changecodec.Result, artifact.Artifact, artifact.Artifact) {
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
	result, err := changecodec.NewResult(base, head, baseSnapshot, headSnapshot, repository, baseRevision, headRevision, delta, []evidence.RepositoryFileDeltaExecution{execution}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return result, base, head
}

func deletionAnalysis(t *testing.T, after string) (artifact.Artifact, artifact.Artifact, artifact.Artifact, artifact.Artifact, Result, changecodec.Result) {
	t.Helper()
	change, base, head := deletionChange(t, "guard\nkeep\n", after)
	payload, err := changecodec.EncodeResult(change)
	if err != nil {
		t.Fatal(err)
	}
	changeArtifact, err := artifact.New(base.Scope(), artifact.KindChangeModel, "application/json", base.Classification(), artifact.OriginDeterministicTool, base.Protection(), []string{base.Identity(), head.Identity()}, payload, time.UnixMilli(200), base.ExpiresAt())
	if err != nil {
		t.Fatal(err)
	}
	change, err = changecodec.ParseResultArtifact(changeArtifact, base, head)
	if err != nil {
		t.Fatal(err)
	}
	headSnapshot, err := sourceoutput.ParseSnapshotArtifact(head)
	if err != nil {
		t.Fatal(err)
	}
	input, err := semanticimpact.NewInput(change.BaseSnapshotIdentity(), change.HeadSnapshotIdentity(), change.Identity(), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := semanticimpact.AnalyzeGo(input)
	if err != nil {
		t.Fatal(err)
	}
	check, err := NewDeterministicCheck(change.Identity(), CheckNotApplicable, 0, 0, 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	result, err := NewResult(changeArtifact, change, head, headSnapshot, nil, []Gap{NewGap(change.Entries()[0], 0, 0, "no_changed_head_lines")}, []DeterministicCheck{check}, nil, profile)
	if err != nil {
		t.Fatal(err)
	}
	payload, err = EncodeResult(result)
	if err != nil {
		t.Fatal(err)
	}
	output, err := artifact.New(base.Scope(), artifact.KindDeterministicEvidence, "application/json", base.Classification(), artifact.OriginDeterministicTool, base.Protection(), []string{changeArtifact.Identity(), change.Identity(), head.Identity(), change.HeadSnapshotIdentity()}, payload, time.UnixMilli(300), base.ExpiresAt())
	if err != nil {
		t.Fatal(err)
	}
	return output, changeArtifact, base, head, result, change
}

func TestNoChangedHeadLinesRequiresVersionedExactGap(t *testing.T) {
	for _, after := range []string{"keep\n", ""} {
		t.Run(after, func(t *testing.T) {
			output, changeArtifact, base, head, result, change := deletionAnalysis(t, after)
			parsed, err := ParseResultArtifact(output, changeArtifact, base, head)
			if err != nil || parsed.SchemaVersion() != 5 || parsed.changedEntries != 1 || parsed.changedRanges != 0 || len(parsed.Items()) != 0 || len(parsed.Observations()) != 0 || len(parsed.Gaps()) != 1 {
				t.Fatalf("parse=%#v err=%v", parsed, err)
			}
			encoded, err := EncodeResult(parsed)
			if err != nil || !bytes.Equal(encoded, output.Payload()) || !bytes.Contains(encoded, []byte(`"observations":[]`)) {
				t.Fatalf("v5 round trip lost fields: %v", err)
			}
			for _, tc := range []struct {
				name   string
				mutate func(*Result)
			}{
				{"missing gap", func(r *Result) { r.gaps = nil }},
				{"duplicate gap", func(r *Result) { r.gaps = append(r.gaps, r.gaps[0]) }},
				{"mismatched reason", func(r *Result) { r.gaps[0].reason = "resource_limit" }},
				{"alternate whole-entry gap", func(r *Result) { r.gaps[0].reason = "evidence_limit" }},
				{"nonzero coordinates", func(r *Result) { r.gaps[0].startLine = 1; r.gaps[0].endLine = 1 }},
				{"wrong execution", func(r *Result) { r.gaps[0].changeExecutionIdentity = strings.Repeat("a", 64) }},
				{"legacy v4", func(r *Result) { r.schemaVersion = 4 }},
				{"legacy v3", func(r *Result) { r.schemaVersion = 3 }},
				{"legacy v2", func(r *Result) { r.schemaVersion = 2; r.checks = nil }},
				{"unknown version", func(r *Result) { r.schemaVersion = 6 }},
			} {
				t.Run(tc.name, func(t *testing.T) {
					payload := canonicalMutation(t, result, tc.mutate)
					rejectResult(t, output, changeArtifact, base, head, payload)
				})
			}
			entry := change.Entries()[0]
			gap := NewGap(entry, 0, 0, entry.Reason())
			entries := map[string]changecodec.Entry{entry.Identity(): entry}
			if validGap(gap, entries, 5, 1) || validGap(gap, entries, 4, 2) {
				t.Fatal("new gap accepted without both versioned contracts")
			}
			if _, err := ParseResultArtifact(rebuildEvidence(t, output, append([]byte(" "), output.Payload()...)), changeArtifact, base, head); !errors.Is(err, ErrInvalidResult) {
				t.Fatalf("noncanonical v5 accepted: %v", err)
			}
		})
	}
}
