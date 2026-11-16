package publication

import (
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/analysiscodec"
	"github.com/georgejieh/open-trestle/internal/changecodec"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/sourceoutput"
	"github.com/georgejieh/open-trestle/semanticimpact"
)

func TestReadinessAcceptsDeletionAnalysis(t *testing.T) {
	repository, _ := evidence.NewRepositoryIdentity("github.com", []string{"owner"}, "repo")
	baseRevision, _ := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("1", 40))
	headRevision, _ := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("2", 40))
	before, after := []byte("guard\nkeep\n"), []byte("keep\n")
	baseFile, _ := evidence.NewRepositoryFile("a.txt", before)
	headFile, _ := evidence.NewRepositoryFile("a.txt", after)
	baseManifest, _ := evidence.NewRepositoryManifest([]evidence.RepositoryFile{baseFile})
	headManifest, _ := evidence.NewRepositoryManifest([]evidence.RepositoryFile{headFile})
	delta, err := evidence.NewRepositoryManifestDelta(baseManifest, headManifest)
	if err != nil || len(delta.Entries()) != 1 {
		t.Fatalf("delta: %v", err)
	}
	execution, err := evidence.ExecuteRepositoryFileDelta(delta.Entries()[0], evidence.RepositoryFileDeltaContent{Present: true, Content: before}, evidence.RepositoryFileDeltaContent{Present: true, Content: after})
	if err != nil || execution.Status() != evidence.RepositoryFileDeltaExecutionStatusSupported || len(execution.FileChange().ChangedRanges()) != 0 {
		t.Fatalf("deletion execution: %v", err)
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
	change, err := changecodec.NewResult(base, head, baseSnapshot, headSnapshot, repository, baseRevision, headRevision, delta, []evidence.RepositoryFileDeltaExecution{execution}, nil)
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
	input, err := semanticimpact.NewInput(change.BaseSnapshotIdentity(), change.HeadSnapshotIdentity(), change.Identity(), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := semanticimpact.AnalyzeGo(input)
	if err != nil {
		t.Fatal(err)
	}
	check, err := analysiscodec.NewDeterministicCheck(change.Identity(), analysiscodec.CheckNotApplicable, 0, 0, 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	analysis, err := analysiscodec.NewResult(changeArtifact, change, head, headSnapshot, nil, []analysiscodec.Gap{analysiscodec.NewGap(change.Entries()[0], 0, 0, "no_changed_head_lines")}, []analysiscodec.DeterministicCheck{check}, nil, profile)
	if err != nil {
		t.Fatal(err)
	}
	payload, err = analysiscodec.EncodeResult(analysis)
	if err != nil {
		t.Fatal(err)
	}
	output, err := artifact.New(scope, artifact.KindDeterministicEvidence, "application/json", base.Classification(), artifact.OriginDeterministicTool, base.Protection(), []string{changeArtifact.Identity(), change.Identity(), head.Identity(), change.HeadSnapshotIdentity()}, payload, time.UnixMilli(300), base.ExpiresAt())
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := analysiscodec.ParseResultArtifact(output, changeArtifact, base, head)
	if err != nil || parsed.SchemaVersion() != 5 {
		t.Fatalf("deletion analysis: version=%d err=%v", parsed.SchemaVersion(), err)
	}
	checks, err := diagnosticDeterministicChecks(parsed, change)
	if err != nil || len(checks) != 1 {
		t.Fatalf("valid deletion analysis refused: checks=%d err=%v", len(checks), err)
	}
}
