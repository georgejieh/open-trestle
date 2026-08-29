package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/internal/scm"
)

func TestRunLocalGitReviewEmitsExactFindings(t *testing.T) {
	canary := "PRIVATE_SOURCE_CANARY_5129"
	base := map[string][]byte{"file.go": []byte("package sample\nfunc target() {}\n")}
	head := map[string][]byte{"file.go": []byte("package sample\nimport \"fmt\"\nfunc target() { fmt.Println(\"debug\"); _ = \"" + canary + "\" }\n")}
	objects, baseDigest, headDigest := writeLocalGitChangeFixture(t, evidence.RevisionAlgorithmSHA1, base, head)
	args := localGitChangeArgs(objects, evidence.RevisionAlgorithmSHA1, baseDigest, headDigest)
	var stdout, stderr bytes.Buffer
	if code := run(append([]string{"local-git", "review"}, args...), &stdout, &stderr); code != 0 || stderr.Len() != 0 {
		t.Fatalf("run() = %d, stderr = %q", code, stderr.String())
	}
	var got localGitReviewResult
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	want, wantCode := expectedLocalGitReviewResult(t, objects, evidence.RevisionAlgorithmSHA1, baseDigest, headDigest)
	if !reflect.DeepEqual(got, want) || wantCode != 0 || got.Status != localGitReviewStatusFindings || !got.ReviewPresent || len(got.Findings) != 1 || len(got.Evidence) != 1 || len(got.Files) != 1 || strings.Count(stdout.String(), "\n") != 1 {
		t.Fatalf("result = %#v, want %#v, code %d", got, want, wantCode)
	}
	for _, forbidden := range []string{objects, "example.test", "private", "sample", baseDigest, headDigest, canary, "fmt.Println"} {
		if strings.Contains(stdout.String(), forbidden) {
			t.Fatalf("output contains forbidden value %q", forbidden)
		}
	}
	first := stdout.String()
	stdout.Reset()
	if code := run(append([]string{"local-git", "review"}, args...), &stdout, &stderr); code != 0 || stdout.String() != first {
		t.Fatalf("repeat = %d, output = %q", code, stdout.String())
	}
}

func TestLocalGitReviewResultJSONSchema(t *testing.T) {
	result := localGitReviewResult{
		Contract: "open-trestle/local-git-review-result", SchemaVersion: 1, Status: localGitReviewStatusFindings,
		ReviewExecutionIdentity: "review-execution", ReviewPresent: true, ReviewResultIdentity: "review-result", RuleVersion: "1",
		Limits: localGitReviewLimitsResult{MaxFiles: 64, MaxBytesPerFile: 1048576, MaxTotalBytes: 67108864, MaxFindings: 1024},
		Change: localGitChangeResult{
			Contract: "open-trestle/local-git-change-result", SchemaVersion: 1, Status: localGitChangeStatusComplete,
			ChangeExecutionIdentity: "change-execution", AcquisitionPairIdentity: "pair", RepositoryIdentity: "repository",
			SourceAdapterIdentity: "adapter", BaseRevisionIdentity: "base", HeadRevisionIdentity: "head",
			BaseEnvelopeIdentity: "base-envelope", HeadEnvelopeIdentity: "head-envelope", ManifestDeltaIdentity: "delta",
			ChangePresent: true, ChangeIdentity: "change", ChangedFileCount: 1, SupportedFileCount: 1,
			UnsupportedFileCount: 0, Entries: []localGitChangeEntryResult{},
		},
		Files:    []localGitReviewFileResult{{Path: "file.go", Outcome: "analyzed", Reason: "none", HeadDigest: "head-digest", MatchCount: 1}},
		Findings: []localGitReviewFindingResult{{ID: "finding", Title: "title", Severity: "medium", Path: "file.go", StartLine: 2, EndLine: 2, EvidenceIDs: []string{"evidence"}}},
		Evidence: []localGitReviewEvidenceResult{{ID: "evidence", Kind: "source", Digest: "evidence-digest", Path: "file.go", StartLine: 2, EndLine: 2}},
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"contract":"open-trestle/local-git-review-result","schema_version":1,"status":"findings","review_execution_identity":"review-execution","review_present":true,"review_result_identity":"review-result","rule_version":"1","limits":{"max_files":64,"max_bytes_per_file":1048576,"max_total_bytes":67108864,"max_findings":1024},"change":{"contract":"open-trestle/local-git-change-result","schema_version":1,"status":"complete","change_execution_identity":"change-execution","acquisition_pair_identity":"pair","repository_identity":"repository","source_adapter_identity":"adapter","base_revision_identity":"base","head_revision_identity":"head","base_envelope_identity":"base-envelope","head_envelope_identity":"head-envelope","manifest_delta_identity":"delta","change_present":true,"change_identity":"change","changed_file_count":1,"supported_file_count":1,"unsupported_file_count":0,"entries":[]},"files":[{"path":"file.go","outcome":"analyzed","reason":"none","head_digest":"head-digest","match_count":1}],"findings":[{"id":"finding","title":"title","severity":"medium","path":"file.go","start_line":2,"end_line":2,"evidence_ids":["evidence"]}],"evidence":[{"id":"evidence","kind":"source","digest":"evidence-digest","path":"file.go","start_line":2,"end_line":2}]}`
	if string(encoded) != want {
		t.Fatalf("JSON = %s, want %s", encoded, want)
	}
}

func TestRunLocalGitReviewReportsInconclusivePartialAndAbsent(t *testing.T) {
	t.Run("inconclusive", func(t *testing.T) {
		objects, baseDigest, headDigest := writeLocalGitChangeFixture(t, evidence.RevisionAlgorithmSHA1, map[string][]byte{"file.go": []byte("package p\nfunc f() {}\n")}, map[string][]byte{"file.go": []byte("package p\nfunc f() { println(1) }\n")})
		result, code := runLocalGitReviewFixture(t, objects, baseDigest, headDigest)
		if code != 3 || result.Status != localGitReviewStatusInconclusive || !result.ReviewPresent || len(result.Findings) != 0 {
			t.Fatalf("result = %#v, code = %d", result, code)
		}
	})
	t.Run("partial", func(t *testing.T) {
		base := map[string][]byte{"file.go": []byte("package p\nfunc f() {}\n")}
		head := map[string][]byte{"added.go": []byte("package p\nfunc added() {}\n"), "file.go": []byte("package p\nimport \"fmt\"\nfunc f() { fmt.Println(\"debug\") }\n")}
		objects, baseDigest, headDigest := writeLocalGitChangeFixture(t, evidence.RevisionAlgorithmSHA1, base, head)
		result, code := runLocalGitReviewFixture(t, objects, baseDigest, headDigest)
		if code != 3 || result.Status != localGitReviewStatusPartial || !result.ReviewPresent || len(result.Findings) != 1 || result.Change.UnsupportedFileCount != 1 {
			t.Fatalf("result = %#v, code = %d", result, code)
		}
	})
	t.Run("no change", func(t *testing.T) {
		objects, digest, _ := writeLocalGitChangeFixture(t, evidence.RevisionAlgorithmSHA1, map[string][]byte{"file": []byte("same")}, map[string][]byte{"file": []byte("same")})
		result, code := runLocalGitReviewFixture(t, objects, digest, digest)
		if code != 3 || result.Status != localGitReviewStatusNoChange || result.ReviewPresent || result.ReviewResultIdentity != "" {
			t.Fatalf("result = %#v, code = %d", result, code)
		}
	})
	t.Run("unsupported", func(t *testing.T) {
		objects, baseDigest, headDigest := writeLocalGitChangeFixture(t, evidence.RevisionAlgorithmSHA1, map[string][]byte{}, map[string][]byte{"added.go": []byte("package p\n")})
		result, code := runLocalGitReviewFixture(t, objects, baseDigest, headDigest)
		if code != 3 || result.Status != localGitReviewStatusUnsupported || result.ReviewPresent || result.Change.UnsupportedFileCount != 1 {
			t.Fatalf("result = %#v, code = %d", result, code)
		}
	})
}

func TestValidateLocalGitReviewEvidenceRejectsAmbiguousBindings(t *testing.T) {
	rangeOne, _ := evidence.NewSourceRange("file.go", 1, 1)
	rangeTwo, _ := evidence.NewSourceRange("file.go", 2, 2)
	itemOne, _ := evidence.NewEvidenceItem("e1", evidence.EvidenceKindSource, strings.Repeat("a", 64), rangeOne)
	itemTwo, _ := evidence.NewEvidenceItem("e2", evidence.EvidenceKindSource, strings.Repeat("b", 64), rangeTwo)
	itemOneOtherRange, _ := evidence.NewEvidenceItem("e1", evidence.EvidenceKindSource, strings.Repeat("c", 64), rangeTwo)
	findingOne, _ := review.NewFinding("f1", "title", review.SeverityMedium, rangeOne, []string{"e1"})
	findingTwo, _ := review.NewFinding("f2", "title", review.SeverityMedium, rangeTwo, []string{"e2"})
	findingShared, _ := review.NewFinding("f2", "title", review.SeverityMedium, rangeTwo, []string{"e1"})
	findingDuplicate, _ := review.NewFinding("f1", "title", review.SeverityMedium, rangeTwo, []string{"e2"})
	findingMultiple, _ := review.NewFinding("f2", "title", review.SeverityMedium, rangeTwo, []string{"e1", "e2"})
	findingCrossOne, _ := review.NewFinding("f1", "title", review.SeverityMedium, rangeOne, []string{"e2"})
	findingCrossTwo, _ := review.NewFinding("f2", "title", review.SeverityMedium, rangeTwo, []string{"e1"})
	if err := validateLocalGitReviewEvidence([]review.Finding{findingOne, findingTwo}, []evidence.EvidenceItem{itemOne, itemTwo}); err != nil {
		t.Fatalf("valid binding error = %v", err)
	}
	for name, test := range map[string]struct {
		findings []review.Finding
		items    []evidence.EvidenceItem
	}{
		"count":             {findings: []review.Finding{findingOne}, items: []evidence.EvidenceItem{itemOne, itemTwo}},
		"shared evidence":   {findings: []review.Finding{findingOne, findingShared}, items: []evidence.EvidenceItem{itemOne, itemOneOtherRange}},
		"duplicate finding": {findings: []review.Finding{findingOne, findingDuplicate}, items: []evidence.EvidenceItem{itemOne, itemTwo}},
		"range mismatch":    {findings: []review.Finding{findingOne}, items: []evidence.EvidenceItem{itemOneOtherRange}},
		"multiple evidence": {findings: []review.Finding{findingOne, findingMultiple}, items: []evidence.EvidenceItem{itemOne, itemTwo}},
		"crossed evidence":  {findings: []review.Finding{findingCrossOne, findingCrossTwo}, items: []evidence.EvidenceItem{itemOne, itemTwo}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateLocalGitReviewEvidence(test.findings, test.items); err == nil {
				t.Fatal("ambiguous binding was accepted")
			}
		})
	}
}

func TestRunLocalGitReviewSARIFMatchesJSONFindings(t *testing.T) {
	path := "space name.go"
	base := map[string][]byte{path: []byte("package sample\nfunc target() {}\n")}
	head := map[string][]byte{path: []byte("package sample\nimport \"fmt\"\nfunc target() { fmt.Println(\"debug\") }\n")}
	objects, baseDigest, headDigest := writeLocalGitChangeFixture(t, evidence.RevisionAlgorithmSHA1, base, head)
	args := localGitChangeArgs(objects, evidence.RevisionAlgorithmSHA1, baseDigest, headDigest)
	var jsonOutput, sarifOutput, stderr bytes.Buffer
	if code := run(append([]string{"local-git", "review"}, args...), &jsonOutput, &stderr); code != 0 || stderr.Len() != 0 {
		t.Fatalf("JSON run = %d, stderr = %q", code, stderr.String())
	}
	explicitJSONArgs := append(append([]string{}, args...), "--format", "json")
	var explicitJSON bytes.Buffer
	if code := run(append([]string{"local-git", "review"}, explicitJSONArgs...), &explicitJSON, &stderr); code != 0 || explicitJSON.String() != jsonOutput.String() {
		t.Fatalf("explicit JSON = %d, output = %q", code, explicitJSON.String())
	}
	sarifArgs := append(append([]string{}, args...), "--format", "sarif")
	if code := run(append([]string{"local-git", "review"}, sarifArgs...), &sarifOutput, &stderr); code != 0 || stderr.Len() != 0 {
		t.Fatalf("SARIF run = %d, stderr = %q", code, stderr.String())
	}
	var jsonResult localGitReviewResult
	if err := json.Unmarshal(jsonOutput.Bytes(), &jsonResult); err != nil {
		t.Fatal(err)
	}
	var sarif sarifLog
	if err := json.Unmarshal(sarifOutput.Bytes(), &sarif); err != nil {
		t.Fatal(err)
	}
	if sarif.Schema != sarifSchemaURI || sarif.Version != "2.1.0" || len(sarif.Runs) != 1 || len(sarif.Runs[0].Results) != len(jsonResult.Findings) || len(sarif.Runs[0].Results) != 1 {
		t.Fatalf("SARIF = %#v", sarif)
	}
	result := sarif.Runs[0].Results[0]
	finding := jsonResult.Findings[0]
	evidenceItem := jsonResult.Evidence[0]
	if result.RuleID != "static-debug-output" || result.Level != "warning" || result.Message.Text != finding.Title || result.Locations[0].PhysicalLocation.ArtifactLocation.URI != "space%20name.go" || result.Locations[0].PhysicalLocation.Region.StartLine != finding.StartLine || result.Locations[0].PhysicalLocation.Region.EndLine != finding.EndLine || result.Properties.EvidenceID != evidenceItem.ID || result.Properties.EvidenceDigest != evidenceItem.Digest || result.Fingerprints["openTrestleFindingId/v1"] != finding.ID {
		t.Fatalf("SARIF result = %#v, JSON finding = %#v, evidence = %#v", result, finding, evidenceItem)
	}
}

func TestRunLocalGitReviewSARIFEmitsEmptyResultsForNoFindings(t *testing.T) {
	objects, baseDigest, headDigest := writeLocalGitChangeFixture(t, evidence.RevisionAlgorithmSHA1, map[string][]byte{"file.go": []byte("package p\nfunc f() {}\n")}, map[string][]byte{"file.go": []byte("package p\nfunc f() { println(1) }\n")})
	args := append(localGitChangeArgs(objects, evidence.RevisionAlgorithmSHA1, baseDigest, headDigest), "--format", "sarif")
	var stdout, stderr bytes.Buffer
	code := run(append([]string{"local-git", "review"}, args...), &stdout, &stderr)
	var sarif sarifLog
	if err := json.Unmarshal(stdout.Bytes(), &sarif); err != nil {
		t.Fatal(err)
	}
	if code != 3 || stderr.Len() != 0 || len(sarif.Runs) != 1 || sarif.Runs[0].Results == nil || len(sarif.Runs[0].Results) != 0 {
		t.Fatalf("SARIF = %#v, code = %d, stderr = %q", sarif, code, stderr.String())
	}
}

func TestRunLocalGitReviewRejectsInvalidFormatBeforeOpen(t *testing.T) {
	args := append(localGitChangeArgs("objects", evidence.RevisionAlgorithmSHA1, strings.Repeat("1", 40), strings.Repeat("2", 40)), "--format", "xml")
	opens := 0
	opener := func(string) (localGitRootHandle, error) {
		opens++
		return localGitRootHandle{}, errors.New("unexpected open")
	}
	var stdout, stderr bytes.Buffer
	if code := runLocalGitReviewWithOpener(args, &stdout, &stderr, opener); code != 2 || opens != 0 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "usage: trestle local-git review") {
		t.Fatalf("result = %d, opens = %d, stdout = %q, stderr = %q", code, opens, stdout.String(), stderr.String())
	}
}

func TestRunLocalGitReviewRejectsArgumentsBeforeOpen(t *testing.T) {
	valid := localGitChangeArgs("objects", evidence.RevisionAlgorithmSHA1, strings.Repeat("1", 40), strings.Repeat("2", 40))
	for name, args := range map[string][]string{
		"missing":    valid[:12],
		"unknown":    replaceLocalGitChangeArg(valid, "--objects-root", "--unknown"),
		"duplicate":  append(append([]string{}, valid...), "--objects-root", "other"),
		"bad digest": replaceLocalGitChangeValue(valid, "--head-revision-digest", "short"),
	} {
		t.Run(name, func(t *testing.T) {
			opens := 0
			opener := func(string) (localGitRootHandle, error) {
				opens++
				return localGitRootHandle{}, errors.New("unexpected open")
			}
			var stdout, stderr bytes.Buffer
			if code := runLocalGitReviewWithOpener(args, &stdout, &stderr, opener); code != 2 || opens != 0 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "usage: trestle local-git review") {
				t.Fatalf("result = %d, opens = %d, stdout = %q, stderr = %q", code, opens, stdout.String(), stderr.String())
			}
		})
	}
}

func TestRunLocalGitReviewClosesBeforeOutputAndSuppressesFailures(t *testing.T) {
	objects, baseDigest, headDigest := writeLocalGitChangeFixture(t, evidence.RevisionAlgorithmSHA1, map[string][]byte{"file.go": []byte("package p\nfunc f() {}\n")}, map[string][]byte{"file.go": []byte("package p\nfunc f() { println(1) }\n")})
	args := localGitChangeArgs(objects, evidence.RevisionAlgorithmSHA1, baseDigest, headDigest)
	root, err := os.OpenRoot(objects)
	if err != nil {
		t.Fatal(err)
	}
	closed := 0
	opener := func(string) (localGitRootHandle, error) {
		return localGitRootHandle{root: root, close: func() error { closed++; return root.Close() }}, nil
	}
	writer := &closeAwareWriter{closed: &closed}
	var stderr bytes.Buffer
	if code := runLocalGitReviewWithOpener(args, writer, &stderr, opener); code != 3 || closed != 1 || !writer.wroteAfterClose {
		t.Fatalf("result = %d, closed = %d, after close = %v", code, closed, writer.wroteAfterClose)
	}
	stderr.Reset()
	if code := runLocalGitReviewWithOpener(args, errorWriter{}, &stderr, openLocalGitRoot); code != 1 || !strings.Contains(stderr.String(), "write result") {
		t.Fatalf("write failure = %d, stderr = %q", code, stderr.String())
	}
}

func runLocalGitReviewFixture(t *testing.T, objects, baseDigest, headDigest string) (localGitReviewResult, int) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(append([]string{"local-git", "review"}, localGitChangeArgs(objects, evidence.RevisionAlgorithmSHA1, baseDigest, headDigest)...), &stdout, &stderr)
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q", stderr.String())
	}
	var result localGitReviewResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	return result, code
}

func expectedLocalGitReviewResult(t *testing.T, objects string, algorithm evidence.RevisionAlgorithm, baseDigest, headDigest string) (localGitReviewResult, int) {
	t.Helper()
	repository, _ := evidence.NewRepositoryIdentity("example.test", []string{"private", "team"}, "sample")
	baseRevision, _ := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, algorithm, baseDigest)
	headRevision, _ := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, algorithm, headDigest)
	root, err := os.OpenRoot(objects)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	store, err := scm.NewLocalGitObjectStore(root, repository)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := scm.NewLocalGitSourceAdapter(store)
	if err != nil {
		t.Fatal(err)
	}
	baseRequest, _ := evidence.NewRepositoryAcquisitionRequest(repository, baseRevision, adapter.Identity(), evidence.AcquisitionArtifactManifestAndContent, evidence.AcquisitionEffectReadOnly)
	headRequest, _ := evidence.NewRepositoryAcquisitionRequest(repository, headRevision, adapter.Identity(), evidence.AcquisitionArtifactManifestAndContent, evidence.AcquisitionEffectReadOnly)
	execution, err := scm.ExecuteLocalGitChangeWithDebugOutputReview(context.Background(), baseRequest, headRequest, adapter, localGitReviewLimits())
	if err != nil {
		t.Fatal(err)
	}
	result, code, err := newLocalGitReviewResult(execution, localGitReviewLimits())
	if err != nil {
		t.Fatal(err)
	}
	return result, code
}
