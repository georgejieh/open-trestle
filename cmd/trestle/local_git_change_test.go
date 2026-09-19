package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/scm"
)

func TestRunLocalGitChangeEmitsExactSupportedEvidence(t *testing.T) {
	for _, algorithm := range []evidence.RevisionAlgorithm{evidence.RevisionAlgorithmSHA1, evidence.RevisionAlgorithmSHA256} {
		t.Run(string(algorithm), func(t *testing.T) {
			objects, baseDigest, headDigest := writeLocalGitChangeFixture(t, algorithm, map[string][]byte{"file.go": []byte("old\n")}, map[string][]byte{"file.go": []byte("new\n")})
			args := localGitChangeArgs(objects, algorithm, baseDigest, headDigest)
			var stdout, stderr bytes.Buffer
			if code := run(append([]string{"local-git", "change"}, args...), &stdout, &stderr); code != 0 || stderr.Len() != 0 {
				t.Fatalf("run() = %d, stderr = %q", code, stderr.String())
			}
			var got localGitChangeResult
			if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			want, wantCode := expectedLocalGitChangeResult(t, objects, algorithm, baseDigest, headDigest)
			if !reflect.DeepEqual(got, want) || wantCode != 0 || got.SchemaVersion != 2 || got.Status != localGitChangeStatusComplete || !got.ChangePresent || got.SupportedFileCount != 1 || got.UnsupportedFileCount != 0 || len(got.Entries) != 1 || strings.Count(stdout.String(), "\n") != 1 {
				t.Fatalf("result = %#v, want %#v, code %d", got, want, wantCode)
			}
			first := stdout.String()
			stdout.Reset()
			if code := run(append([]string{"local-git", "change"}, args...), &stdout, &stderr); code != 0 || stdout.String() != first {
				t.Fatalf("repeat = %d, output = %q", code, stdout.String())
			}
			for _, forbidden := range []string{objects, "example.test", "private", "sample", baseDigest, headDigest, "old", "new"} {
				if strings.Contains(stdout.String(), forbidden) {
					t.Fatalf("output contains forbidden value %q", forbidden)
				}
			}
		})
	}
}

func TestLocalGitChangeResultJSONSchema(t *testing.T) {
	result := localGitChangeResult{
		Contract: "open-trestle/local-git-change-result", SchemaVersion: 1, Status: localGitChangeStatusPartial,
		ChangeExecutionIdentity: "ce", AcquisitionPairIdentity: "pair", RepositoryIdentity: "repo", SourceAdapterIdentity: "adapter",
		BaseRevisionIdentity: "base", HeadRevisionIdentity: "head", BaseEnvelopeIdentity: "be", HeadEnvelopeIdentity: "he",
		ManifestDeltaIdentity: "delta", ChangePresent: true, ChangeIdentity: "change", ChangedFileCount: 1,
		SupportedFileCount: 0, UnsupportedFileCount: 1,
		Entries: []localGitChangeEntryResult{{
			Path: "file.go", Kind: "added", Status: "unsupported", Reason: "added_file",
			RepositoryFileDeltaIdentity: "fde", ExecutionIdentity: "execution",
			FileChangeIdentity: "", LineMapIdentity: "",
		}},
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"contract":"open-trestle/local-git-change-result","schema_version":1,"status":"partial","change_execution_identity":"ce","acquisition_pair_identity":"pair","repository_identity":"repo","source_adapter_identity":"adapter","base_revision_identity":"base","head_revision_identity":"head","base_envelope_identity":"be","head_envelope_identity":"he","manifest_delta_identity":"delta","change_present":true,"change_identity":"change","changed_file_count":1,"supported_file_count":0,"unsupported_file_count":1,"entries":[{"path":"file.go","kind":"added","status":"unsupported","reason":"added_file","repository_file_delta_identity":"fde","execution_identity":"execution","file_change_identity":"","line_map_identity":""}]}`
	if string(encoded) != want {
		t.Fatalf("JSON = %s, want %s", encoded, want)
	}
}

func TestRunLocalGitChangePreservesOrderedUnsupportedEntries(t *testing.T) {
	base := map[string][]byte{"changed.go": []byte("old\n"), "removed.go": []byte("removed\n"), "same.go": []byte("same\n")}
	head := map[string][]byte{"added.go": []byte("added\n"), "changed.go": []byte("new\n"), "same.go": []byte("same\n")}
	objects, baseDigest, headDigest := writeLocalGitChangeFixture(t, evidence.RevisionAlgorithmSHA1, base, head)
	var stdout, stderr bytes.Buffer
	code := run(append([]string{"local-git", "change"}, localGitChangeArgs(objects, evidence.RevisionAlgorithmSHA1, baseDigest, headDigest)...), &stdout, &stderr)
	var result localGitChangeResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if code != 3 || stderr.Len() != 0 || result.SchemaVersion != 2 || result.Status != localGitChangeStatusPartial || result.SupportedFileCount != 2 || result.UnsupportedFileCount != 1 || len(result.Entries) != 3 || result.Entries[0].Path != "added.go" || result.Entries[0].Status != string(evidence.RepositoryFileDeltaExecutionStatusSupported) || result.Entries[0].Reason != string(evidence.RepositoryFileDeltaUnsupportedReasonNone) || result.Entries[0].FileChangeIdentity == "" || result.Entries[0].LineMapIdentity == "" || result.Entries[1].Path != "changed.go" || result.Entries[2].Path != "removed.go" || result.Entries[2].Reason != string(evidence.RepositoryFileDeltaUnsupportedReasonRemovedFile) {
		t.Fatalf("partial result = %#v, code = %d, stderr = %q", result, code, stderr.String())
	}
}

func TestRunLocalGitChangeReportsNoChangeAndUnsupported(t *testing.T) {
	t.Run("no change", func(t *testing.T) {
		objects, digest, _ := writeLocalGitChangeFixture(t, evidence.RevisionAlgorithmSHA1, map[string][]byte{"file": []byte("same")}, map[string][]byte{"file": []byte("same")})
		var stdout, stderr bytes.Buffer
		code := run(append([]string{"local-git", "change"}, localGitChangeArgs(objects, evidence.RevisionAlgorithmSHA1, digest, digest)...), &stdout, &stderr)
		var result localGitChangeResult
		_ = json.Unmarshal(stdout.Bytes(), &result)
		if code != 0 || result.SchemaVersion != 2 || result.Status != localGitChangeStatusNoChange || result.ChangePresent || len(result.Entries) != 0 || stderr.Len() != 0 {
			t.Fatalf("no-change result = %#v, code = %d, stderr = %q", result, code, stderr.String())
		}
	})
	t.Run("unsupported", func(t *testing.T) {
		objects, baseDigest, headDigest := writeLocalGitChangeFixture(t, evidence.RevisionAlgorithmSHA1, map[string][]byte{"file": []byte{'a', 0}}, map[string][]byte{"file": []byte{'b', 0}})
		var stdout, stderr bytes.Buffer
		code := run(append([]string{"local-git", "change"}, localGitChangeArgs(objects, evidence.RevisionAlgorithmSHA1, baseDigest, headDigest)...), &stdout, &stderr)
		var result localGitChangeResult
		_ = json.Unmarshal(stdout.Bytes(), &result)
		if code != 3 || result.SchemaVersion != 2 || result.Status != localGitChangeStatusUnsupported || result.ChangePresent || len(result.Entries) != 1 || result.Entries[0].Reason != string(evidence.RepositoryFileDeltaUnsupportedReasonContent) || stderr.Len() != 0 {
			t.Fatalf("unsupported result = %#v, code = %d, stderr = %q", result, code, stderr.String())
		}
	})
}

func TestRunLocalGitChangeRejectsInvalidArgumentsBeforeOpen(t *testing.T) {
	valid := localGitChangeArgs("objects", evidence.RevisionAlgorithmSHA1, strings.Repeat("1", 40), strings.Repeat("2", 40))
	tests := map[string][]string{
		"missing":     valid[:12],
		"extra":       append(append([]string{}, valid...), "extra"),
		"unknown":     replaceLocalGitChangeArg(valid, "--objects-root", "--unknown"),
		"duplicate":   append(append([]string{}, valid...), "--objects-root", "other"),
		"algorithm":   replaceLocalGitChangeValue(valid, "--revision-algorithm", "md5"),
		"base digest": replaceLocalGitChangeValue(valid, "--base-revision-digest", "short"),
		"head digest": replaceLocalGitChangeValue(valid, "--head-revision-digest", strings.Repeat("A", 40)),
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			opens := 0
			opener := func(string) (localGitRootHandle, error) {
				opens++
				return localGitRootHandle{}, errors.New("unexpected open")
			}
			var stdout, stderr bytes.Buffer
			if code := runLocalGitChangeWithOpener(args, &stdout, &stderr, opener); code != 2 || opens != 0 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "usage: trestle local-git change") {
				t.Fatalf("result = %d, opens = %d, stdout = %q, stderr = %q", code, opens, stdout.String(), stderr.String())
			}
		})
	}
}

func TestRunLocalGitChangeClosesBeforeOutputAndSuppressesFailures(t *testing.T) {
	objects, baseDigest, headDigest := writeLocalGitChangeFixture(t, evidence.RevisionAlgorithmSHA1, map[string][]byte{"file": []byte("old")}, map[string][]byte{"file": []byte("new")})
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
	if code := runLocalGitChangeWithOpener(args, writer, &stderr, opener); code != 0 || closed != 1 || !writer.wroteAfterClose {
		t.Fatalf("success = %d, closed = %d, after close = %v", code, closed, writer.wroteAfterClose)
	}

	root, err = os.OpenRoot(objects)
	if err != nil {
		t.Fatal(err)
	}
	closed = 0
	opener = func(string) (localGitRootHandle, error) {
		return localGitRootHandle{root: root, close: func() error { closed++; _ = root.Close(); return errors.New("close failed") }}, nil
	}
	var stdout bytes.Buffer
	stderr.Reset()
	if code := runLocalGitChangeWithOpener(args, &stdout, &stderr, opener); code != 1 || closed != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "close object root") {
		t.Fatalf("close failure = %d, stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
	}
	stderr.Reset()
	if code := runLocalGitChangeWithOpener(args, errorWriter{}, &stderr, openLocalGitRoot); code != 1 || !strings.Contains(stderr.String(), "write result") {
		t.Fatalf("write failure = %d, stderr = %q", code, stderr.String())
	}
}

func expectedLocalGitChangeResult(t *testing.T, objects string, algorithm evidence.RevisionAlgorithm, baseDigest, headDigest string) (localGitChangeResult, int) {
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
	execution, err := scm.ExecuteLocalGitChange(context.Background(), baseRequest, headRequest, adapter)
	if err != nil {
		t.Fatal(err)
	}
	result, code, err := newLocalGitChangeResult(execution)
	if err != nil {
		t.Fatal(err)
	}
	return result, code
}

func localGitChangeArgs(objects string, algorithm evidence.RevisionAlgorithm, baseDigest, headDigest string) []string {
	return []string{"--objects-root", objects, "--repository-authority", "example.test", "--repository-namespace", "private/team", "--repository-name", "sample", "--revision-algorithm", string(algorithm), "--base-revision-digest", baseDigest, "--head-revision-digest", headDigest}
}

func replaceLocalGitChangeValue(args []string, name, value string) []string {
	result := append([]string(nil), args...)
	for i := range result {
		if result[i] == name {
			result[i+1] = value
			return result
		}
	}
	panic(name)
}

func replaceLocalGitChangeArg(args []string, old, replacement string) []string {
	result := append([]string(nil), args...)
	for i := range result {
		if result[i] == old {
			result[i] = replacement
			return result
		}
	}
	panic(old)
}

func writeLocalGitChangeFixture(t *testing.T, algorithm evidence.RevisionAlgorithm, baseContents, headContents map[string][]byte) (string, string, string) {
	t.Helper()
	objects := t.TempDir()
	baseTree := writeCLIChangeTree(t, objects, algorithm, baseContents)
	headTree := writeCLIChangeTree(t, objects, algorithm, headContents)
	baseCommit := []byte("tree " + baseTree + "\nauthor A <a@example.com> 0 +0000\ncommitter A <a@example.com> 0 +0000\n\nbase\n")
	headCommit := []byte("tree " + headTree + "\nauthor A <a@example.com> 0 +0000\ncommitter A <a@example.com> 0 +0000\n\nhead\n")
	return objects, writeCLIObject(t, objects, algorithm, "commit", baseCommit), writeCLIObject(t, objects, algorithm, "commit", headCommit)
}

func writeCLIChangeTree(t *testing.T, objects string, algorithm evidence.RevisionAlgorithm, contents map[string][]byte) string {
	t.Helper()
	paths := make([]string, 0, len(contents))
	for path := range contents {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	var tree []byte
	for _, path := range paths {
		blob := writeCLIObject(t, objects, algorithm, "blob", contents[path])
		tree = append(tree, cliTreeEntry(t, "100644", path, blob)...)
	}
	return writeCLIObject(t, objects, algorithm, "tree", tree)
}
