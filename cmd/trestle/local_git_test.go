package main

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/scm"
)

func TestRunLocalGitInspectEmitsExactEnvelopeIdentities(t *testing.T) {
	for _, algorithm := range []evidence.RevisionAlgorithm{evidence.RevisionAlgorithmSHA1, evidence.RevisionAlgorithmSHA256} {
		t.Run(string(algorithm), func(t *testing.T) {
			objects, digest, secret := writeLocalGitInspectFixture(t, algorithm, false)
			args := localGitInspectArgs(objects, algorithm, digest)
			var stdout, stderr bytes.Buffer
			if code := run(append([]string{"local-git", "inspect"}, args...), &stdout, &stderr); code != 0 || stderr.Len() != 0 {
				t.Fatalf("run() = %d, stderr = %q", code, stderr.String())
			}
			first := stdout.String()
			stdout.Reset()
			if code := run(append([]string{"local-git", "inspect"}, args...), &stdout, &stderr); code != 0 || stdout.String() != first {
				t.Fatalf("repeat = %d, output = %q, want %q", code, stdout.String(), first)
			}
			if strings.Count(first, "\n") != 1 || !strings.HasSuffix(first, "\n") {
				t.Fatalf("output framing = %q", first)
			}
			var got localGitInspectResult
			if err := json.Unmarshal([]byte(first), &got); err != nil {
				t.Fatalf("Unmarshal() error = %v", err)
			}
			want := expectedLocalGitInspectResult(t, objects, algorithm, digest)
			if got != want {
				t.Fatalf("result = %#v, want %#v", got, want)
			}
			for _, forbidden := range []string{objects, "example.test", "private", "sample", digest, secret, "nested/main.go"} {
				if strings.Contains(first, forbidden) {
					t.Fatalf("output contains forbidden input %q", forbidden)
				}
			}
		})
	}
}

func TestRunLocalGitInspectAcceptsEmptyRevision(t *testing.T) {
	objects, digest, _ := writeLocalGitInspectFixture(t, evidence.RevisionAlgorithmSHA1, true)
	var stdout, stderr bytes.Buffer
	if code := run(append([]string{"local-git", "inspect"}, localGitInspectArgs(objects, evidence.RevisionAlgorithmSHA1, digest)...), &stdout, &stderr); code != 0 || stderr.Len() != 0 {
		t.Fatalf("run() = %d, stderr = %q", code, stderr.String())
	}
	var result localGitInspectResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil || result.ProfileBundleIdentity == "" || result.ContentCoverage != "complete" {
		t.Fatalf("empty result = (%#v, %v)", result, err)
	}
}

func TestRunLocalGitInspectRejectsInvalidArgumentsBeforeOpen(t *testing.T) {
	valid := localGitInspectArgs("objects", evidence.RevisionAlgorithmSHA1, strings.Repeat("1", 40))
	tests := map[string][]string{
		"missing":      valid[:10],
		"unknown":      append(append([]string{}, valid...), "--other", "x"),
		"duplicate":    append(append([]string{}, valid...), "--objects-root", "other"),
		"extra":        append(append([]string{}, valid...), "extra"),
		"equals":       append([]string{"--objects-root=objects"}, valid[2:]...),
		"empty":        append([]string{"--objects-root", ""}, valid[2:]...),
		"namespace":    replaceLocalGitInspectArg(valid, "--repository-namespace", "private//team"),
		"algorithm":    replaceLocalGitInspectArg(valid, "--revision-algorithm", "md5"),
		"short digest": replaceLocalGitInspectArg(valid, "--revision-digest", "12"),
		"uppercase":    replaceLocalGitInspectArg(valid, "--revision-digest", strings.Repeat("A", 40)),
		"zero":         replaceLocalGitInspectArg(valid, "--revision-digest", strings.Repeat("0", 40)),
		"nonhex":       replaceLocalGitInspectArg(valid, "--revision-digest", strings.Repeat("z", 40)),
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			opens := 0
			opener := func(string) (localGitRootHandle, error) {
				opens++
				return localGitRootHandle{}, errors.New("unexpected open")
			}
			var stdout, stderr bytes.Buffer
			if code := runLocalGitInspectWithOpener(args, &stdout, &stderr, opener); code != 2 || opens != 0 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "usage: trestle local-git inspect") {
				t.Fatalf("result = %d, opens = %d, stdout = %q, stderr = %q", code, opens, stdout.String(), stderr.String())
			}
		})
	}
}

func TestRunLocalGitInspectFailuresDoNotDiscloseInputs(t *testing.T) {
	rootPath := "/secret/object/root"
	digest := strings.Repeat("1", 40)
	malformed := localGitInspectArgs("objects", evidence.RevisionAlgorithmSHA1, digest)
	malformed[0] = "--objects-root=" + rootPath
	var parseStdout, parseStderr bytes.Buffer
	if code := runLocalGitInspectWithOpener(malformed, &parseStdout, &parseStderr, func(string) (localGitRootHandle, error) { return localGitRootHandle{}, errors.New("unexpected open") }); code != 2 || strings.Contains(parseStderr.String(), rootPath) {
		t.Fatalf("parse failure = %d, stderr = %q", code, parseStderr.String())
	}

	args := localGitInspectArgs(rootPath, evidence.RevisionAlgorithmSHA1, digest)
	opener := func(string) (localGitRootHandle, error) {
		return localGitRootHandle{}, errors.New("open " + rootPath + ": denied")
	}
	var stdout, stderr bytes.Buffer
	if code := runLocalGitInspectWithOpener(args, &stdout, &stderr, opener); code != 1 || stdout.Len() != 0 || strings.Contains(stderr.String(), rootPath) {
		t.Fatalf("open failure = %d, stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
	}

	objects := t.TempDir()
	stderr.Reset()
	args = localGitInspectArgs(objects, evidence.RevisionAlgorithmSHA1, digest)
	if code := runLocalGitInspectWithOpener(args, &stdout, &stderr, openLocalGitRoot); code != 1 || strings.Contains(stderr.String(), objects) || strings.Contains(stderr.String(), digest) || strings.Contains(stderr.String(), digest[:2]+"/"+digest[2:]) {
		t.Fatalf("inspect failure = %d, stderr = %q", code, stderr.String())
	}
}

func TestRunLocalGitInspectUsesExactRootWithoutDiscovery(t *testing.T) {
	objects, digest, _ := writeLocalGitInspectFixture(t, evidence.RevisionAlgorithmSHA1, false)
	var stdout, stderr bytes.Buffer
	args := localGitInspectArgs(filepath.Dir(objects), evidence.RevisionAlgorithmSHA1, digest)
	if code := run(append([]string{"local-git", "inspect"}, args...), &stdout, &stderr); code != 1 || stdout.Len() != 0 {
		t.Fatalf("parent root = %d, stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
	}
}

func TestRunLocalGitInspectClosesBeforeOutputAndSuppressesCloseFailure(t *testing.T) {
	objects, digest, _ := writeLocalGitInspectFixture(t, evidence.RevisionAlgorithmSHA1, false)
	args := localGitInspectArgs(objects, evidence.RevisionAlgorithmSHA1, digest)
	for _, closeErr := range []error{nil, errors.New("close failed")} {
		root, err := os.OpenRoot(objects)
		if err != nil {
			t.Fatal(err)
		}
		closed := 0
		opener := func(string) (localGitRootHandle, error) {
			return localGitRootHandle{root: root, close: func() error {
				closed++
				if err := root.Close(); err != nil {
					return err
				}
				return closeErr
			}}, nil
		}
		writer := &closeAwareWriter{closed: &closed}
		var stderr bytes.Buffer
		code := runLocalGitInspectWithOpener(args, writer, &stderr, opener)
		if closed != 1 {
			t.Fatalf("close count = %d", closed)
		}
		if closeErr == nil {
			if code != 0 || !writer.wroteAfterClose {
				t.Fatalf("success = %d, after close = %v", code, writer.wroteAfterClose)
			}
		} else if code != 1 || writer.Len() != 0 || !strings.Contains(stderr.String(), "close object root") {
			t.Fatalf("close failure = %d, stdout = %q, stderr = %q", code, writer.String(), stderr.String())
		}
	}
}

func TestRunLocalGitInspectClosesInvalidInjectedHandle(t *testing.T) {
	objects, digest, _ := writeLocalGitInspectFixture(t, evidence.RevisionAlgorithmSHA1, false)
	root, err := os.OpenRoot(objects)
	if err != nil {
		t.Fatal(err)
	}
	opener := func(string) (localGitRootHandle, error) { return localGitRootHandle{root: root}, nil }
	var stdout, stderr bytes.Buffer
	if code := runLocalGitInspectWithOpener(localGitInspectArgs(objects, evidence.RevisionAlgorithmSHA1, digest), &stdout, &stderr, opener); code != 1 || stdout.Len() != 0 {
		t.Fatalf("invalid handle = %d, stdout = %q", code, stdout.String())
	}
	if _, err := root.Stat("."); err == nil {
		t.Fatal("injected root remained open")
	}
}

func TestRunLocalGitInspectClosesAfterExecutionAndWriteFailures(t *testing.T) {
	objects := t.TempDir()
	args := localGitInspectArgs(objects, evidence.RevisionAlgorithmSHA1, strings.Repeat("1", 40))
	closed := 0
	root, err := os.OpenRoot(objects)
	if err != nil {
		t.Fatal(err)
	}
	opener := func(string) (localGitRootHandle, error) {
		return localGitRootHandle{root: root, close: func() error { closed++; return root.Close() }}, nil
	}
	var stdout, stderr bytes.Buffer
	if code := runLocalGitInspectWithOpener(args, &stdout, &stderr, opener); code != 1 || closed != 1 || stdout.Len() != 0 {
		t.Fatalf("execution failure = %d, closed = %d", code, closed)
	}

	objects, digest, _ := writeLocalGitInspectFixture(t, evidence.RevisionAlgorithmSHA1, false)
	var errout bytes.Buffer
	if code := runLocalGitInspectWithOpener(localGitInspectArgs(objects, evidence.RevisionAlgorithmSHA1, digest), errorWriter{}, &errout, openLocalGitRoot); code != 1 || !strings.Contains(errout.String(), "write result") {
		t.Fatalf("write failure = %d, stderr = %q", code, errout.String())
	}
	errout.Reset()
	if code := runLocalGitInspectWithOpener(localGitInspectArgs(objects, evidence.RevisionAlgorithmSHA1, digest), shortWriter{}, &errout, openLocalGitRoot); code != 1 || !strings.Contains(errout.String(), "write result") {
		t.Fatalf("short write = %d, stderr = %q", code, errout.String())
	}
}

func expectedLocalGitInspectResult(t *testing.T, objects string, algorithm evidence.RevisionAlgorithm, digest string) localGitInspectResult {
	t.Helper()
	repository, err := evidence.NewRepositoryIdentity("example.test", []string{"private", "team"}, "sample")
	if err != nil {
		t.Fatal(err)
	}
	revision, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, algorithm, digest)
	if err != nil {
		t.Fatal(err)
	}
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
	request, err := evidence.NewRepositoryAcquisitionRequest(repository, revision, adapter.Identity(), evidence.AcquisitionArtifactManifestAndContent, evidence.AcquisitionEffectReadOnly)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := scm.ExecuteLocalGitAcquisitionWithBindingAndProfile(context.Background(), request, adapter)
	if err != nil {
		t.Fatal(err)
	}
	result, err := newLocalGitInspectResult(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func localGitInspectArgs(objects string, algorithm evidence.RevisionAlgorithm, digest string) []string {
	return []string{"--objects-root", objects, "--repository-authority", "example.test", "--repository-namespace", "private/team", "--repository-name", "sample", "--revision-algorithm", string(algorithm), "--revision-digest", digest}
}

func replaceLocalGitInspectArg(args []string, name, value string) []string {
	result := append([]string(nil), args...)
	for i := range result {
		if result[i] == name {
			result[i+1] = value
			return result
		}
	}
	panic(name)
}

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }

type closeAwareWriter struct {
	bytes.Buffer
	closed          *int
	wroteAfterClose bool
}

func (w *closeAwareWriter) Write(p []byte) (int, error) {
	w.wroteAfterClose = *w.closed == 1
	return w.Buffer.Write(p)
}

func writeLocalGitInspectFixture(t *testing.T, algorithm evidence.RevisionAlgorithm, empty bool) (string, string, string) {
	t.Helper()
	objects := t.TempDir()
	var rootTree []byte
	secret := "SENTINEL_BLOB_CONTENT_7481"
	if !empty {
		blob := writeCLIObject(t, objects, algorithm, "blob", []byte(secret+"\n"))
		child := writeCLIObject(t, objects, algorithm, "tree", cliTreeEntry(t, "100644", "main.go", blob))
		rootTree = cliTreeEntry(t, "40000", "nested", child)
	}
	tree := writeCLIObject(t, objects, algorithm, "tree", rootTree)
	commit := []byte("tree " + tree + "\nauthor A <a@example.com> 0 +0000\ncommitter A <a@example.com> 0 +0000\n\nmessage\n")
	return objects, writeCLIObject(t, objects, algorithm, "commit", commit), secret
}

func cliTreeEntry(t *testing.T, mode, name, digest string) []byte {
	t.Helper()
	object, err := hex.DecodeString(digest)
	if err != nil {
		t.Fatal(err)
	}
	return append(append([]byte(mode+" "+name), 0), object...)
}

func writeCLIObject(t *testing.T, objects string, algorithm evidence.RevisionAlgorithm, kind string, payload []byte) string {
	t.Helper()
	framed := append([]byte(fmt.Sprintf("%s %d\x00", kind, len(payload))), payload...)
	var digest string
	if algorithm == evidence.RevisionAlgorithmSHA1 {
		sum := sha1.Sum(framed)
		digest = hex.EncodeToString(sum[:])
	} else {
		sum := sha256.Sum256(framed)
		digest = hex.EncodeToString(sum[:])
	}
	dir := filepath.Join(objects, digest[:2])
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	file, err := os.Create(filepath.Join(dir, digest[2:]))
	if err != nil {
		t.Fatal(err)
	}
	zw := zlib.NewWriter(file)
	if _, err := zw.Write(framed); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return digest
}

var _ io.Writer = (*closeAwareWriter)(nil)
