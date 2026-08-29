package scm

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

func TestLocalGitObjectStoreReadsVerifiedObjects(t *testing.T) {
	testCases := []struct {
		name      string
		algorithm evidence.RevisionAlgorithm
		kind      string
		payload   []byte
	}{
		{name: "sha1 commit", algorithm: evidence.RevisionAlgorithmSHA1, kind: "commit", payload: []byte("tree 0123456789abcdef0123456789abcdef01234567\n\nmessage\n")},
		{name: "sha256 commit", algorithm: evidence.RevisionAlgorithmSHA256, kind: "commit", payload: []byte("tree 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n\nmessage\n")},
		{name: "sha1 tree", algorithm: evidence.RevisionAlgorithmSHA1, kind: "tree", payload: []byte("tree payload")},
		{name: "sha256 tree", algorithm: evidence.RevisionAlgorithmSHA256, kind: "tree", payload: []byte("tree payload")},
		{name: "sha1 blob", algorithm: evidence.RevisionAlgorithmSHA1, kind: "blob", payload: []byte("blob payload\x00\xff")},
		{name: "sha256 blob", algorithm: evidence.RevisionAlgorithmSHA256, kind: "blob", payload: []byte("blob payload\x00\xff")},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			directory, store := newLocalGitObjectStoreFixture(t)
			digest := writeLooseObject(t, directory, testCase.algorithm, testCase.kind, testCase.payload)
			var (
				payload []byte
				err     error
			)
			switch testCase.kind {
			case "commit":
				revision := mustRevisionIdentity(t, testCase.algorithm, digest)
				payload, err = store.ReadCommit(context.Background(), revision)
			case "tree":
				payload, err = store.ReadTree(context.Background(), testCase.algorithm, digest)
			case "blob":
				payload, err = store.ReadBlob(context.Background(), testCase.algorithm, digest)
			}
			if err != nil || !bytes.Equal(payload, testCase.payload) {
				t.Fatalf("read = (%x, %v), want %x", payload, err, testCase.payload)
			}
		})
	}
}

func TestNewLocalGitObjectStoreValidatesInputs(t *testing.T) {
	repository := mustRepositoryIdentity(t)
	if store, err := NewLocalGitObjectStore(nil, repository); err == nil || store != nil {
		t.Fatalf("NewLocalGitObjectStore(nil) = (%#v, %v)", store, err)
	}
	directory := t.TempDir()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatalf("OpenRoot() error = %v", err)
	}
	if store, err := NewLocalGitObjectStore(root, evidence.RepositoryIdentity{}); err == nil || store != nil {
		t.Fatalf("NewLocalGitObjectStore(zero repository) = (%#v, %v)", store, err)
	}
	if err := root.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if store, err := NewLocalGitObjectStore(root, repository); err == nil || store != nil {
		t.Fatalf("NewLocalGitObjectStore(closed root) = (%#v, %v)", store, err)
	}
}

func TestLocalGitObjectStoreRepositoryIdentity(t *testing.T) {
	_, store := newLocalGitObjectStoreFixture(t)
	want := mustRepositoryIdentity(t).Identity()
	if got := store.RepositoryIdentity(); got != want {
		t.Fatalf("RepositoryIdentity() = %q, want %q", got, want)
	}
	var zero *LocalGitObjectStore
	if got := zero.RepositoryIdentity(); got != "" {
		t.Fatalf("nil RepositoryIdentity() = %q", got)
	}
}

func TestLocalGitObjectStoreRejectsInvalidObjectIdentities(t *testing.T) {
	_, store := newLocalGitObjectStoreFixture(t)
	invalid := []struct {
		name      string
		algorithm evidence.RevisionAlgorithm
		digest    string
	}{
		{name: "unknown algorithm", algorithm: evidence.RevisionAlgorithm("md5"), digest: strings.Repeat("1", 40)},
		{name: "short", algorithm: evidence.RevisionAlgorithmSHA1, digest: strings.Repeat("1", 39)},
		{name: "long", algorithm: evidence.RevisionAlgorithmSHA1, digest: strings.Repeat("1", 41)},
		{name: "uppercase", algorithm: evidence.RevisionAlgorithmSHA1, digest: strings.Repeat("a", 39) + "A"},
		{name: "nonhex", algorithm: evidence.RevisionAlgorithmSHA1, digest: strings.Repeat("1", 39) + "g"},
		{name: "zero sha1", algorithm: evidence.RevisionAlgorithmSHA1, digest: strings.Repeat("0", 40)},
		{name: "zero sha256", algorithm: evidence.RevisionAlgorithmSHA256, digest: strings.Repeat("0", 64)},
	}
	for _, testCase := range invalid {
		t.Run(testCase.name, func(t *testing.T) {
			payload, err := store.ReadBlob(context.Background(), testCase.algorithm, testCase.digest)
			if err == nil || payload != nil {
				t.Fatalf("ReadBlob() = (%x, %v)", payload, err)
			}
		})
	}
	if payload, err := store.ReadCommit(context.Background(), evidence.RevisionIdentity{}); err == nil || payload != nil {
		t.Fatalf("ReadCommit(zero) = (%x, %v)", payload, err)
	}
}

func TestLocalGitObjectStoreRejectsWrongTypeAndIdentity(t *testing.T) {
	directory, store := newLocalGitObjectStoreFixture(t)
	blobDigest := writeLooseObject(t, directory, evidence.RevisionAlgorithmSHA1, "blob", []byte("payload"))
	if payload, err := store.ReadTree(context.Background(), evidence.RevisionAlgorithmSHA1, blobDigest); err == nil || payload != nil {
		t.Fatalf("ReadTree(blob) = (%x, %v)", payload, err)
	}
	otherDigest := gitObjectDigest(evidence.RevisionAlgorithmSHA1, []byte("blob 5\x00other"))
	writeObjectFile(t, directory, otherDigest, compressLooseBytes(t, []byte("blob 7\x00payload")))
	if payload, err := store.ReadBlob(context.Background(), evidence.RevisionAlgorithmSHA1, otherDigest); err == nil || payload != nil {
		t.Fatalf("ReadBlob(mismatched identity) = (%x, %v)", payload, err)
	}
}

func TestLocalGitObjectStoreRejectsMalformedLooseObjects(t *testing.T) {
	testCases := []struct {
		name string
		raw  func(*testing.T) []byte
	}{
		{name: "not zlib", raw: func(*testing.T) []byte { return []byte("not zlib") }},
		{name: "missing nul", raw: func(t *testing.T) []byte { return compressLooseBytes(t, []byte("blob 1x")) }},
		{name: "missing space", raw: func(t *testing.T) []byte { return compressLooseBytes(t, []byte("blob\x00")) }},
		{name: "noncanonical size", raw: func(t *testing.T) []byte { return compressLooseBytes(t, []byte("blob 01\x00x")) }},
		{name: "signed size", raw: func(t *testing.T) []byte { return compressLooseBytes(t, []byte("blob +1\x00x")) }},
		{name: "nondigit size", raw: func(t *testing.T) []byte { return compressLooseBytes(t, []byte("blob x\x00x")) }},
		{name: "short payload", raw: func(t *testing.T) []byte { return compressLooseBytes(t, []byte("blob 2\x00x")) }},
		{name: "trailing decompressed", raw: func(t *testing.T) []byte { return compressLooseBytes(t, []byte("blob 1\x00xy")) }},
		{name: "oversized header", raw: func(t *testing.T) []byte {
			return compressLooseBytes(t, append(bytes.Repeat([]byte("x"), maxLooseObjectHeaderBytes+1), 0))
		}},
		{name: "oversized declared payload", raw: func(t *testing.T) []byte {
			return compressLooseBytes(t, []byte(fmt.Sprintf("blob %d\x00", maxGitBlobPayloadBytes+1)))
		}},
		{name: "bad checksum", raw: func(t *testing.T) []byte {
			raw := compressLooseBytes(t, []byte("blob 1\x00x"))
			raw[len(raw)-1] ^= 0xff
			return raw
		}},
		{name: "trailing compressed", raw: func(t *testing.T) []byte { return append(compressLooseBytes(t, []byte("blob 1\x00x")), 0) }},
	}
	for i, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			directory, store := newLocalGitObjectStoreFixture(t)
			digest := fmt.Sprintf("%040x", i+1)
			writeObjectFile(t, directory, digest, testCase.raw(t))
			payload, err := store.ReadBlob(context.Background(), evidence.RevisionAlgorithmSHA1, digest)
			if err == nil || payload != nil {
				t.Fatalf("ReadBlob() = (%x, %v)", payload, err)
			}
		})
	}
}

func TestLocalGitObjectStoreRejectsNonregularAndEscapingObjects(t *testing.T) {
	t.Run("directory", func(t *testing.T) {
		directory, store := newLocalGitObjectStoreFixture(t)
		digest := strings.Repeat("1", 40)
		if err := os.MkdirAll(filepath.Join(directory, digest[:2], digest[2:]), 0o700); err != nil {
			t.Fatalf("MkdirAll() error = %v", err)
		}
		payload, err := store.ReadBlob(context.Background(), evidence.RevisionAlgorithmSHA1, digest)
		if err == nil || payload != nil || !strings.Contains(err.Error(), "is not a regular file") {
			t.Fatalf("ReadBlob(directory) = (%x, %v)", payload, err)
		}
	})
	t.Run("escaping symlink", func(t *testing.T) {
		directory, store := newLocalGitObjectStoreFixture(t)
		digest := strings.Repeat("2", 40)
		outside := filepath.Join(t.TempDir(), "object")
		if err := os.WriteFile(outside, compressLooseBytes(t, []byte("blob 1\x00x")), 0o600); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}
		objectPath := filepath.Join(directory, digest[:2], digest[2:])
		if err := os.MkdirAll(filepath.Dir(objectPath), 0o700); err != nil {
			t.Fatalf("MkdirAll() error = %v", err)
		}
		if err := os.Symlink(outside, objectPath); err != nil {
			t.Skipf("Symlink() error = %v", err)
		}
		payload, err := store.ReadBlob(context.Background(), evidence.RevisionAlgorithmSHA1, digest)
		if err == nil || payload != nil {
			t.Fatalf("ReadBlob(escaping symlink) = (%x, %v)", payload, err)
		}
	})
}

func TestLocalGitObjectStoreRejectsFIFOWithoutBlocking(t *testing.T) {
	if rootPath := os.Getenv("OPEN_TRESTLE_FIFO_ROOT"); rootPath != "" {
		root, err := os.OpenRoot(rootPath)
		if err != nil {
			t.Fatalf("OpenRoot() error = %v", err)
		}
		defer root.Close()
		store, err := NewLocalGitObjectStore(root, mustRepositoryIdentity(t))
		if err != nil {
			t.Fatalf("NewLocalGitObjectStore() error = %v", err)
		}
		payload, err := store.ReadBlob(context.Background(), evidence.RevisionAlgorithmSHA1, strings.Repeat("3", 40))
		if err == nil || payload != nil || !strings.Contains(err.Error(), "is not a regular file") {
			t.Fatalf("ReadBlob(FIFO) = (%x, %v)", payload, err)
		}
		return
	}
	if runtime.GOOS == "windows" || runtime.GOOS == "plan9" || runtime.GOOS == "js" {
		t.Skip("named FIFO fixture is unavailable")
	}
	mkfifo, err := exec.LookPath("mkfifo")
	if err != nil {
		t.Skip("mkfifo is unavailable")
	}
	directory := t.TempDir()
	digest := strings.Repeat("3", 40)
	objectPath := filepath.Join(directory, digest[:2], digest[2:])
	if err := os.MkdirAll(filepath.Dir(objectPath), 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if output, err := exec.Command(mkfifo, objectPath).CombinedOutput(); err != nil {
		t.Fatalf("mkfifo: %v: %s", err, output)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLocalGitObjectStoreRejectsFIFOWithoutBlocking$")
	command.Env = append(os.Environ(), "OPEN_TRESTLE_FIFO_ROOT="+directory)
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("FIFO read blocked: %v: %s", ctx.Err(), output)
	}
	if err != nil {
		t.Fatalf("FIFO child: %v: %s", err, output)
	}
}

func TestLocalGitObjectStoreHonorsCancellation(t *testing.T) {
	t.Run("before open", func(t *testing.T) {
		directory, store := newLocalGitObjectStoreFixture(t)
		digest := writeLooseObject(t, directory, evidence.RevisionAlgorithmSHA1, "blob", []byte("payload"))
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := store.objectsRoot.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
		payload, err := store.ReadBlob(ctx, evidence.RevisionAlgorithmSHA1, digest)
		if !errors.Is(err, context.Canceled) || payload != nil {
			t.Fatalf("ReadBlob() = (%x, %v)", payload, err)
		}
	})
	t.Run("during decode", func(t *testing.T) {
		directory, store := newLocalGitObjectStoreFixture(t)
		digest := writeLooseObject(t, directory, evidence.RevisionAlgorithmSHA1, "blob", bytes.Repeat([]byte("x"), 1<<20))
		ctx := newCancelAfterChecksContext(8)
		payload, err := store.ReadBlob(ctx, evidence.RevisionAlgorithmSHA1, digest)
		if !errors.Is(err, context.Canceled) || payload != nil {
			t.Fatalf("ReadBlob() = (%x, %v)", payload, err)
		}
	})
	if _, err := (&LocalGitObjectStore{}).ReadBlob(context.Background(), evidence.RevisionAlgorithmSHA1, strings.Repeat("1", 40)); err == nil {
		t.Fatal("zero store read succeeded")
	}
	if _, store := newLocalGitObjectStoreFixture(t); true {
		if _, err := store.ReadBlob(nil, evidence.RevisionAlgorithmSHA1, strings.Repeat("1", 40)); err == nil {
			t.Fatal("nil context read succeeded")
		}
	}
}

func TestLocalGitObjectStoreRejectsClosedRoot(t *testing.T) {
	directory, store := newLocalGitObjectStoreFixture(t)
	digest := writeLooseObject(t, directory, evidence.RevisionAlgorithmSHA1, "blob", []byte("payload"))
	if err := store.objectsRoot.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	payload, err := store.ReadBlob(context.Background(), evidence.RevisionAlgorithmSHA1, digest)
	if err == nil || payload != nil {
		t.Fatalf("ReadBlob() = (%x, %v)", payload, err)
	}
}

func TestLocalGitObjectStoreDoesNotCachePayloads(t *testing.T) {
	directory, store := newLocalGitObjectStoreFixture(t)
	want := []byte("payload")
	digest := writeLooseObject(t, directory, evidence.RevisionAlgorithmSHA1, "blob", want)
	first, err := store.ReadBlob(context.Background(), evidence.RevisionAlgorithmSHA1, digest)
	if err != nil {
		t.Fatalf("first ReadBlob() error = %v", err)
	}
	first[0] = 'X'
	second, err := store.ReadBlob(context.Background(), evidence.RevisionAlgorithmSHA1, digest)
	if err != nil || !bytes.Equal(second, want) {
		t.Fatalf("second ReadBlob() = (%q, %v), want %q", second, err, want)
	}
}

func TestLocalGitObjectStoreSupportsConcurrentReads(t *testing.T) {
	directory, store := newLocalGitObjectStoreFixture(t)
	want := []byte("payload")
	digest := writeLooseObject(t, directory, evidence.RevisionAlgorithmSHA256, "blob", want)
	var wait sync.WaitGroup
	errorsFound := make(chan error, 8)
	for range 8 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			payload, err := store.ReadBlob(context.Background(), evidence.RevisionAlgorithmSHA256, digest)
			if err != nil {
				errorsFound <- err
				return
			}
			if !bytes.Equal(payload, want) {
				errorsFound <- fmt.Errorf("payload = %q", payload)
			}
		}()
	}
	wait.Wait()
	close(errorsFound)
	for err := range errorsFound {
		t.Error(err)
	}
}

func TestReadLooseObjectPayloadRejectsTrailingByteReturnedWithEOF(t *testing.T) {
	reader := &finalByteEOFReader{content: []byte("blob 1\x00xy")}
	if _, _, err := readLooseObjectPayload(reader, "blob", maxGitBlobPayloadBytes); err == nil {
		t.Fatal("readLooseObjectPayload() accepted trailing byte")
	}
}

func TestLooseObjectBounds(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		limit int64
	}{
		{name: "commit", limit: maxGitCommitPayloadBytes},
		{name: "tree", limit: maxGitTreePayloadBytes},
		{name: "blob", limit: maxGitBlobPayloadBytes},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			text := fmt.Sprintf("%d", testCase.limit)
			if got, err := parseCanonicalLooseObjectSize(text, testCase.limit); err != nil || got != testCase.limit {
				t.Fatalf("parse exact = (%d, %v)", got, err)
			}
			if _, err := parseCanonicalLooseObjectSize(fmt.Sprintf("%d", testCase.limit+1), testCase.limit); err == nil {
				t.Fatal("parse limit + 1 succeeded")
			}
		})
	}
	if err := validateLooseObjectCompressedSize(maxLooseObjectCompressedBytes); err != nil {
		t.Fatalf("validate exact compressed size: %v", err)
	}
	if err := validateLooseObjectCompressedSize(maxLooseObjectCompressedBytes + 1); err == nil {
		t.Fatal("validate compressed limit + 1 succeeded")
	}
	for _, value := range []string{"", "00", "01", "+1", "-1", "1x", strings.Repeat("9", 128)} {
		if _, err := parseCanonicalLooseObjectSize(value, maxGitBlobPayloadBytes); err == nil {
			t.Fatalf("parseCanonicalLooseObjectSize(%q) succeeded", value)
		}
	}
	if _, err := parseCanonicalLooseObjectSize("0", -1); err == nil {
		t.Fatal("parseCanonicalLooseObjectSize() accepted a negative limit")
	}
	if _, err := parseCanonicalLooseObjectSize("1", 0); err == nil {
		t.Fatal("parseCanonicalLooseObjectSize() accepted limit + 1")
	}
}

func newLocalGitObjectStoreFixture(t *testing.T) (string, *LocalGitObjectStore) {
	t.Helper()
	directory := t.TempDir()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatalf("OpenRoot() error = %v", err)
	}
	t.Cleanup(func() { _ = root.Close() })
	store, err := NewLocalGitObjectStore(root, mustRepositoryIdentity(t))
	if err != nil {
		t.Fatalf("NewLocalGitObjectStore() error = %v", err)
	}
	return directory, store
}

func mustRepositoryIdentity(t *testing.T) evidence.RepositoryIdentity {
	t.Helper()
	repository, err := evidence.NewRepositoryIdentity("git.example.com", []string{"team"}, "repo")
	if err != nil {
		t.Fatalf("NewRepositoryIdentity() error = %v", err)
	}
	return repository
}

func mustRevisionIdentity(t *testing.T, algorithm evidence.RevisionAlgorithm, digest string) evidence.RevisionIdentity {
	t.Helper()
	revision, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, algorithm, digest)
	if err != nil {
		t.Fatalf("NewRevisionIdentity() error = %v", err)
	}
	return revision
}

func writeLooseObject(t *testing.T, directory string, algorithm evidence.RevisionAlgorithm, kind string, payload []byte) string {
	t.Helper()
	framing := []byte(fmt.Sprintf("%s %d\x00", kind, len(payload)))
	framing = append(framing, payload...)
	digest := gitObjectDigest(algorithm, framing)
	writeObjectFile(t, directory, digest, compressLooseBytes(t, framing))
	return digest
}

func writeObjectFile(t *testing.T, directory, digest string, content []byte) {
	t.Helper()
	path := filepath.Join(directory, digest[:2], digest[2:])
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
}

func compressLooseBytes(t *testing.T, content []byte) []byte {
	t.Helper()
	var output bytes.Buffer
	writer := zlib.NewWriter(&output)
	if _, err := writer.Write(content); err != nil {
		t.Fatalf("zlib Write() error = %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("zlib Close() error = %v", err)
	}
	return output.Bytes()
}

func gitObjectDigest(algorithm evidence.RevisionAlgorithm, framing []byte) string {
	switch algorithm {
	case evidence.RevisionAlgorithmSHA1:
		digest := sha1.Sum(framing)
		return hex.EncodeToString(digest[:])
	case evidence.RevisionAlgorithmSHA256:
		digest := sha256.Sum256(framing)
		return hex.EncodeToString(digest[:])
	default:
		return ""
	}
}

type cancelAfterChecksContext struct {
	context.Context
	limit int32
	calls atomic.Int32
	done  chan struct{}
	once  sync.Once
}

func newCancelAfterChecksContext(limit int32) *cancelAfterChecksContext {
	return &cancelAfterChecksContext{Context: context.Background(), limit: limit, done: make(chan struct{})}
}

func (c *cancelAfterChecksContext) Done() <-chan struct{} {
	return c.done
}

func (c *cancelAfterChecksContext) Err() error {
	if c.calls.Add(1) < c.limit {
		return nil
	}
	c.once.Do(func() { close(c.done) })
	return context.Canceled
}

type finalByteEOFReader struct {
	content []byte
}

func (r *finalByteEOFReader) Read(buffer []byte) (int, error) {
	if len(r.content) == 0 {
		return 0, io.EOF
	}
	read := copy(buffer, r.content[:1])
	r.content = r.content[read:]
	if len(r.content) == 0 {
		return read, io.EOF
	}
	return read, nil
}
