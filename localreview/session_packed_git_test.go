package localreview

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/scm"
)

type packedLRObject struct {
	digest string
	oid    []byte
	kind   string
	body   []byte
	offset uint64
	crc    uint32
}

func packedLRPackLooseRoot(t *testing.T, looseRoot string, algorithm evidence.RevisionAlgorithm) string {
	t.Helper()
	objects := packedLRLooseObjects(t, looseRoot, algorithm)
	if len(objects) == 0 {
		t.Fatal("no loose fixture objects to pack")
	}
	root := t.TempDir()
	packDir := filepath.Join(root, "pack")
	if err := os.MkdirAll(packDir, 0o700); err != nil {
		t.Fatal(err)
	}
	pack := []byte("PACK")
	pack = binary.BigEndian.AppendUint32(pack, 2)
	pack = binary.BigEndian.AppendUint32(pack, uint32(len(objects)))
	for i := range objects {
		entry := append(packedLRObjectHeader(packedLRType(t, objects[i].kind), len(objects[i].body)), packedLRCompress(t, objects[i].body)...)
		objects[i].offset = uint64(len(pack))
		objects[i].crc = crc32.ChecksumIEEE(entry)
		pack = append(pack, entry...)
	}
	trailer := packedLRHash(t, algorithm, pack)
	pack = append(pack, trailer...)
	idx := packedLRIndex(t, algorithm, objects, trailer)
	stem := "pack-" + hex.EncodeToString(trailer)
	if err := os.WriteFile(filepath.Join(packDir, stem+".pack"), pack, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packDir, stem+".idx"), idx, 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}

func packedLRLooseObjects(t *testing.T, root string, algorithm evidence.RevisionAlgorithm) []packedLRObject {
	t.Helper()
	var objects []packedLRObject
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if entry.Name() == "pack" {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		parts := strings.Split(rel, string(os.PathSeparator))
		if len(parts) != 2 || len(parts[0]) != 2 {
			return nil
		}
		digest := parts[0] + parts[1]
		if algorithm == evidence.RevisionAlgorithmSHA1 && len(digest) != 40 || algorithm == evidence.RevisionAlgorithmSHA256 && len(digest) != 64 {
			return nil
		}
		kind, body := packedLRPayload(t, path)
		objects = append(objects, packedLRObject{digest: digest, oid: packedLRDecode(t, digest), kind: kind, body: body})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(objects, func(i, j int) bool { return objects[i].digest < objects[j].digest })
	return objects
}

func packedLRPayload(t *testing.T, path string) (string, []byte) {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	zr, err := zlib.NewReader(io.LimitReader(file, 80<<20))
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	framed, err := io.ReadAll(io.LimitReader(zr, 80<<20))
	if err != nil {
		t.Fatal(err)
	}
	sep := bytes.IndexByte(framed, 0)
	if sep <= 0 {
		t.Fatal("bad loose object frame")
	}
	parts := strings.SplitN(string(framed[:sep]), " ", 2)
	if len(parts) != 2 {
		t.Fatal("bad loose object header")
	}
	return parts[0], append([]byte(nil), framed[sep+1:]...)
}

func packedLRType(t *testing.T, kind string) int {
	t.Helper()
	switch kind {
	case "commit":
		return 1
	case "tree":
		return 2
	case "blob":
		return 3
	default:
		t.Fatalf("unsupported fixture object kind %q", kind)
		return 0
	}
}

func packedLRObjectHeader(objectType, size int) []byte {
	first := byte(objectType<<4) | byte(size&0x0f)
	size >>= 4
	if size == 0 {
		return []byte{first}
	}
	out := []byte{first | 0x80}
	for size > 0 {
		b := byte(size & 0x7f)
		size >>= 7
		if size > 0 {
			b |= 0x80
		}
		out = append(out, b)
	}
	return out
}

func packedLRCompress(t *testing.T, body []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	zw := zlib.NewWriter(&out)
	if _, err := zw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func packedLRIndex(t *testing.T, algorithm evidence.RevisionAlgorithm, objects []packedLRObject, trailer []byte) []byte {
	t.Helper()
	sorted := append([]packedLRObject(nil), objects...)
	sort.Slice(sorted, func(i, j int) bool { return bytes.Compare(sorted[i].oid, sorted[j].oid) < 0 })
	idx := []byte{0xff, 't', 'O', 'c'}
	idx = binary.BigEndian.AppendUint32(idx, 2)
	fanout := make([]uint32, 256)
	for _, object := range sorted {
		fanout[int(object.oid[0])]++
	}
	var cumulative uint32
	for _, count := range fanout {
		cumulative += count
		idx = binary.BigEndian.AppendUint32(idx, cumulative)
	}
	for _, object := range sorted {
		idx = append(idx, object.oid...)
	}
	for _, object := range sorted {
		idx = binary.BigEndian.AppendUint32(idx, object.crc)
	}
	for _, object := range sorted {
		idx = binary.BigEndian.AppendUint32(idx, uint32(object.offset))
	}
	idx = append(idx, trailer...)
	idx = append(idx, packedLRHash(t, algorithm, idx)...)
	return idx
}

func packedLRHash(t *testing.T, algorithm evidence.RevisionAlgorithm, value []byte) []byte {
	t.Helper()
	var h hash.Hash
	if algorithm == evidence.RevisionAlgorithmSHA1 {
		h = sha1.New()
	} else if algorithm == evidence.RevisionAlgorithmSHA256 {
		h = sha256.New()
	} else {
		t.Fatalf("unsupported algorithm %q", algorithm)
	}
	if n, err := h.Write(value); err != nil || n != len(value) {
		t.Fatalf("hash write = (%d, %v)", n, err)
	}
	return h.Sum(nil)
}

func packedLRSHA256(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func packedLRDecode(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func packedLROptions(t *testing.T, f *rmModelFixture, clock *rmClock) SessionOptions {
	t.Helper()
	f.objects = packedLRPackLooseRoot(t, f.objects, evidence.RevisionAlgorithmSHA1)
	o := rmOptions(t, f, clock)
	o.ObjectStoreProfile = scm.LocalGitObjectStoreProfileLooseAndPackIndexV1
	o.ObjectAlgorithm = evidence.RevisionAlgorithmSHA1
	return o
}

func TestPackedGitSessionRunsOrdinaryReviewWithOwnedPackRoot(t *testing.T) {
	f := newRmModelFixture(t, rmModelFixtureOptions{})
	o := packedLROptions(t, f, rmNewClock())
	s := rmSession(t, o)
	p := rmPrepare(t, s, f, "packed-session")
	rmNineTasks(t, p)
	result, err := s.Run(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if result.wire.Status != "findings" || result.wire.RunStatus != "succeeded" || result.ExitCode() != 4 || result.wire.ComprehensiveClearance {
		t.Fatalf("packed session result = %#v", result.wire)
	}
	if !slices.Contains(result.wire.Limitations, "loose_and_pack_index_v1_subset") || slices.Contains(result.wire.Limitations, "loose_git_objects_only") || !slices.Contains(result.wire.Limitations, "no_publication") {
		t.Fatalf("packed session limitations = %v", result.wire.Limitations)
	}
	for _, task := range result.wire.Tasks {
		if task.Status != "succeeded" || task.Attempts != 1 || task.Output == "" {
			t.Fatal("packed session did not use the real prepared worker graph")
		}
	}
}

func TestPackedGitSessionPrepareRejectsAlgorithmDrift(t *testing.T) {
	f := newRmModelFixture(t, rmModelFixtureOptions{})
	o := packedLROptions(t, f, rmNewClock())
	s := rmSession(t, o)
	scope, err := audit.NewReviewScope(s.options.TenantID, s.options.RepositoryID, "packed-algorithm-drift")
	if err != nil {
		t.Fatal(err)
	}
	base, _ := rmRevisions(t, f)
	head, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA256, strings.Repeat("1", 64))
	if err != nil {
		t.Fatal(err)
	}
	if prepared, err := s.Prepare(context.Background(), scope, rmHash([]byte("packed-algorithm-drift")), base, head); err == nil || prepared.RequestIdentity() != "" {
		t.Fatalf("Prepare(mixed algorithms) = (%#v, %v), want refusal", prepared, err)
	}
}

func TestPackedGitSessionConstructorRefusesBeforeCredentialsAndKeepsRoot(t *testing.T) {
	f := newRmModelFixture(t, rmModelFixtureOptions{})
	rootPath := packedLRPackLooseRoot(t, f.objects, evidence.RevisionAlgorithmSHA1)
	if err := os.WriteFile(filepath.Join(rootPath, "pack", "multi-pack-index"), []byte("MIDX"), 0o600); err != nil {
		t.Fatal(err)
	}
	clock := rmNewClock()
	f.objects = rootPath
	o := rmOptions(t, f, clock)
	o.ObjectStoreProfile = scm.LocalGitObjectStoreProfileLooseAndPackIndexV1
	o.ObjectAlgorithm = evidence.RevisionAlgorithmSHA1
	forbidden := &rmForbiddenCredentials{}
	o.Credentials = forbidden
	s, err := NewSession(o)
	if err == nil || s != nil {
		t.Fatalf("NewSession(unsupported packed layout) = (%#v, %v), want refusal", s, err)
	}
	if forbidden.calls != 0 {
		t.Fatal("packed source layout refusal resolved model credentials")
	}
	if _, statErr := o.ObjectsRoot.Stat("."); statErr != nil {
		t.Fatalf("failed packed session constructor closed caller root: %v", statErr)
	}
}
