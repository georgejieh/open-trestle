package main

import (
	"bytes"
	"compress/zlib"
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

	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/scm"
)

type packedCLILooseObject struct {
	digest string
	oid    []byte
	kind   string
	body   []byte
	offset uint64
	crc    uint32
}

func packedCLINewModelFixture(t *testing.T, options localModelFixtureOptions) *localModelFixture {
	t.Helper()
	f := newLocalModelFixture(t, options)
	f.objects = packedCLIPackLooseRoot(t, f.objects, evidence.RevisionAlgorithmSHA1)
	f.args = packedCLIWithObjectStore(packedCLIReplaceArg(f.args, "--objects-root", f.objects))
	return f
}

func packedCLIReplaceArg(args []string, name, value string) []string {
	result := append([]string(nil), args...)
	for i := range result {
		if result[i] == name && i+1 < len(result) {
			result[i+1] = value
			return result
		}
	}
	panic(name)
}

func packedCLIWithObjectStore(args []string) []string {
	for _, arg := range args {
		if arg == "--object-store" {
			return args
		}
	}
	return append(append([]string(nil), args...), "--object-store", string(scm.LocalGitObjectStoreProfileLooseAndPackIndexV1))
}

func packedCLIPackLooseRoot(t *testing.T, looseRoot string, algorithm evidence.RevisionAlgorithm) string {
	t.Helper()
	objects := packedCLIReadLooseObjects(t, looseRoot, algorithm)
	if len(objects) == 0 {
		t.Fatal("fixture did not contain loose objects to pack")
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
		entry := append(packedCLIObjectHeader(packedCLIType(t, objects[i].kind), len(objects[i].body)), packedCLICompress(t, objects[i].body)...)
		objects[i].offset = uint64(len(pack))
		objects[i].crc = crc32.ChecksumIEEE(entry)
		pack = append(pack, entry...)
	}
	packTrailer := packedCLIHashBytes(t, algorithm, pack)
	pack = append(pack, packTrailer...)
	idx := packedCLIBuildIndex(t, algorithm, objects, packTrailer)
	stem := "pack-" + hex.EncodeToString(packTrailer)
	if err := os.WriteFile(filepath.Join(packDir, stem+".pack"), pack, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packDir, stem+".idx"), idx, 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}

func packedCLIReadLooseObjects(t *testing.T, root string, algorithm evidence.RevisionAlgorithm) []packedCLILooseObject {
	t.Helper()
	var objects []packedCLILooseObject
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
		if len(digest) != packedCLIDigestLength(t, algorithm) {
			return nil
		}
		kind, body := packedCLILoosePayload(t, path)
		objects = append(objects, packedCLILooseObject{digest: digest, oid: packedCLIDecodeHex(t, digest), kind: kind, body: body})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(objects, func(i, j int) bool { return objects[i].digest < objects[j].digest })
	return objects
}

func packedCLILoosePayload(t *testing.T, path string) (string, []byte) {
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
		t.Fatal("loose fixture object lacks framing")
	}
	parts := strings.SplitN(string(framed[:sep]), " ", 2)
	if len(parts) != 2 {
		t.Fatal("loose fixture object lacks typed framing")
	}
	return parts[0], append([]byte(nil), framed[sep+1:]...)
}

func packedCLIType(t *testing.T, kind string) int {
	t.Helper()
	switch kind {
	case "commit":
		return 1
	case "tree":
		return 2
	case "blob":
		return 3
	default:
		t.Fatalf("unsupported loose fixture kind %q", kind)
		return 0
	}
}

func packedCLIObjectHeader(objectType, size int) []byte {
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

func packedCLICompress(t *testing.T, body []byte) []byte {
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

func packedCLIBuildIndex(t *testing.T, algorithm evidence.RevisionAlgorithm, objects []packedCLILooseObject, packTrailer []byte) []byte {
	t.Helper()
	sorted := append([]packedCLILooseObject(nil), objects...)
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
	idx = append(idx, packTrailer...)
	idx = append(idx, packedCLIHashBytes(t, algorithm, idx)...)
	return idx
}

func packedCLIHashBytes(t *testing.T, algorithm evidence.RevisionAlgorithm, value []byte) []byte {
	t.Helper()
	var h hash.Hash
	switch algorithm {
	case evidence.RevisionAlgorithmSHA1:
		h = sha1.New()
	case evidence.RevisionAlgorithmSHA256:
		h = sha256.New()
	default:
		t.Fatalf("unsupported algorithm %q", algorithm)
	}
	if n, err := h.Write(value); err != nil || n != len(value) {
		t.Fatalf("hash write = (%d, %v)", n, err)
	}
	return h.Sum(nil)
}

func packedCLISHA256Hex(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func packedCLIDecodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func packedCLIDigestLength(t *testing.T, algorithm evidence.RevisionAlgorithm) int {
	t.Helper()
	if algorithm == evidence.RevisionAlgorithmSHA1 {
		return 40
	}
	if algorithm == evidence.RevisionAlgorithmSHA256 {
		return 64
	}
	t.Fatalf("unsupported algorithm %q", algorithm)
	return 0
}

func TestRunLocalGitPackedModelReviewCompletesNineTaskGraph(t *testing.T) {
	f := packedCLINewModelFixture(t, localModelFixtureOptions{})
	result, _ := localModelExecute(t, f, f.args, 4)
	generationCalls, generated := f.generation.snapshot()
	verificationCalls, verified := f.verification.snapshot()
	if generationCalls != 1 || verificationCalls != 1 || len(generated) != 1 || len(verified) != 1 {
		t.Fatal("packed model review did not use real loopback generation and verification")
	}
	if result.Status != "findings" || result.CI != "blocked" || result.RunStatus != "succeeded" || result.ComprehensiveClearance {
		t.Fatal("packed review forged success semantics or clearance")
	}
	keys := []string{}
	for _, task := range result.Tasks {
		keys = append(keys, task.Key)
		if task.Status != "succeeded" || task.Attempts != 1 || task.Output == "" {
			t.Fatal("packed run did not finish each admitted task exactly once")
		}
	}
	slices.Sort(keys)
	if !slices.Equal(keys, []string{"analysis", "candidates", "change", "context", "memory", "readiness", "source-base", "source-head", "verification"}) {
		t.Fatalf("packed run keys = %v", keys)
	}
	if !slices.Contains(result.Limitations, "loose_and_pack_index_v1_subset") || slices.Contains(result.Limitations, "loose_git_objects_only") || !slices.Contains(result.Limitations, "bounded_source_context") || !slices.Contains(result.Limitations, "no_publication") {
		t.Fatalf("packed limitations = %v", result.Limitations)
	}
	if result.Context != generated[0].ContextID || result.GenerationRequest != generated[0].RequestID || result.VerificationRequest != verified[0].RequestID || result.VerificationContext != verified[0].ContextID || len(result.CandidateIDs) != 1 {
		t.Fatal("packed result is disconnected from actual model-visible packets")
	}
	if result.Diagnostics.SourceCoverage.Selected == 0 || result.Diagnostics.Coverage.VerifiedCount != 1 || len(result.Diagnostics.Findings) != 1 {
		t.Fatal("packed source acquisition did not feed ordinary review diagnostics")
	}
	for _, event := range result.Audit {
		if strings.HasPrefix(event.Kind, "publication_") {
			t.Fatal("packed read-only review gained publication authority")
		}
	}
}

func TestRunLocalGitPackedModelReviewRequiresExplicitOptIn(t *testing.T) {
	f := newLocalModelFixture(t, localModelFixtureOptions{})
	f.objects = packedCLIPackLooseRoot(t, f.objects, evidence.RevisionAlgorithmSHA1)
	f.args = packedCLIReplaceArg(f.args, "--objects-root", f.objects)
	result, _ := localModelExecute(t, f, f.args, 3)
	generationCalls, _ := f.generation.snapshot()
	verificationCalls, _ := f.verification.snapshot()
	if result.Status != "incomplete" || result.RunStatus != "not_opened" || generationCalls != 0 || verificationCalls != 0 {
		t.Fatalf("packed root without --object-store = status %s run %s calls %d/%d", result.Status, result.RunStatus, generationCalls, verificationCalls)
	}
	if !slices.Contains(result.Limitations, "loose_git_objects_only") || slices.Contains(result.Limitations, "loose_and_pack_index_v1_subset") {
		t.Fatalf("default limitations changed for omitted opt-in: %v", result.Limitations)
	}
}

func TestRunLocalGitPackedModelReviewRetainedInputStillWorks(t *testing.T) {
	f := packedCLINewModelFixture(t, localModelFixtureOptions{})
	retained, _ := rmCLIInput(t, f)
	f.args = rmCLIArgs(f, retained)
	result, _ := localModelExecute(t, f, f.args, 4)
	if !slices.Contains(result.Limitations, "loose_and_pack_index_v1_subset") || !slices.Contains(result.Limitations, "retained_input_read_only") || slices.Contains(result.Limitations, "empty_memory_index") {
		t.Fatalf("packed retained-input limitations = %v", result.Limitations)
	}
	calls, captures := f.generation.snapshot()
	if calls != 1 || len(captures) != 1 || captures[0].Packet.MemoryAuthority != "advisory_only" || captures[0].Packet.Memory.RetrievalIdentity == "" {
		t.Fatal("packed retained-input mode did not reach the actual model packet")
	}
}

func TestRunLocalGitPackedModelReviewRejectsStaticCommandWidening(t *testing.T) {
	f := packedCLINewModelFixture(t, localModelFixtureOptions{})
	args := append([]string{"local-git", "change"}, f.args[2:]...)
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	if code == 0 {
		t.Fatal("--object-store widened local-git change instead of remaining model-review-only")
	}
	generationCalls, _ := f.generation.snapshot()
	verificationCalls, _ := f.verification.snapshot()
	if generationCalls != 0 || verificationCalls != 0 {
		t.Fatal("rejected widened command dispatched a model")
	}
}
