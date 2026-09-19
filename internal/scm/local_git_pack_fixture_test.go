package scm

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

const packedTestProfileIdentity = "de5515d7a1782495bbb622dc483331d6382fc1502fe498cf989e298296eb1697"

const (
	packedTypeCommit   = 1
	packedTypeTree     = 2
	packedTypeBlob     = 3
	packedTypeTag      = 4
	packedTypeOFSDelta = 6
	packedTypeREFDelta = 7
)

type packedTestEntry struct {
	objectType string
	packType   int
	payload    []byte
	delta      []byte
	digest     string
	oid        []byte
	baseIndex  int
	baseOID    []byte
	offset     uint64
	crc        uint32
	entry      []byte
}

type packedTestBuilder struct {
	algorithm evidence.RevisionAlgorithm
	entries   []*packedTestEntry
}

type packedTestFiles struct {
	objectRoot string
	packPath   string
	idxPath    string
	pack       []byte
	idx        []byte
	entries    []*packedTestEntry
}

func newPackedTestBuilder(t *testing.T, algorithm evidence.RevisionAlgorithm) *packedTestBuilder {
	t.Helper()
	if algorithm != evidence.RevisionAlgorithmSHA1 && algorithm != evidence.RevisionAlgorithmSHA256 {
		t.Fatalf("unsupported test object algorithm %q", algorithm)
	}
	return &packedTestBuilder{algorithm: algorithm}
}

func (b *packedTestBuilder) addWhole(t *testing.T, objectType string, payload []byte) int {
	t.Helper()
	entry := &packedTestEntry{objectType: objectType, packType: packedPackType(t, objectType), payload: append([]byte(nil), payload...), baseIndex: -1}
	entry.digest = packedObjectDigest(t, b.algorithm, objectType, payload)
	entry.oid = packedOIDBytes(t, entry.digest)
	b.entries = append(b.entries, entry)
	return len(b.entries) - 1
}

func (b *packedTestBuilder) addOFSDelta(t *testing.T, baseIndex int, objectType string, target []byte) int {
	t.Helper()
	if baseIndex < 0 || baseIndex >= len(b.entries) {
		t.Fatalf("base index %d is out of range", baseIndex)
	}
	base := b.entries[baseIndex]
	delta := packedDeltaReplace(base.payload, target)
	if bytes.HasPrefix(target, base.payload) {
		delta = packedDeltaCopyAndInsert(base.payload, target[len(base.payload):])
	}
	entry := &packedTestEntry{objectType: objectType, packType: packedTypeOFSDelta, payload: append([]byte(nil), target...), delta: delta, baseIndex: baseIndex}
	entry.digest = packedObjectDigest(t, b.algorithm, objectType, target)
	entry.oid = packedOIDBytes(t, entry.digest)
	b.entries = append(b.entries, entry)
	return len(b.entries) - 1
}

func (b *packedTestBuilder) addREFDelta(t *testing.T, baseIndex int, objectType string, target []byte) int {
	t.Helper()
	if baseIndex < 0 || baseIndex >= len(b.entries) {
		t.Fatalf("base index %d is out of range", baseIndex)
	}
	base := b.entries[baseIndex]
	entry := &packedTestEntry{objectType: objectType, packType: packedTypeREFDelta, payload: append([]byte(nil), target...), delta: packedDeltaReplace(base.payload, target), baseIndex: baseIndex, baseOID: append([]byte(nil), base.oid...)}
	entry.digest = packedObjectDigest(t, b.algorithm, objectType, target)
	entry.oid = packedOIDBytes(t, entry.digest)
	b.entries = append(b.entries, entry)
	return len(b.entries) - 1
}

func (b *packedTestBuilder) addInvalidREFDelta(t *testing.T, baseIndex int, objectType string, declaredTarget []byte, invalidDelta []byte) int {
	t.Helper()
	if baseIndex < 0 || baseIndex >= len(b.entries) {
		t.Fatalf("base index %d is out of range", baseIndex)
	}
	base := b.entries[baseIndex]
	entry := &packedTestEntry{objectType: objectType, packType: packedTypeREFDelta, payload: append([]byte(nil), declaredTarget...), delta: append([]byte(nil), invalidDelta...), baseIndex: baseIndex, baseOID: append([]byte(nil), base.oid...)}
	entry.digest = packedObjectDigest(t, b.algorithm, objectType, declaredTarget)
	entry.oid = packedOIDBytes(t, entry.digest)
	b.entries = append(b.entries, entry)
	return len(b.entries) - 1
}

func (b *packedTestBuilder) addDeclaredREFDelta(t *testing.T, baseDigest string, objectType string, declaredTarget []byte, delta []byte) int {
	t.Helper()
	entry := &packedTestEntry{objectType: objectType, packType: packedTypeREFDelta, payload: append([]byte(nil), declaredTarget...), delta: append([]byte(nil), delta...), baseIndex: -1, baseOID: packedOIDBytes(t, baseDigest)}
	entry.digest = packedObjectDigest(t, b.algorithm, objectType, declaredTarget)
	entry.oid = packedOIDBytes(t, entry.digest)
	b.entries = append(b.entries, entry)
	return len(b.entries) - 1
}

func packedPackType(t *testing.T, objectType string) int {
	t.Helper()
	switch objectType {
	case "commit":
		return packedTypeCommit
	case "tree":
		return packedTypeTree
	case "blob":
		return packedTypeBlob
	case "tag":
		return packedTypeTag
	default:
		t.Fatalf("unsupported packed object type %q", objectType)
		return 0
	}
}

func packedObjectDigest(t *testing.T, algorithm evidence.RevisionAlgorithm, objectType string, payload []byte) string {
	t.Helper()
	framed := append([]byte(fmt.Sprintf("%s %d\x00", objectType, len(payload))), payload...)
	switch algorithm {
	case evidence.RevisionAlgorithmSHA1:
		sum := sha1.Sum(framed)
		return hex.EncodeToString(sum[:])
	case evidence.RevisionAlgorithmSHA256:
		sum := sha256.Sum256(framed)
		return hex.EncodeToString(sum[:])
	default:
		t.Fatalf("unsupported object algorithm %q", algorithm)
		return ""
	}
}

func packedHash(t *testing.T, algorithm evidence.RevisionAlgorithm) hash.Hash {
	t.Helper()
	switch algorithm {
	case evidence.RevisionAlgorithmSHA1:
		return sha1.New()
	case evidence.RevisionAlgorithmSHA256:
		return sha256.New()
	default:
		t.Fatalf("unsupported object algorithm %q", algorithm)
		return nil
	}
}

func packedHashSize(t *testing.T, algorithm evidence.RevisionAlgorithm) int {
	t.Helper()
	return packedHash(t, algorithm).Size()
}

func packedOIDBytes(t *testing.T, digest string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(digest)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func packedWriteAll(t *testing.T, h hash.Hash, parts ...[]byte) []byte {
	t.Helper()
	for _, part := range parts {
		if n, err := h.Write(part); err != nil || n != len(part) {
			t.Fatalf("hash write = (%d, %v), want %d", n, err, len(part))
		}
	}
	return h.Sum(nil)
}

func packedEncodeObjectHeader(objectType int, size int) []byte {
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

func packedEncodeOFSDeltaOffset(current, base uint64) []byte {
	diff := current - base
	buf := []byte{byte(diff & 0x7f)}
	for diff >>= 7; diff > 0; diff >>= 7 {
		diff--
		buf = append(buf, byte(0x80|(diff&0x7f)))
	}
	for i, j := 0, len(buf)-1; i < j; i, j = i+1, j-1 {
		buf[i], buf[j] = buf[j], buf[i]
	}
	return buf
}

func packedDeltaSize(out []byte, size int) []byte {
	for {
		b := byte(size & 0x7f)
		size >>= 7
		if size > 0 {
			b |= 0x80
		}
		out = append(out, b)
		if size == 0 {
			return out
		}
	}
}

func packedDeltaReplace(base, target []byte) []byte {
	out := packedDeltaSize(nil, len(base))
	out = packedDeltaSize(out, len(target))
	for len(target) > 0 {
		n := len(target)
		if n > 127 {
			n = 127
		}
		out = append(out, byte(n))
		out = append(out, target[:n]...)
		target = target[n:]
	}
	return out
}

func packedDeltaCopyAndInsert(base, insert []byte) []byte {
	out := packedDeltaSize(nil, len(base))
	out = packedDeltaSize(out, len(base)+len(insert))
	copyOpcode := byte(0x80)
	size := len(base)
	if size&0xff != 0 {
		copyOpcode |= 0x10
	}
	if size&0xff00 != 0 {
		copyOpcode |= 0x20
	}
	if size&0xff0000 != 0 {
		copyOpcode |= 0x40
	}
	out = append(out, copyOpcode)
	if size&0xff != 0 {
		out = append(out, byte(size))
	}
	if size&0xff00 != 0 {
		out = append(out, byte(size>>8))
	}
	if size&0xff0000 != 0 {
		out = append(out, byte(size>>16))
	}
	for len(insert) > 0 {
		n := len(insert)
		if n > 127 {
			n = 127
		}
		out = append(out, byte(n))
		out = append(out, insert[:n]...)
		insert = insert[n:]
	}
	return out
}

func packedDeltaBadCopy(baseSize, resultSize int) []byte {
	out := packedDeltaSize(nil, baseSize)
	out = packedDeltaSize(out, resultSize)
	return append(out, 0x91, byte(baseSize+1), 0x01)
}

func packedDeltaTruncatedInsert(baseSize, resultSize int) []byte {
	out := packedDeltaSize(nil, baseSize)
	out = packedDeltaSize(out, resultSize)
	return append(out, 0x05, 'x')
}

func packedCompress(t *testing.T, payload []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	zw := zlib.NewWriter(&out)
	if _, err := zw.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func packedTreeEntry(t *testing.T, algorithm evidence.RevisionAlgorithm, mode, name, digest string) []byte {
	t.Helper()
	object := packedOIDBytes(t, digest)
	if len(object) != packedHashSize(t, algorithm) {
		t.Fatalf("tree object id has %d bytes", len(object))
	}
	return append(append([]byte(mode+" "+name), 0), object...)
}

func packedWritePackAndIndex(t *testing.T, objectRoot string, builder *packedTestBuilder, mutate func(*packedTestFiles)) packedTestFiles {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(objectRoot, "pack"), 0o700); err != nil {
		t.Fatal(err)
	}
	pack := []byte("PACK")
	pack = binary.BigEndian.AppendUint32(pack, 2)
	pack = binary.BigEndian.AppendUint32(pack, uint32(len(builder.entries)))
	for _, entry := range builder.entries {
		entry.offset = uint64(len(pack))
		var body []byte
		switch entry.packType {
		case packedTypeOFSDelta:
			body = append(body, packedEncodeOFSDeltaOffset(entry.offset, builder.entries[entry.baseIndex].offset)...)
			body = append(body, packedCompress(t, entry.delta)...)
		case packedTypeREFDelta:
			body = append(body, entry.baseOID...)
			body = append(body, packedCompress(t, entry.delta)...)
		default:
			body = packedCompress(t, entry.payload)
		}
		size := len(entry.payload)
		if entry.packType == packedTypeOFSDelta || entry.packType == packedTypeREFDelta {
			size = len(entry.delta)
		}
		entry.entry = append(packedEncodeObjectHeader(entry.packType, size), body...)
		entry.crc = crc32.ChecksumIEEE(entry.entry)
		pack = append(pack, entry.entry...)
	}
	trailer := packedWriteAll(t, packedHash(t, builder.algorithm), pack)
	pack = append(pack, trailer...)
	idx := packedBuildIndex(t, builder.algorithm, builder.entries, trailer)
	stem := "pack-" + hex.EncodeToString(trailer)
	files := packedTestFiles{objectRoot: objectRoot, packPath: filepath.Join(objectRoot, "pack", stem+".pack"), idxPath: filepath.Join(objectRoot, "pack", stem+".idx"), pack: pack, idx: idx, entries: builder.entries}
	if mutate != nil {
		mutate(&files)
	}
	if err := os.WriteFile(files.packPath, files.pack, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(files.idxPath, files.idx, 0o600); err != nil {
		t.Fatal(err)
	}
	return files
}

func packedBuildIndex(t *testing.T, algorithm evidence.RevisionAlgorithm, entries []*packedTestEntry, packTrailer []byte) []byte {
	t.Helper()
	sorted := append([]*packedTestEntry(nil), entries...)
	sort.Slice(sorted, func(i, j int) bool { return bytes.Compare(sorted[i].oid, sorted[j].oid) < 0 })
	fanout := make([]uint32, 256)
	for _, entry := range sorted {
		fanout[int(entry.oid[0])]++
	}
	var cumulative uint32
	idx := []byte{0xff, 't', 'O', 'c'}
	idx = binary.BigEndian.AppendUint32(idx, 2)
	for i := range fanout {
		cumulative += fanout[i]
		idx = binary.BigEndian.AppendUint32(idx, cumulative)
	}
	for _, entry := range sorted {
		idx = append(idx, entry.oid...)
	}
	for _, entry := range sorted {
		idx = binary.BigEndian.AppendUint32(idx, entry.crc)
	}
	largeOffsets := []uint64{}
	for _, entry := range sorted {
		if entry.offset > 0x7fffffff {
			idx = binary.BigEndian.AppendUint32(idx, 0x80000000|uint32(len(largeOffsets)))
			largeOffsets = append(largeOffsets, entry.offset)
		} else {
			idx = binary.BigEndian.AppendUint32(idx, uint32(entry.offset))
		}
	}
	for _, offset := range largeOffsets {
		idx = binary.BigEndian.AppendUint64(idx, offset)
	}
	idx = append(idx, packTrailer...)
	idxChecksum := packedWriteAll(t, packedHash(t, algorithm), idx)
	idx = append(idx, idxChecksum...)
	return idx
}

func packedIdxLayout(t *testing.T, algorithm evidence.RevisionAlgorithm, objectCount int) (fanout, oids, crcs, offsets, trailer int) {
	t.Helper()
	h := packedHashSize(t, algorithm)
	fanout = 8
	oids = fanout + 256*4
	crcs = oids + objectCount*h
	offsets = crcs + objectCount*4
	trailer = offsets + objectCount*4
	return fanout, oids, crcs, offsets, trailer
}

func packedFinalizeIndexChecksum(t *testing.T, algorithm evidence.RevisionAlgorithm, idx []byte) {
	t.Helper()
	h := packedHashSize(t, algorithm)
	if len(idx) < h {
		t.Fatal("idx too short")
	}
	sum := packedWriteAll(t, packedHash(t, algorithm), idx[:len(idx)-h])
	copy(idx[len(idx)-h:], sum)
}

func packedSimpleRevisionFixture(t *testing.T, algorithm evidence.RevisionAlgorithm, mutate func(*packedTestFiles)) (string, evidence.RevisionIdentity, map[string][]byte, packedTestFiles) {
	t.Helper()
	builder := newPackedTestBuilder(t, algorithm)
	content := []byte("packed file content\n")
	blob := builder.addWhole(t, "blob", content)
	treePayload := packedTreeEntry(t, algorithm, "100644", "file.txt", builder.entries[blob].digest)
	tree := builder.addWhole(t, "tree", treePayload)
	commitPayload := []byte("tree " + builder.entries[tree].digest + "\nauthor A <a@example.com> 0 +0000\ncommitter A <a@example.com> 0 +0000\n\npacked fixture\n")
	commit := builder.addWhole(t, "commit", commitPayload)
	objectRoot := t.TempDir()
	files := packedWritePackAndIndex(t, objectRoot, builder, mutate)
	revision := packedRevision(t, algorithm, builder.entries[commit].digest)
	return objectRoot, revision, map[string][]byte{"file.txt": content}, files
}

func packedDeltaRevisionFixture(t *testing.T, algorithm evidence.RevisionAlgorithm, mutate func(*packedTestFiles)) (string, evidence.RevisionIdentity, []byte, packedTestFiles) {
	t.Helper()
	builder := newPackedTestBuilder(t, algorithm)
	baseContent := []byte("alpha\n")
	base := builder.addWhole(t, "blob", baseContent)
	middleContent := []byte("alpha\nbeta\n")
	middle := builder.addOFSDelta(t, base, "blob", middleContent)
	finalContent := []byte("omega\nselected\n")
	final := builder.addREFDelta(t, middle, "blob", finalContent)
	treePayload := packedTreeEntry(t, algorithm, "100644", "delta.txt", builder.entries[final].digest)
	tree := builder.addWhole(t, "tree", treePayload)
	commitPayload := []byte("tree " + builder.entries[tree].digest + "\nauthor A <a@example.com> 0 +0000\ncommitter A <a@example.com> 0 +0000\n\ndelta fixture\n")
	commit := builder.addWhole(t, "commit", commitPayload)
	objectRoot := t.TempDir()
	files := packedWritePackAndIndex(t, objectRoot, builder, mutate)
	return objectRoot, packedRevision(t, algorithm, builder.entries[commit].digest), finalContent, files
}

func packedRevision(t *testing.T, algorithm evidence.RevisionAlgorithm, digest string) evidence.RevisionIdentity {
	t.Helper()
	revision, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, algorithm, digest)
	if err != nil {
		t.Fatal(err)
	}
	return revision
}

func packedRepository(t *testing.T) evidence.RepositoryIdentity {
	t.Helper()
	repository, err := evidence.NewRepositoryIdentity("example.test", []string{"private", "packed"}, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	return repository
}

func packedOpenStore(t *testing.T, objectRoot string, algorithm evidence.RevisionAlgorithm) (*LocalGitObjectStore, *os.Root) {
	t.Helper()
	root, err := os.OpenRoot(objectRoot)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewLocalGitObjectStoreWithOptions(LocalGitObjectStoreOptions{ObjectsRoot: root, Repository: packedRepository(t), Profile: LocalGitObjectStoreProfileLooseAndPackIndexV1, ObjectAlgorithm: algorithm})
	if err != nil {
		_ = root.Close()
		t.Fatalf("NewLocalGitObjectStoreWithOptions(packed) error = %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close(context.Background())
		_ = root.Close()
	})
	return store, root
}

func packedReadRevision(t *testing.T, objectRoot string, algorithm evidence.RevisionAlgorithm, revision evidence.RevisionIdentity) LocalGitRevisionResult {
	t.Helper()
	store, _ := packedOpenStore(t, objectRoot, algorithm)
	result, err := ReadLocalGitRevision(context.Background(), store, revision)
	if err != nil {
		t.Fatalf("ReadLocalGitRevision(packed) error = %v", err)
	}
	return result
}

func packedExpectRevisionError(t *testing.T, objectRoot string, algorithm evidence.RevisionAlgorithm, revision evidence.RevisionIdentity) error {
	t.Helper()
	root, err := os.OpenRoot(objectRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	store, err := NewLocalGitObjectStoreWithOptions(LocalGitObjectStoreOptions{ObjectsRoot: root, Repository: packedRepository(t), Profile: LocalGitObjectStoreProfileLooseAndPackIndexV1, ObjectAlgorithm: algorithm})
	if err != nil {
		if _, rootErr := root.Stat("."); rootErr != nil {
			t.Fatalf("rejected packed constructor closed caller root: %v", rootErr)
		}
		return err
	}
	defer store.Close(context.Background())
	result, err := ReadLocalGitRevision(context.Background(), store, revision)
	if err == nil || result.RevisionIdentity() != "" {
		t.Fatalf("ReadLocalGitRevision(corrupt packed) = (%#v, %v), want failure", result, err)
	}
	return err
}

func packedReplaceArg(args []string, name, value string) []string {
	result := append([]string(nil), args...)
	for i := range result {
		if result[i] == name && i+1 < len(result) {
			result[i+1] = value
			return result
		}
	}
	panic(name)
}

func packedAppendObjectStore(args []string) []string {
	for _, value := range args {
		if value == "--object-store" {
			return args
		}
	}
	return append(append([]string(nil), args...), "--object-store", string(LocalGitObjectStoreProfileLooseAndPackIndexV1))
}

func packedLooseObjectPayload(t *testing.T, path string) (string, []byte) {
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
		t.Fatal("loose object lacks canonical header")
	}
	parts := strings.SplitN(string(framed[:sep]), " ", 2)
	if len(parts) != 2 {
		t.Fatal("loose object header lacks type and size")
	}
	return parts[0], append([]byte(nil), framed[sep+1:]...)
}
