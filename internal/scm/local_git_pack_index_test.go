package scm

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

func TestLocalGitPackedRevisionReadsSHA1AndSHA256CommitTreeBlob(t *testing.T) {
	for _, algorithm := range []evidence.RevisionAlgorithm{evidence.RevisionAlgorithmSHA1, evidence.RevisionAlgorithmSHA256} {
		t.Run(string(algorithm), func(t *testing.T) {
			objectRoot, revision, wantContents, _ := packedSimpleRevisionFixture(t, algorithm, nil)
			store, _ := packedOpenStore(t, objectRoot, algorithm)
			if store.Profile() != LocalGitObjectStoreProfileLooseAndPackIndexV1 || store.ProfileIdentity() != packedTestProfileIdentity {
				t.Fatalf("packed profile = (%q, %q)", store.Profile(), store.ProfileIdentity())
			}
			if identity, err := LocalGitObjectStoreProfileIdentity(LocalGitObjectStoreProfileLooseAndPackIndexV1); err != nil || identity != packedTestProfileIdentity {
				t.Fatalf("LocalGitObjectStoreProfileIdentity(packed) = (%q, %v)", identity, err)
			}
			result, err := ReadLocalGitRevision(context.Background(), store, revision)
			if err != nil {
				t.Fatalf("ReadLocalGitRevision(%s packed) error = %v", algorithm, err)
			}
			contents := result.Contents()
			if result.RevisionIdentity() != revision.Identity() || result.RepositoryIdentity() != store.RepositoryIdentity() || result.FileCount() != 1 || result.TotalContentBytes() != int64(len(wantContents["file.txt"])) || !bytes.Equal(contents["file.txt"], wantContents["file.txt"]) {
				t.Fatalf("packed result = %#v contents %#v", result, contents)
			}
			contents["file.txt"][0] ^= 0xff
			if bytes.Equal(contents["file.txt"], result.Contents()["file.txt"]) {
				t.Fatal("packed revision result returned mutable internal content")
			}
		})
	}
}

func TestLocalGitPackedRevisionResolvesBaseFirstOFSAndREFDeltas(t *testing.T) {
	objectRoot, revision, wantContent, _ := packedDeltaRevisionFixture(t, evidence.RevisionAlgorithmSHA1, nil)
	result := packedReadRevision(t, objectRoot, evidence.RevisionAlgorithmSHA1, revision)
	if got := result.Contents()["delta.txt"]; !bytes.Equal(got, wantContent) {
		t.Fatalf("delta content = %q, want %q", got, wantContent)
	}
}

func TestLocalGitPackedReaderAcceptsUnusedTagsAndRejectsSelectedTags(t *testing.T) {
	builder := newPackedTestBuilder(t, evidence.RevisionAlgorithmSHA1)
	builder.addWhole(t, "tag", []byte("object "+strings.Repeat("1", 40)+"\ntype blob\ntag unused\ntagger A <a@example.com> 0 +0000\n\nunused\n"))
	content := []byte("tag should not be opened\n")
	blob := builder.addWhole(t, "blob", content)
	treePayload := packedTreeEntry(t, evidence.RevisionAlgorithmSHA1, "100644", "file.txt", builder.entries[blob].digest)
	tree := builder.addWhole(t, "tree", treePayload)
	commitPayload := []byte("tree " + builder.entries[tree].digest + "\nauthor A <a@example.com> 0 +0000\ncommitter A <a@example.com> 0 +0000\n\nunused tag accepted\n")
	commit := builder.addWhole(t, "commit", commitPayload)
	objectRoot := t.TempDir()
	packedWritePackAndIndex(t, objectRoot, builder, nil)
	result := packedReadRevision(t, objectRoot, evidence.RevisionAlgorithmSHA1, packedRevision(t, evidence.RevisionAlgorithmSHA1, builder.entries[commit].digest))
	if got := result.Contents()["file.txt"]; !bytes.Equal(got, content) {
		t.Fatalf("content = %q", got)
	}
	store, _ := packedOpenStore(t, objectRoot, evidence.RevisionAlgorithmSHA1)
	if payload, err := store.ReadBlob(context.Background(), evidence.RevisionAlgorithmSHA1, builder.entries[0].digest); err == nil || payload != nil {
		t.Fatalf("ReadBlob(selected tag) = (%q, %v), want rejection", payload, err)
	}
}

func TestLocalGitPackedIndexAndPackCorruptionSelectedScope(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*packedTestFiles)
	}{
		{name: "bad idx checksum", mutate: func(f *packedTestFiles) { f.idx[len(f.idx)-1] ^= 0x55 }},
		{name: "bad pack checksum", mutate: func(f *packedTestFiles) { f.pack[len(f.pack)-1] ^= 0x55 }},
		{name: "bad selected crc", mutate: func(f *packedTestFiles) {
			_, _, crcs, _, _ := packedIdxLayout(t, evidence.RevisionAlgorithmSHA1, len(f.entries))
			f.idx[crcs+3] ^= 0x7f
			packedFinalizeIndexChecksum(t, evidence.RevisionAlgorithmSHA1, f.idx)
		}},
		{name: "bad selected digest", mutate: func(f *packedTestFiles) {
			_, oids, _, _, _ := packedIdxLayout(t, evidence.RevisionAlgorithmSHA1, len(f.entries))
			f.idx[oids] ^= 0x01
			packedFinalizeIndexChecksum(t, evidence.RevisionAlgorithmSHA1, f.idx)
		}},
		{name: "fanout count mismatch", mutate: func(f *packedTestFiles) {
			fanout, _, _, _, _ := packedIdxLayout(t, evidence.RevisionAlgorithmSHA1, len(f.entries))
			binary.BigEndian.PutUint32(f.idx[fanout+255*4:fanout+256*4], uint32(len(f.entries)+1))
			packedFinalizeIndexChecksum(t, evidence.RevisionAlgorithmSHA1, f.idx)
		}},
		{name: "oid order mismatch", mutate: func(f *packedTestFiles) {
			_, oids, _, _, _ := packedIdxLayout(t, evidence.RevisionAlgorithmSHA1, len(f.entries))
			if len(f.entries) < 2 {
				t.Fatal("fixture needs at least two objects")
			}
			a := append([]byte(nil), f.idx[oids:oids+20]...)
			copy(f.idx[oids:oids+20], f.idx[oids+20:oids+40])
			copy(f.idx[oids+20:oids+40], a)
			packedFinalizeIndexChecksum(t, evidence.RevisionAlgorithmSHA1, f.idx)
		}},
		{name: "first object offset below pack header", mutate: func(f *packedTestFiles) {
			_, _, _, offsets, _ := packedIdxLayout(t, evidence.RevisionAlgorithmSHA1, len(f.entries))
			binary.BigEndian.PutUint32(f.idx[offsets:offsets+4], 11)
			packedFinalizeIndexChecksum(t, evidence.RevisionAlgorithmSHA1, f.idx)
		}},
		{name: "large offset out of bounds", mutate: func(f *packedTestFiles) {
			_, _, _, offsets, trailer := packedIdxLayout(t, evidence.RevisionAlgorithmSHA1, len(f.entries))
			binary.BigEndian.PutUint32(f.idx[offsets:offsets+4], 0x80000000)
			large := make([]byte, 8)
			binary.BigEndian.PutUint64(large, uint64(len(f.pack)+4096))
			f.idx = append(append(append([]byte(nil), f.idx[:trailer]...), large...), f.idx[trailer:]...)
			packedFinalizeIndexChecksum(t, evidence.RevisionAlgorithmSHA1, f.idx)
		}},
		{name: "pack trailing byte after checksum", mutate: func(f *packedTestFiles) { f.pack = append(f.pack, 0) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			objectRoot, revision, _, _ := packedSimpleRevisionFixture(t, evidence.RevisionAlgorithmSHA1, tc.mutate)
			packedExpectRevisionError(t, objectRoot, evidence.RevisionAlgorithmSHA1, revision)
		})
	}
}

func TestLocalGitPackedLayoutRejectsUnsupportedFormatsAndMissingPairs(t *testing.T) {
	cases := []struct {
		name  string
		alter func(string, packedTestFiles)
	}{
		{name: "missing idx pair", alter: func(_ string, f packedTestFiles) {
			if err := os.Remove(f.idxPath); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "missing pack pair", alter: func(_ string, f packedTestFiles) {
			if err := os.Remove(f.packPath); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "promisor sidecar", alter: func(_ string, f packedTestFiles) {
			if err := os.WriteFile(strings.TrimSuffix(f.packPath, ".pack")+".promisor", []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "multi-pack-index", alter: func(root string, _ packedTestFiles) {
			if err := os.WriteFile(filepath.Join(root, "pack", "multi-pack-index"), []byte("MIDX"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "alternates", alter: func(root string, _ packedTestFiles) {
			if err := os.MkdirAll(filepath.Join(root, "info"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "info", "alternates"), []byte("../other\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "http alternates", alter: func(root string, _ packedTestFiles) {
			if err := os.MkdirAll(filepath.Join(root, "info"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "info", "http-alternates"), []byte("https://example.invalid\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			objectRoot, revision, _, files := packedSimpleRevisionFixture(t, evidence.RevisionAlgorithmSHA1, nil)
			tc.alter(objectRoot, files)
			packedExpectRevisionError(t, objectRoot, evidence.RevisionAlgorithmSHA1, revision)
		})
	}
}

func TestLocalGitPackedDuplicateOIDRejectedWithinAndAcrossPacks(t *testing.T) {
	objectRoot, revision, _, files := packedSimpleRevisionFixture(t, evidence.RevisionAlgorithmSHA1, nil)
	duplicateBuilder := newPackedTestBuilder(t, evidence.RevisionAlgorithmSHA1)
	for _, entry := range files.entries {
		duplicateBuilder.addWhole(t, entry.objectType, entry.payload)
	}
	duplicateBuilder.addWhole(t, "blob", []byte("extra object for distinct overlapping pack"))
	other := packedWritePackAndIndex(t, objectRoot, duplicateBuilder, nil)
	if other.packPath == files.packPath {
		t.Fatal("overlapping pack fixture unexpectedly reused the original pack")
	}
	packedExpectRevisionError(t, objectRoot, evidence.RevisionAlgorithmSHA1, revision)

	builder := newPackedTestBuilder(t, evidence.RevisionAlgorithmSHA1)
	blob := builder.addWhole(t, "blob", []byte("same"))
	builder.entries = append(builder.entries, builder.entries[blob])
	objectRoot = t.TempDir()
	packedWritePackAndIndex(t, objectRoot, builder, nil)
	store, _ := packedOpenStore(t, objectRoot, evidence.RevisionAlgorithmSHA1)
	if payload, err := store.ReadBlob(context.Background(), evidence.RevisionAlgorithmSHA1, builder.entries[blob].digest); err == nil || payload != nil {
		t.Fatalf("ReadBlob(duplicate same-pack oid) = (%q, %v), want rejection", payload, err)
	}
}

func TestLocalGitPackedDeltaCorruptionDepthCyclesAndDigestBudget(t *testing.T) {
	cases := []struct {
		name  string
		build func(t *testing.T) (string, evidence.RevisionIdentity)
	}{
		{name: "out of bounds copy", build: func(t *testing.T) (string, evidence.RevisionIdentity) {
			builder := newPackedTestBuilder(t, evidence.RevisionAlgorithmSHA1)
			base := builder.addWhole(t, "blob", []byte("base"))
			selected := builder.addInvalidREFDelta(t, base, "blob", []byte("declared"), packedDeltaBadCopy(4, 1))
			return packedCommitSelectingBlob(t, builder, selected, "bad-copy.txt")
		}},
		{name: "truncated insert", build: func(t *testing.T) (string, evidence.RevisionIdentity) {
			builder := newPackedTestBuilder(t, evidence.RevisionAlgorithmSHA1)
			base := builder.addWhole(t, "blob", []byte("base"))
			selected := builder.addInvalidREFDelta(t, base, "blob", []byte("declared"), packedDeltaTruncatedInsert(4, 5))
			return packedCommitSelectingBlob(t, builder, selected, "truncated-insert.txt")
		}},
		{name: "selected digest mismatch", build: func(t *testing.T) (string, evidence.RevisionIdentity) {
			builder := newPackedTestBuilder(t, evidence.RevisionAlgorithmSHA1)
			base := builder.addWhole(t, "blob", []byte("base"))
			selected := builder.addInvalidREFDelta(t, base, "blob", []byte("declared"), packedDeltaReplace([]byte("base"), []byte("different")))
			return packedCommitSelectingBlob(t, builder, selected, "digest.txt")
		}},
		{name: "delta depth", build: func(t *testing.T) (string, evidence.RevisionIdentity) {
			builder := newPackedTestBuilder(t, evidence.RevisionAlgorithmSHA1)
			last := builder.addWhole(t, "blob", []byte("0"))
			for i := 1; i <= 33; i++ {
				last = builder.addREFDelta(t, last, "blob", []byte(strings.Repeat("x", i)))
			}
			return packedCommitSelectingBlob(t, builder, last, "deep.txt")
		}},
		{name: "delta cycle", build: func(t *testing.T) (string, evidence.RevisionIdentity) {
			builder := newPackedTestBuilder(t, evidence.RevisionAlgorithmSHA1)
			targetA := []byte("cycle-a")
			targetB := []byte("cycle-b")
			digestA := packedObjectDigest(t, evidence.RevisionAlgorithmSHA1, "blob", targetA)
			digestB := packedObjectDigest(t, evidence.RevisionAlgorithmSHA1, "blob", targetB)
			builder.addDeclaredREFDelta(t, digestB, "blob", targetA, packedDeltaReplace(targetB, targetA))
			selected := builder.addDeclaredREFDelta(t, digestA, "blob", targetB, packedDeltaReplace(targetA, targetB))
			return packedCommitSelectingBlob(t, builder, selected, "cycle.txt")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			objectRoot, revision := tc.build(t)
			packedExpectRevisionError(t, objectRoot, evidence.RevisionAlgorithmSHA1, revision)
		})
	}
}

func packedCommitSelectingBlob(t *testing.T, builder *packedTestBuilder, blobIndex int, name string) (string, evidence.RevisionIdentity) {
	t.Helper()
	treePayload := packedTreeEntry(t, builder.algorithm, "100644", name, builder.entries[blobIndex].digest)
	tree := builder.addWhole(t, "tree", treePayload)
	commitPayload := []byte("tree " + builder.entries[tree].digest + "\nauthor A <a@example.com> 0 +0000\ncommitter A <a@example.com> 0 +0000\n\nselected delta\n")
	commit := builder.addWhole(t, "commit", commitPayload)
	objectRoot := t.TempDir()
	packedWritePackAndIndex(t, objectRoot, builder, nil)
	return objectRoot, packedRevision(t, builder.algorithm, builder.entries[commit].digest)
}
