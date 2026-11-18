package repoindex

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuilderLoadRebuildsMissingRecords(t *testing.T) {
	store := newTestStore(t, DefaultStoreLimits())
	analyzer := &fakeAnalyzer{}
	tree := newMemoryTree(1, map[string]string{"a.go": "package a\n", "b.go": "package b\n"}, nil)
	build(t, store, analyzer, tree, DefaultBuildLimits(), nil)
	segments, _ := filepath.Glob(filepath.Join(store.Directory(), "seg-*"))
	for _, segment := range segments {
		if err := os.Remove(segment); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.Load(context.Background(), "sha1", tree.commit); !errors.Is(err, ErrDamaged) {
		t.Fatalf("a snapshot without its records loaded: %v", err)
	}
	calls := analyzer.calls.Load()
	g, built, err := Builder{Store: store, Analyzer: analyzer}.Load(context.Background(), tree)
	if err != nil || !built || len(g.Files()) != 2 || analyzer.calls.Load()-calls != 2 {
		t.Fatalf("load = built %v, %v", built, err)
	}
	if _, built, err := (Builder{Store: store, Analyzer: analyzer}).Load(context.Background(), tree); err != nil || built {
		t.Fatalf("a healthy snapshot was rebuilt: %v", err)
	}
}

func TestCompactionRemovesADamagedSegmentAndCompletes(t *testing.T) {
	store := newTestStore(t, DefaultStoreLimits())
	analyzer := &fakeAnalyzer{}
	old := newMemoryTree(1, map[string]string{"old.go": "package old\n"}, nil)
	build(t, store, analyzer, old, DefaultBuildLimits(), nil)
	segments, _ := filepath.Glob(filepath.Join(store.Directory(), "seg-*"))
	data, _ := os.ReadFile(segments[0])
	data[segmentHeader+2] ^= 0xff
	if err := os.WriteFile(segments[0], data, 0o600); err != nil {
		t.Fatal(err)
	}
	current := newMemoryTree(2, map[string]string{"new.go": "package current\n"}, nil)
	build(t, store, analyzer, current, DefaultBuildLimits(), nil)
	sess, err := store.open(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	snapshots, _ := sess.allSnapshots()
	live, _ := sess.liveRecords(snapshots)
	err = sess.compact(live)
	sess.close()
	if err != nil {
		t.Fatalf("compaction failed on a damaged record: %v", err)
	}
	if _, err := store.Load(context.Background(), "sha1", current.commit); err != nil {
		t.Fatalf("the current commit lost its records: %v", err)
	}
	if _, err := store.Load(context.Background(), "sha1", old.commit); !errors.Is(err, ErrDamaged) {
		t.Fatalf("the damaged commit loaded: %v", err)
	}
}

func TestSegmentLengthsAreBoundedBeforeAllocation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "seg")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	size := int64(maxDirectoryBytes + 1<<20)
	header := append([]byte(segmentMagic), testIdentity[:]...)
	trailer := binary.LittleEndian.AppendUint64(nil, uint64(segmentHeader))
	trailer = binary.LittleEndian.AppendUint64(trailer, uint64(size-int64(segmentHeader)-int64(segmentTrailer)))
	trailer = binary.LittleEndian.AppendUint32(trailer, 0)
	trailer = append(trailer, segmentEnd...)
	if _, err := file.WriteAt(header, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt(trailer, size-int64(len(trailer))); err != nil {
		t.Fatal(err)
	}
	if _, err := readSegmentDirectory(file, size, testIdentity, 0); !errors.Is(err, errCorrupt) {
		t.Fatalf("a directory past its bound was read: %v", err)
	}
}

func TestOversizedFileGapsReachCoverage(t *testing.T) {
	analyzer := realAnalyzer(t)
	store := newTestStore(t, DefaultStoreLimits())
	tree := newMemoryTree(1, map[string]string{"big.py": "x = 1\n" + strings.Repeat("#", 3<<20), "ok.py": "x = 1\n"}, nil)
	g := loadGraph(t, store, build(t, store, analyzer, tree, DefaultBuildLimits(), nil))
	if c := g.Coverage(); c.Complete || c.AnalysisGaps["limit_exceeded:file_size"] != 1 {
		t.Fatalf("coverage = %+v", c)
	}
}
