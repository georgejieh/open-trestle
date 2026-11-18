package repoindex

import (
	"context"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/internal/varcodec"
	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

// memoryTree is a tree held in memory; an object ID is the SHA-1 of the
// content.
type memoryTree struct {
	commit  string
	paths   []string
	objects map[string][]byte
	ids     map[string]string
	reads   atomic.Int64
}

func newMemoryTree(commit int, files map[string]string, order []string) *memoryTree {
	t := &memoryTree{commit: fmt.Sprintf("%040x", commit), objects: map[string][]byte{}, ids: map[string]string{}}
	if order == nil {
		for p := range files {
			order = append(order, p)
		}
	}
	for _, p := range order {
		sum := sha1.Sum([]byte(files[p]))
		id := hex.EncodeToString(sum[:])
		t.paths = append(t.paths, p)
		t.objects[id] = []byte(files[p])
		t.ids[p] = id
	}
	return t
}

func (t *memoryTree) Algorithm() string { return "sha1" }
func (t *memoryTree) Commit() string    { return t.commit }

func (t *memoryTree) Walk(ctx context.Context, maxEntries int, visit func(TreeEntry) error) (TreeWalk, error) {
	walk := TreeWalk{}
	for _, p := range t.paths {
		if walk.Entries >= maxEntries {
			walk.Truncated = true
			break
		}
		walk.Entries++
		if err := visit(TreeEntry{Path: p, Object: t.ids[p]}); err != nil {
			return walk, err
		}
	}
	return walk, nil
}

func (t *memoryTree) ReadBlobs(_ context.Context, next func() (string, bool), deliver func([]byte, error) error) error {
	for object, ok := next(); ok; object, ok = next() {
		t.reads.Add(1)
		var err error
		content, found := t.objects[object]
		if !found {
			err = errors.New("missing object")
		}
		if err := deliver(content, err); err != nil {
			return err
		}
	}
	return nil
}

// fakeAnalyzer records one definition per file without parsing; a file
// named hang.go fails as a whole by its deadline.
type fakeAnalyzer struct {
	calls  atomic.Int64
	active atomic.Int64
	peak   atomic.Int64
	delay  time.Duration
}

func (f *fakeAnalyzer) Supports(syntaxanalysis.Language) bool { return true }

func (f *fakeAnalyzer) Analyze(ctx context.Context, s syntaxanalysis.Source) (syntaxanalysis.FileAnalysis, error) {
	f.calls.Add(1)
	n := f.active.Add(1)
	defer f.active.Add(-1)
	for {
		peak := f.peak.Load()
		if n <= peak || f.peak.CompareAndSwap(peak, n) {
			break
		}
	}
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	if err := ctx.Err(); err != nil {
		return syntaxanalysis.FileAnalysis{}, err
	}
	if strings.HasSuffix(s.Path(), "hang.go") {
		return syntaxanalysis.WholeFileGap(s, "fake", syntaxanalysis.GapDeadlineExceeded, ""), nil
	}
	return syntaxanalysis.WholeFileGap(s, "fake", syntaxanalysis.GapParseError, ""), nil
}

func build(t *testing.T, store *Store, analyzer syntaxanalysis.Analyzer, tree Tree, limits BuildLimits, now func() time.Time) Snapshot {
	t.Helper()
	s, err := Builder{Store: store, Analyzer: analyzer, Limits: limits, Parallelism: 4, Now: now}.Build(context.Background(), tree)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func statuses(s Snapshot) map[Status]int {
	out := map[Status]int{}
	for _, f := range s.Files {
		out[f.Status]++
	}
	return out
}

func manyFiles(n int, extension string) (map[string]string, []string) {
	files := map[string]string{}
	order := []string{}
	for i := 0; i < n; i++ {
		p := fmt.Sprintf("d%03d/f%05d%s", i/1000, i, extension)
		files[p] = fmt.Sprintf("package d\n// %d\n", i)
		order = append(order, p)
	}
	return files, order
}

func TestBuildBoundsEntriesFilesAndBytes(t *testing.T) {
	files, order := manyFiles(30000, ".go")
	tree := newMemoryTree(1, files, order)
	store := newTestStore(t, DefaultStoreLimits())
	analyzer := &fakeAnalyzer{}
	s := build(t, store, analyzer, tree, BuildLimits{MaxEntries: 20000, MaxFiles: 500, MaxBytes: 1 << 30, MaxDuration: time.Hour}, nil)
	if !s.Coverage.TreeTruncated || s.Coverage.TreeEntries != 20000 || len(s.Files) != 20000 {
		t.Fatalf("entries: %+v", s.Coverage)
	}
	if got := statuses(s); got[StatusIndexed] != 500 || got[StatusFileLimit] != 19500 || analyzer.calls.Load() != 500 {
		t.Fatalf("file limit: %v, %d calls", got, analyzer.calls.Load())
	}
	if c := loadGraph(t, store, s).Coverage(); c.Complete || c.Statuses[StatusFileLimit] != 19500 || !c.Coverage.TreeTruncated {
		t.Fatalf("a limited graph claims coverage: %+v", c)
	}
	// The next build of the same commit continues where the limit stopped.
	s = build(t, store, analyzer, tree, BuildLimits{MaxEntries: 20000, MaxFiles: 500, MaxBytes: 1 << 30, MaxDuration: time.Hour}, nil)
	if got := statuses(s); got[StatusIndexed] != 1000 || s.Coverage.Reused != 500 || s.Coverage.Analysed != 500 {
		t.Fatalf("second build: %v %+v", got, s.Coverage)
	}

	small := newMemoryTree(2, map[string]string{"a.go": strings.Repeat("a", 100), "b.go": strings.Repeat("b", 100), "c.go": "c"}, []string{"a.go", "b.go", "c.go"})
	s = build(t, newTestStore(t, DefaultStoreLimits()), &fakeAnalyzer{}, small, BuildLimits{MaxEntries: 10, MaxFiles: 10, MaxBytes: 150, MaxDuration: time.Hour}, nil)
	if got := statuses(s); got[StatusIndexed] != 1 || got[StatusByteLimit] != 2 {
		t.Fatalf("byte limit: %v", got)
	}
}

func TestBuildAnalysesASharedBlobOnce(t *testing.T) {
	files := map[string]string{"a/x.go": "package x\n", "b/x.go": "package x\n", "c/y.go": "package y\n"}
	analyzer := &fakeAnalyzer{}
	store := newTestStore(t, DefaultStoreLimits())
	s := build(t, store, analyzer, newMemoryTree(1, files, nil), DefaultBuildLimits(), nil)
	if analyzer.calls.Load() != 2 || statuses(s)[StatusIndexed] != 3 || s.Coverage.Analysed != 2 {
		t.Fatalf("calls %d, statuses %v", analyzer.calls.Load(), statuses(s))
	}
	if g := loadGraph(t, store, s); len(g.Files()) != 3 {
		t.Fatal("a file sharing a blob was lost")
	}
}

func TestCompactionKeepsBinaryRecords(t *testing.T) {
	store := newTestStore(t, DefaultStoreLimits())
	tree := newMemoryTree(1, map[string]string{"a.go": "package a\n", "b.js": "x\x00"}, nil)
	build(t, store, &fakeAnalyzer{}, tree, DefaultBuildLimits(), nil)
	sess, err := store.open(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	snapshots, err := sess.allSnapshots()
	if err != nil {
		t.Fatal(err)
	}
	live, _ := sess.liveRecords(snapshots)
	if err := sess.compact(live); err != nil {
		t.Fatal(err)
	}
	sess.close()
	reads := tree.reads.Load()
	if s := build(t, store, &fakeAnalyzer{}, tree, DefaultBuildLimits(), nil); tree.reads.Load() != reads || statuses(s)[StatusBinary] != 1 {
		t.Fatal("a binary record was lost by compaction")
	}
}

func TestSegmentDirectoryRejectsCraftedLocations(t *testing.T) {
	store := newTestStore(t, DefaultStoreLimits())
	build(t, store, &fakeAnalyzer{}, newMemoryTree(1, map[string]string{"a.go": "package a\n"}, nil), DefaultBuildLimits(), nil)
	segments, _ := filepath.Glob(filepath.Join(store.Directory(), "seg-*"))
	data, err := os.ReadFile(segments[0])
	if err != nil {
		t.Fatal(err)
	}
	trailer := data[len(data)-segmentTrailer:]
	at := int(binary.LittleEndian.Uint64(trailer))
	length := int(binary.LittleEndian.Uint64(trailer[8:]))
	directory := varcodec.AppendUvarint(nil, 1)
	directory = append(directory, data[at+1:at+1+32+1]...)
	directory = varcodec.AppendUvarint(directory, uint64(segmentHeader))
	directory = varcodec.AppendUvarint(directory, math.MaxInt64)
	directory = binary.LittleEndian.AppendUint32(directory, 0)
	crafted := append(append([]byte{}, data[:at]...), directory...)
	crafted = binary.LittleEndian.AppendUint64(crafted, uint64(at))
	crafted = binary.LittleEndian.AppendUint64(crafted, uint64(len(directory)))
	crafted = binary.LittleEndian.AppendUint32(crafted, crc32.Checksum(directory, crcTable))
	crafted = append(crafted, segmentEnd...)
	_ = length
	path := filepath.Join(t.TempDir(), "seg")
	if err := os.WriteFile(path, crafted, 0o600); err != nil {
		t.Fatal(err)
	}
	file, _ := os.Open(path)
	defer file.Close()
	if _, err := readSegmentDirectory(file, int64(len(crafted)), testIdentity, 0); !errors.Is(err, errCorrupt) {
		t.Fatalf("a crafted location was accepted: %v", err)
	}
}

func TestBuildStopsAtTheTimeLimit(t *testing.T) {
	files, order := manyFiles(100, ".go")
	var clock atomic.Int64
	now := func() time.Time { return time.Unix(0, clock.Add(int64(time.Second))) }
	s := build(t, newTestStore(t, DefaultStoreLimits()), &fakeAnalyzer{}, newMemoryTree(1, files, order), BuildLimits{MaxEntries: 1000, MaxFiles: 1000, MaxBytes: 1 << 30, MaxDuration: 10 * time.Second}, now)
	got := statuses(s)
	if got[StatusTimeLimit] == 0 || got[StatusIndexed] == 0 || got[StatusTimeLimit]+got[StatusIndexed] != 100 {
		t.Fatalf("time limit: %v", got)
	}
}

func TestBuildClassifiesBinaryOversizedGeneratedAndFailedFiles(t *testing.T) {
	analyzer := realAnalyzer(t)
	files := map[string]string{
		"bin/data.js":       "var a = 1;\x00",
		"big/huge.py":       strings.Repeat("x = 1\n", (2<<20)/6+10),
		"gen/marked.go":     "// Code generated by x. DO NOT EDIT.\npackage gen\n",
		"gen/types.pb.go":   "package gen\n",
		"vendor/v/v.go":     "package v\n",
		"node_modules/m.js": "export const m = 1;\n",
		"docs/page.html":    "<p id=\"x\"></p>\n",
		"src/hang.go":       "package src\n",
	}
	store := newTestStore(t, DefaultStoreLimits())
	tree := newMemoryTree(1, files, nil)
	s := build(t, store, &switchAnalyzer{real: analyzer, fake: &fakeAnalyzer{}}, tree, DefaultBuildLimits(), nil)
	byPath := map[string]FileEntry{}
	for _, f := range s.Files {
		byPath[f.Path] = f
	}
	for path, want := range map[string][2]string{
		"bin/data.js":       {string(RoleSource), string(StatusBinary)},
		"big/huge.py":       {string(RoleSource), string(StatusIndexed)},
		"gen/marked.go":     {string(RoleGenerated), string(StatusIndexed)},
		"gen/types.pb.go":   {string(RoleGenerated), string(StatusIndexed)},
		"vendor/v/v.go":     {string(RoleVendored), string(StatusNotAnalysed)},
		"node_modules/m.js": {string(RoleVendored), string(StatusNotAnalysed)},
		"docs/page.html":    {string(RoleDocs), string(StatusNotAnalysed)},
		"src/hang.go":       {string(RoleSource), string(StatusFailed)},
	} {
		if f := byPath[path]; string(f.Role) != want[0] || string(f.Status) != want[1] {
			t.Errorf("%s: role %s status %s, want %v", path, f.Role, f.Status, want)
		}
	}
	g := loadGraph(t, store, s)
	gaps := g.files[g.byPath["big/huge.py"]].gaps
	if len(gaps) != 1 || gaps[0].Limit != syntaxanalysis.LimitFileSize {
		t.Fatalf("oversized file gaps = %v", gaps)
	}
	reads, fake := tree.reads.Load(), &fakeAnalyzer{}
	s = build(t, store, &switchAnalyzer{real: analyzer, fake: fake}, tree, DefaultBuildLimits(), nil)
	if tree.reads.Load()-reads != 1 || fake.calls.Load() != 1 || s.Coverage.Analysed != 0 {
		t.Fatalf("a rebuild read %d blobs; only the failed file is retried", tree.reads.Load()-reads)
	}
}

// switchAnalyzer sends hang.go to the fake analyzer and the rest to the
// real one.
type switchAnalyzer struct {
	real syntaxanalysis.Analyzer
	fake *fakeAnalyzer
}

func (s *switchAnalyzer) Supports(l syntaxanalysis.Language) bool { return true }

func (s *switchAnalyzer) Analyze(ctx context.Context, source syntaxanalysis.Source) (syntaxanalysis.FileAnalysis, error) {
	if strings.HasSuffix(source.Path(), "hang.go") {
		return s.fake.Analyze(ctx, source)
	}
	return s.real.Analyze(ctx, source)
}

func TestStoreLimitsEvictSnapshotsAndRecords(t *testing.T) {
	store := newTestStore(t, StoreLimits{MaxBytes: 1 << 30, MaxSnapshots: 2})
	analyzer := &fakeAnalyzer{}
	var last Snapshot
	for commit := 1; commit <= 4; commit++ {
		files := map[string]string{"shared.go": "package a\n", fmt.Sprintf("only%d.go", commit): fmt.Sprintf("package a // %d\n", commit)}
		last = build(t, store, analyzer, newMemoryTree(commit, files, nil), DefaultBuildLimits(), nil)
	}
	names := indexFiles(t, store)
	if names["snap"] != 2 {
		t.Fatalf("snapshots kept: %v", names)
	}
	if _, err := store.Load(context.Background(), "sha1", fmt.Sprintf("%040x", 1)); !errors.Is(err, ErrNotIndexed) {
		t.Fatalf("evicted snapshot loaded: %v", err)
	}
	g := loadGraph(t, store, last)
	if len(g.Files()) != 2 {
		t.Fatal("newest snapshot lost files")
	}

	files, order := manyFiles(200, ".go")
	tight := newTestStore(t, StoreLimits{MaxBytes: 20000, MaxSnapshots: 8})
	s := build(t, tight, analyzer, newMemoryTree(9, files, order), DefaultBuildLimits(), nil)
	if got := statuses(s); got[StatusStoreLimit] == 0 || got[StatusIndexed] == 0 {
		t.Fatalf("store limit: %v", got)
	}
	if total := folderBytes(t, tight); total > 20000 {
		t.Fatalf("store holds %d bytes, over its limit", total)
	}
}

func indexFiles(t *testing.T, store *Store) map[string]int {
	t.Helper()
	entries, err := os.ReadDir(store.Directory())
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]int{}
	for _, e := range entries {
		out[strings.SplitN(e.Name(), "-", 2)[0]]++
	}
	return out
}

func folderBytes(t *testing.T, store *Store) int64 {
	t.Helper()
	entries, _ := os.ReadDir(store.Directory())
	var total int64
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "seg-") || strings.HasPrefix(e.Name(), "snap-") {
			info, _ := e.Info()
			total += info.Size()
		}
	}
	return total
}

func TestStoreDropsStaleAndCorruptFilesAndRefusesUnprotectedOnes(t *testing.T) {
	store := newTestStore(t, DefaultStoreLimits())
	analyzer := &fakeAnalyzer{}
	tree := newMemoryTree(1, map[string]string{"a.go": "package a\n", "b.go": "package b\n"}, nil)
	build(t, store, analyzer, tree, DefaultBuildLimits(), nil)

	other, _ := NewStore(store.Directory(), [32]byte{9}, DefaultStoreLimits())
	if _, err := other.Load(context.Background(), "sha1", tree.commit); !errors.Is(err, ErrNotIndexed) {
		t.Fatalf("another analysis identity loaded the snapshot: %v", err)
	}
	if got := indexFiles(t, store); got["seg"] != 0 || got["snap"] != 0 {
		t.Fatalf("stale files kept: %v", got)
	}

	calls := analyzer.calls.Load()
	build(t, store, analyzer, tree, DefaultBuildLimits(), nil)
	if analyzer.calls.Load()-calls != 2 {
		t.Fatal("records of another identity were reused")
	}
	segments, _ := filepath.Glob(filepath.Join(store.Directory(), "seg-*"))
	data, _ := os.ReadFile(segments[0])
	data[len(data)-30] ^= 0xff
	if err := os.WriteFile(segments[0], data, 0o600); err != nil {
		t.Fatal(err)
	}
	calls = analyzer.calls.Load()
	s := build(t, store, analyzer, tree, DefaultBuildLimits(), nil)
	if analyzer.calls.Load()-calls != 2 || statuses(s)[StatusIndexed] != 2 {
		t.Fatal("a corrupt segment was not replaced")
	}

	segments, _ = filepath.Glob(filepath.Join(store.Directory(), "seg-*"))
	data, _ = os.ReadFile(segments[0])
	data[segmentHeader+2] ^= 0xff
	if err := os.WriteFile(segments[0], data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(context.Background(), "sha1", tree.commit); !errors.Is(err, ErrDamaged) {
		t.Fatalf("a damaged record loaded: %v", err)
	}
	calls = analyzer.calls.Load()
	if s := build(t, store, analyzer, tree, DefaultBuildLimits(), nil); analyzer.calls.Load()-calls != 2 || statuses(s)[StatusIndexed] != 2 {
		t.Fatal("the files of a damaged segment were not analysed again")
	}
	loadGraph(t, store, s)

	intruder := filepath.Join(store.Directory(), "seg-intruder.otx")
	if err := os.WriteFile(intruder, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	exposeToOthers(t, intruder)
	if _, err := store.Load(context.Background(), "sha1", tree.commit); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("an unprotected file was accepted: %v", err)
	}
}

func TestStoreAllowsOneProcessAtATime(t *testing.T) {
	store := newTestStore(t, DefaultStoreLimits())
	store.lockWait = 50 * time.Millisecond
	tree := newMemoryTree(1, map[string]string{"a.go": "package a\n"}, nil)
	slow := &fakeAnalyzer{delay: 300 * time.Millisecond}
	done := make(chan error, 1)
	go func() {
		_, err := Builder{Store: store, Analyzer: slow}.Build(context.Background(), tree)
		done <- err
	}()
	for slow.calls.Load() == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if _, err := store.Load(context.Background(), "sha1", tree.commit); !errors.Is(err, ErrBusy) {
		t.Fatalf("load during a build = %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestBuildAnalysesConcurrentlyAndCancels(t *testing.T) {
	files, order := manyFiles(400, ".go")
	analyzer := &fakeAnalyzer{delay: time.Millisecond}
	store := newTestStore(t, DefaultStoreLimits())
	s, err := Builder{Store: store, Analyzer: analyzer, Parallelism: 8}.Build(context.Background(), newMemoryTree(1, files, order))
	if err != nil || statuses(s)[StatusIndexed] != 400 {
		t.Fatalf("build = %v, %v", statuses(s), err)
	}
	if analyzer.peak.Load() < 2 || analyzer.peak.Load() > 8 {
		t.Fatalf("peak concurrency %d", analyzer.peak.Load())
	}
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			g, err := store.Load(context.Background(), s.Algorithm, s.Commit)
			if err == nil && len(g.Files()) != 400 {
				t.Error("partial graph")
			}
			if err != nil && !errors.Is(err, ErrBusy) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()

	for p := range files {
		files[p] += "// changed\n"
	}
	ctx, cancel := context.WithCancel(context.Background())
	slow := &fakeAnalyzer{delay: 20 * time.Millisecond}
	go func() {
		for slow.calls.Load() < 5 {
			time.Sleep(time.Millisecond)
		}
		cancel()
	}()
	if _, err := (Builder{Store: store, Analyzer: slow, Parallelism: 2}).Build(ctx, newMemoryTree(2, files, order)); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled build = %v", err)
	}
	if got := indexFiles(t, store); got["tmp"] != 0 || got["snap"] != 1 {
		t.Fatalf("a canceled build left files: %v", got)
	}
}
