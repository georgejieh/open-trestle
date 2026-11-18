package repoindex

import (
	"context"
	"errors"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

// Builder indexes commits into a store.
type Builder struct {
	Store *Store
	// Analyzer analyses each new blob, usually a syntaxworker.Pool.
	Analyzer syntaxanalysis.Analyzer
	// Limits bound each build; the zero value means DefaultBuildLimits.
	Limits BuildLimits
	// Parallelism is how many files are analysed at once; zero means one.
	Parallelism int
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// analysedRoles are the roles whose files are analysed. Vendored code is
// third-party code that a review does not cover.
var analysedRoles = map[Role]int{RoleSource: 0, RoleTest: 1, RoleGenerated: 2}

// segmentOverhead is a segment's header and trailer, and directoryEntryBytes
// the most a record's directory entry takes; the store limit reserves both.
const (
	segmentOverhead     = int64(segmentHeader + segmentTrailer + 10)
	directoryEntryBytes = 32 + 1 + 10 + 10 + 4
)

type outcome struct {
	index  int
	status Status
	record *blobRecord
}

// Build indexes a commit and stores its snapshot. Only blobs the store has
// no record of are read and analysed. A file a limit leaves out keeps the
// limit as its status, so a later build of the same commit continues where
// this one stopped. Cancellation aborts the build and stores nothing.
func (b Builder) Build(ctx context.Context, tree Tree) (Snapshot, error) {
	limits := b.Limits
	if limits == (BuildLimits{}) {
		limits = DefaultBuildLimits()
	}
	if b.Store == nil || b.Analyzer == nil || !limits.valid() || b.Parallelism < 0 {
		return Snapshot{}, errors.New("invalid repository index build")
	}
	now := b.Now
	if now == nil {
		now = time.Now
	}
	sess, err := b.Store.open(ctx, true)
	if err != nil {
		return Snapshot{}, err
	}
	defer sess.close()
	started := now()
	s := Snapshot{Algorithm: tree.Algorithm(), Commit: tree.Commit(), Coverage: Coverage{Limits: limits}}
	invalid := 0
	walk, err := tree.Walk(ctx, limits.MaxEntries, func(e TreeEntry) error {
		if !syntaxanalysis.ValidPath(e.Path) || !validObject(e.Object) {
			invalid++
			return nil
		}
		s.Files = append(s.Files, newFileEntry(e))
		return nil
	})
	if err != nil {
		return Snapshot{}, err
	}
	s.Coverage.TreeEntries, s.Coverage.TreeTruncated, s.Coverage.InvalidPaths = len(s.Files), walk.Truncated, walk.InvalidPaths+invalid
	if s.Modules, err = goModules(ctx, tree, s.Files); err != nil {
		return Snapshot{}, err
	}

	budget := max(0, b.Store.limits.MaxBytes-int64(len(encodeSnapshot(s, b.Store.identity)))-segmentOverhead)
	var recordBytes int64
	// Files with the same blob and key share one record and one analysis:
	// pending holds the first of them and sharing the others.
	pending, sharing, counted := []int{}, map[Key][]int{}, map[Key]bool{}
	for i, f := range s.Files {
		if f.Status != "" {
			continue
		}
		key := s.key(f)
		if !sess.has(key) {
			if _, seen := sharing[key]; !seen {
				pending = append(pending, i)
			}
			sharing[key] = append(sharing[key], i)
			continue
		}
		if !counted[key] && recordBytes+sess.recordBytes(key)+directoryEntryBytes > budget {
			s.Files[i].Status = StatusStoreLimit
			continue
		}
		if !counted[key] {
			counted[key] = true
			recordBytes += sess.recordBytes(key) + directoryEntryBytes
		}
		s.Files[i] = withFlags(f, sess.records[key].flags)
		s.Coverage.Reused++
	}
	slices.SortStableFunc(pending, func(x, y int) int { return analysedRoles[s.Files[x].Role] - analysedRoles[s.Files[y].Role] })

	segment, err := sess.newSegment()
	if err != nil {
		return Snapshot{}, err
	}
	committed := false
	defer func() {
		if !committed {
			sess.discard(segment)
		}
	}()
	outcomes, wait := b.analyse(ctx, tree, &s, pending, limits, started, now)
	for o := range outcomes {
		key := s.key(s.Files[o.index])
		apply := func(update func(*FileEntry)) {
			for _, i := range sharing[key] {
				update(&s.Files[i])
			}
		}
		if o.record == nil {
			apply(func(f *FileEntry) { f.Status = o.status })
			continue
		}
		encoded := o.record.encode()
		if recordBytes+int64(len(encoded))+directoryEntryBytes > budget {
			apply(func(f *FileEntry) { f.Status = StatusStoreLimit })
			continue
		}
		if err := segment.add(key, o.record.flags(), encoded); err != nil {
			_ = wait(true)
			return Snapshot{}, ErrUnavailable
		}
		recordBytes += int64(len(encoded)) + directoryEntryBytes
		apply(func(f *FileEntry) { *f = withFlags(*f, o.record.flags()) })
		if !o.record.binary {
			s.Coverage.Analysed++
			s.Coverage.AnalysedBytes += o.record.size
		}
	}
	if err := wait(false); err != nil {
		return Snapshot{}, err
	}
	s.BuiltAt = now().UTC()
	// A clock that steps backwards must not make the duration negative.
	s.Coverage.Duration = max(0, s.BuiltAt.Sub(started))
	committed = true
	if err := sess.installSegment(segment); err != nil {
		return Snapshot{}, err
	}
	if err := sess.writeSnapshot(s); err != nil {
		return Snapshot{}, err
	}
	return s, sess.evict()
}

// maxGoModFiles and maxGoModBytes bound the go.mod files a build reads.
const (
	maxGoModFiles = 1024
	maxGoModBytes = 1 << 20
)

// goModules reads the module path of every go.mod file outside vendored
// code. A go.mod file that cannot be read or declares no module is left out,
// and its packages resolve by path suffix instead.
func goModules(ctx context.Context, tree Tree, files []FileEntry) ([]GoModule, error) {
	found := []FileEntry{}
	for _, f := range files {
		if path.Base(f.Path) == "go.mod" && f.Status == StatusNotAnalysed && f.Role != RoleVendored && len(found) < maxGoModFiles {
			found = append(found, f)
		}
	}
	modules := []GoModule{}
	next := 0
	err := tree.ReadBlobs(ctx, func() (string, bool) {
		if next >= len(found) {
			return "", false
		}
		next++
		return found[next-1].Object, true
	}, func(content []byte, err error) error {
		if err == nil && len(content) <= maxGoModBytes {
			if module := goModulePath(content); module != "" {
				modules = append(modules, GoModule{Dir: path.Dir(found[next-1].Path), Path: module})
			}
		}
		return ctx.Err()
	})
	slices.SortStableFunc(modules, func(a, b GoModule) int { return len(b.Path) - len(a.Path) })
	return modules, err
}

// goModulePath returns the path of a go.mod file's module directive.
func goModulePath(content []byte) string {
	for _, line := range strings.Split(string(content), "\n") {
		line, _, _ = strings.Cut(line, "//")
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "module" {
			module := strings.Trim(fields[1], "\"`")
			if syntaxanalysis.ValidPath(module) && !strings.ContainsAny(module, " \\") {
				return module
			}
			return ""
		}
	}
	return ""
}

// newFileEntry classifies a tree entry. A file to be analysed is left
// without a status.
func newFileEntry(e TreeEntry) FileEntry {
	f := FileEntry{Path: e.Path, Object: e.Object, Role: ClassifyPath(e.Path)}
	language, known := syntaxanalysis.LanguageForPath(e.Path)
	if known {
		f.Language = language
	}
	_, analysed := analysedRoles[f.Role]
	switch {
	case e.Kind == EntrySymlink:
		f.Status = StatusSymlink
	case e.Kind == EntrySubmodule:
		f.Status = StatusSubmodule
	case !known || !analysed:
		f.Status = StatusNotAnalysed
	}
	return f
}

// failedAsAWhole reports an analysis that is only a whole-file gap of a
// failure that may not recur: a deadline, a failed worker or analyzer, or
// an analyzer that could not run.
func failedAsAWhole(a syntaxanalysis.FileAnalysis) bool {
	if len(a.Gaps) != 1 || a.Gaps[0].HasRange || len(a.Definitions)+len(a.References)+len(a.Imports) > 0 {
		return false
	}
	switch a.Gaps[0].Reason {
	case syntaxanalysis.GapDeadlineExceeded, syntaxanalysis.GapAnalysisFailed, syntaxanalysis.GapAnalysisUnavailable:
		return true
	}
	return false
}

// withFlags gives an entry the status and role its stored record implies.
func withFlags(f FileEntry, flags byte) FileEntry {
	f.Status = StatusIndexed
	if flags&flagBinary != 0 {
		f.Status = StatusBinary
	}
	if flags&flagGenerated != 0 && f.Role != RoleVendored {
		f.Role = RoleGenerated
	}
	return f
}

// analyse reads the pending blobs in order and analyses them on
// b.Parallelism goroutines. Every pending file yields one outcome. wait
// ends the work, after stopping it when abort is set, and returns the first
// error: a cancellation or a failure of the analyzer's contract.
func (b Builder) analyse(parent context.Context, tree Tree, s *Snapshot, pending []int, limits BuildLimits, started time.Time, now func() time.Time) (<-chan outcome, func(abort bool) error) {
	ctx, cancel := context.WithCancel(parent)
	outcomes := make(chan outcome, 64)
	type job struct {
		index  int
		source syntaxanalysis.Source
		record blobRecord
	}
	jobs := make(chan job)
	errs := make(chan error, 1)
	fail := func(err error) {
		select {
		case errs <- err:
		default:
		}
		cancel()
	}
	workers := max(1, b.Parallelism)
	done := make(chan struct{}, workers)
	for range workers {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := range jobs {
				analysis, err := b.Analyzer.Analyze(ctx, j.source)
				if err == nil && failedAsAWhole(analysis) {
					outcomes <- outcome{index: j.index, status: StatusFailed}
					continue
				}
				if err == nil {
					j.record.analysis, err = syntaxanalysis.EncodeBinary(analysis)
				}
				if err != nil {
					fail(err)
					continue
				}
				outcomes <- outcome{index: j.index, record: &j.record}
			}
		}()
	}
	go func() {
		defer func() {
			close(jobs)
			for range workers {
				<-done
			}
			close(outcomes)
		}()
		files, bytes, stopped := 0, int64(0), Status("")
		position, current := 0, -1
		// next skips the files a limit leaves out and returns the next blob
		// to read.
		next := func() (string, bool) {
			for ; position < len(pending) && ctx.Err() == nil; position++ {
				i := pending[position]
				switch {
				case stopped != "":
				case files >= limits.MaxFiles:
					stopped = StatusFileLimit
				case now().Sub(started) >= limits.MaxDuration:
					stopped = StatusTimeLimit
				}
				if stopped != "" {
					outcomes <- outcome{index: i, status: stopped}
					continue
				}
				current = i
				position++
				return s.Files[i].Object, true
			}
			return "", false
		}
		deliver := func(content []byte, err error) error {
			i, f := current, s.Files[current]
			switch {
			case ctx.Err() != nil:
				return ctx.Err()
			case err != nil:
				outcomes <- outcome{index: i, status: StatusUnavailable}
				return nil
			case bytes+int64(len(content)) > limits.MaxBytes:
				stopped = StatusByteLimit
				outcomes <- outcome{index: i, status: stopped}
				return nil
			}
			record := blobRecord{size: int64(len(content)), generated: isGeneratedContent(content)}
			if isBinaryContent(content) {
				record.binary = true
				outcomes <- outcome{index: i, record: &record}
				return nil
			}
			source, err := syntaxanalysis.NewSource(f.Path, f.Language, content)
			if err != nil {
				outcomes <- outcome{index: i, status: StatusUnavailable}
				return nil
			}
			files++
			bytes += int64(len(content))
			select {
			case jobs <- job{index: i, source: source, record: record}:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		if err := tree.ReadBlobs(ctx, next, deliver); err != nil {
			fail(err)
		}
	}()
	wait := func(abort bool) error {
		if abort {
			cancel()
		}
		for range outcomes {
		}
		cancel()
		select {
		case err := <-errs:
			return err
		default:
			return parent.Err()
		}
	}
	return outcomes, wait
}
