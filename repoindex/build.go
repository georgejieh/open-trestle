package repoindex

import (
	"context"
	"errors"
	"slices"
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

// snapshotEntryBytes estimates the bytes of one snapshot entry, which the
// store limit reserves before records.
const snapshotEntryBytes = 128

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

	budget := max(0, b.Store.limits.MaxBytes-int64(len(s.Files))*snapshotEntryBytes)
	var recordBytes int64
	pending := []int{}
	for i, f := range s.Files {
		if f.Status != "" {
			continue
		}
		key := s.key(f)
		if !sess.has(key) {
			pending = append(pending, i)
			continue
		}
		if recordBytes+sess.recordBytes(key) > budget {
			s.Files[i].Status = StatusStoreLimit
			continue
		}
		recordBytes += sess.recordBytes(key)
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
		f := &s.Files[o.index]
		if o.record == nil {
			f.Status = o.status
			continue
		}
		encoded := o.record.encode()
		if recordBytes+int64(len(encoded)) > budget {
			f.Status = StatusStoreLimit
			continue
		}
		if err := segment.add(s.key(*f), o.record.flags(), encoded); err != nil {
			_ = wait(true)
			return Snapshot{}, ErrUnavailable
		}
		recordBytes += int64(len(encoded))
		*f = withFlags(*f, o.record.flags())
		if !o.record.binary {
			s.Coverage.Analysed++
			s.Coverage.AnalysedBytes += o.record.size
		}
	}
	if err := wait(false); err != nil {
		return Snapshot{}, err
	}
	s.BuiltAt = now().UTC()
	s.Coverage.Duration = s.BuiltAt.Sub(started)
	committed = true
	if err := sess.installSegment(segment); err != nil {
		return Snapshot{}, err
	}
	if err := sess.writeSnapshot(s); err != nil {
		return Snapshot{}, err
	}
	return s, sess.evict()
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
