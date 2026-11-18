package repoindex

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/georgejieh/open-trestle/internal/fileauthority"
	"github.com/georgejieh/open-trestle/internal/filelock"
)

var (
	// ErrUnavailable reports an index folder that cannot be used: missing
	// where it must exist, not private, or holding a file that is not a
	// protected file.
	ErrUnavailable = errors.New("repository index folder cannot be used")
	// ErrBusy reports that another process holds the index.
	ErrBusy = errors.New("repository index is in use by another process")
	// ErrNotIndexed reports a commit the index has no snapshot of.
	ErrNotIndexed = errors.New("commit is not indexed")

	errCorrupt = errors.New("repository index file is corrupt")
	errStale   = errors.New("repository index file has another analysis identity")
)

// StoreLimits bound the index folder.
type StoreLimits struct {
	// MaxBytes bounds the segment and snapshot files together.
	MaxBytes int64
	// MaxSnapshots bounds the commits kept.
	MaxSnapshots int
}

// DefaultStoreLimits returns the limits used unless configured.
func DefaultStoreLimits() StoreLimits { return StoreLimits{MaxBytes: 1 << 30, MaxSnapshots: 8} }

const (
	lockName = "lock"
	// maxSegments is how many segment files may accumulate before they are
	// merged into one.
	maxSegments = 8
	// maxSnapshotFileBytes bounds one snapshot file.
	maxSnapshotFileBytes = 512 << 20
	// compactionSlack is how far the segments may grow past the records
	// the snapshots use before they are rewritten.
	compactionSlack = 64 << 20
)

// Store is an index folder. Every file in it is a 0600 regular file owned
// by this account in a 0700 folder; segment files hold blob records and
// snapshot files list a commit's files. Every file starts with the format
// and the analysis identity, so a file of another format or analyzer build
// is removed when the store is opened. One process uses the folder at a
// time.
type Store struct {
	dir      string
	identity [32]byte
	limits   StoreLimits
	lockWait time.Duration
}

// NewStore names an index folder by absolute path. Identity is the
// analysis identity: records made by other analyzer code are never used.
// It touches nothing.
func NewStore(dir string, identity [32]byte, limits StoreLimits) (*Store, error) {
	if dir == "" || !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || limits.MaxBytes <= 0 || limits.MaxSnapshots <= 0 {
		return nil, ErrUnavailable
	}
	return &Store{dir: dir, identity: identity, limits: limits, lockWait: 3 * time.Second}, nil
}

// Directory returns the index folder.
func (s *Store) Directory() string { return s.dir }

type segmentFile struct {
	name string
	file *os.File
	size int64
}

// session is the store held under its lock.
type session struct {
	store     *Store
	pin       *fileauthority.DirectoryPin
	lock      *filelock.Lock
	root      *os.Root
	segments  []segmentFile
	records   map[Key]location
	snapshots map[string]int64
}

func (s *Store) prepare(create bool) (*fileauthority.DirectoryPin, error) {
	if create {
		if err := os.MkdirAll(s.dir, 0o700); err != nil {
			return nil, fmt.Errorf("%w: cannot create %s", ErrUnavailable, s.dir)
		}
	}
	info, err := os.Lstat(s.dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotIndexed
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return nil, fmt.Errorf("%w: %s must be a private folder (mode 0700)", ErrUnavailable, s.dir)
	}
	pin, err := fileauthority.PinDirectory(s.dir)
	if err != nil {
		return nil, fmt.Errorf("%w: %s or a parent folder is not owned by this account or is writable by others", ErrUnavailable, s.dir)
	}
	return pin, nil
}

func (s *Store) acquire(ctx context.Context, pin *fileauthority.DirectoryPin) (*filelock.Lock, error) {
	deadline := time.Now().Add(s.lockWait)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if pin.Recheck() != nil {
			return nil, ErrUnavailable
		}
		lock, err := filelock.Acquire(filepath.Join(s.dir, lockName))
		if err == nil {
			return lock, nil
		}
		if !errors.Is(err, filelock.ErrLocked) {
			return nil, fmt.Errorf("%w: cannot lock the index", ErrUnavailable)
		}
		if time.Now().After(deadline) {
			return nil, ErrBusy
		}
		timer := time.NewTimer(20 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

// open locks the folder and reads every segment directory. It removes what
// an interrupted write left and the files of another format or analysis
// identity.
func (s *Store) open(ctx context.Context, create bool) (*session, error) {
	pin, err := s.prepare(create)
	if err != nil {
		return nil, err
	}
	lock, err := s.acquire(ctx, pin)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(s.dir)
	if err != nil {
		_ = lock.Close()
		return nil, ErrUnavailable
	}
	sess := &session{store: s, pin: pin, lock: lock, root: root, records: map[Key]location{}, snapshots: map[string]int64{}}
	if err := sess.scan(); err != nil {
		sess.close()
		return nil, err
	}
	return sess, nil
}

func (sess *session) scan() error {
	entries, err := os.ReadDir(sess.store.dir)
	if err != nil {
		return ErrUnavailable
	}
	for _, entry := range entries {
		name := entry.Name()
		switch {
		case strings.HasPrefix(name, "tmp-"):
			if err := sess.root.Remove(name); err != nil {
				return ErrUnavailable
			}
		case strings.HasPrefix(name, "seg-"):
			if err := sess.addSegment(name); err != nil {
				return err
			}
		case strings.HasPrefix(name, "snap-"):
			info, err := sess.protected(name)
			if err != nil {
				return err
			}
			sess.snapshots[name] = info.Size()
		}
	}
	return nil
}

// protected checks that a name in the folder is a protected file.
func (sess *session) protected(name string) (os.FileInfo, error) {
	info, err := sess.root.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || !fileauthority.TrustedOwner(info) {
		return nil, fmt.Errorf("%w: %s is not a protected file (a 0600 regular file owned by this account)", ErrUnavailable, name)
	}
	return info, nil
}

func (sess *session) openProtected(name string) (*os.File, os.FileInfo, error) {
	before, err := sess.protected(name)
	if err != nil {
		return nil, nil, err
	}
	file, err := sess.root.Open(name)
	if err != nil {
		return nil, nil, ErrUnavailable
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		_ = file.Close()
		return nil, nil, ErrUnavailable
	}
	return file, opened, nil
}

func (sess *session) addSegment(name string) error {
	file, info, err := sess.openProtected(name)
	if err != nil {
		return err
	}
	entries, err := readSegmentDirectory(file, info.Size(), sess.store.identity, len(sess.segments))
	if err != nil {
		_ = file.Close()
		if errors.Is(err, errStale) || errors.Is(err, errCorrupt) {
			return sess.remove(name)
		}
		return err
	}
	sess.segments = append(sess.segments, segmentFile{name: name, file: file, size: info.Size()})
	for key, l := range entries {
		if _, ok := sess.records[key]; !ok {
			sess.records[key] = l
		}
	}
	return nil
}

func (sess *session) remove(name string) error {
	if err := sess.root.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%w: cannot remove %s", ErrUnavailable, name)
	}
	return nil
}

func (sess *session) close() {
	for _, seg := range sess.segments {
		_ = seg.file.Close()
	}
	_ = sess.root.Close()
	_ = sess.lock.Close()
}

func (sess *session) has(key Key) bool {
	_, ok := sess.records[key]
	return ok
}

func (sess *session) recordBytes(key Key) int64 { return sess.records[key].length }

func (sess *session) record(key Key) (blobRecord, error) {
	l, ok := sess.records[key]
	if !ok {
		return blobRecord{}, errCorrupt
	}
	data, err := readRecord(sess.segments[l.segment].file, l)
	if err != nil {
		return blobRecord{}, err
	}
	return decodeBlobRecord(data)
}

// createTemporary creates a protected temporary file in the folder.
func (sess *session) createTemporary() (*os.File, string, error) {
	var random [12]byte
	_, _ = rand.Read(random[:])
	name := "tmp-" + hex.EncodeToString(random[:])
	file, err := sess.root.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, "", fmt.Errorf("%w: cannot write in %s", ErrUnavailable, sess.store.dir)
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		_ = sess.root.Remove(name)
		return nil, "", ErrUnavailable
	}
	return file, name, nil
}

// install renames a finished temporary file into place.
func (sess *session) install(temporary, name string) error {
	if sess.pin.Recheck() != nil {
		return ErrUnavailable
	}
	if err := sess.root.Rename(temporary, name); err != nil {
		return fmt.Errorf("%w: cannot install %s", ErrUnavailable, name)
	}
	return nil
}

func (sess *session) syncFolder() error {
	folder, err := sess.root.Open(".")
	if err != nil {
		return ErrUnavailable
	}
	defer folder.Close()
	if err := folder.Sync(); err != nil && !errors.Is(err, os.ErrInvalid) {
		return fmt.Errorf("%w: cannot sync %s", ErrUnavailable, sess.store.dir)
	}
	return nil
}

func (sess *session) newSegment() (*segmentWriter, error) {
	file, name, err := sess.createTemporary()
	if err != nil {
		return nil, err
	}
	w, err := newSegmentWriter(file, name, sess.store.identity)
	if err != nil {
		sess.discard(&segmentWriter{file: file, name: name})
		return nil, ErrUnavailable
	}
	return w, nil
}

// discard removes an unfinished segment.
func (sess *session) discard(w *segmentWriter) {
	_ = w.file.Close()
	_ = sess.root.Remove(w.name)
}

// installSegment finishes a segment and adds its records to the session.
func (sess *session) installSegment(w *segmentWriter) error {
	if len(w.keys) == 0 {
		sess.discard(w)
		return nil
	}
	if err := w.finish(); err != nil {
		sess.discard(w)
		return fmt.Errorf("%w: cannot write a segment", ErrUnavailable)
	}
	if err := w.file.Close(); err != nil {
		_ = sess.root.Remove(w.name)
		return ErrUnavailable
	}
	var random [8]byte
	_, _ = rand.Read(random[:])
	name := "seg-" + hex.EncodeToString(random[:]) + ".otx"
	if err := sess.install(w.name, name); err != nil {
		_ = sess.root.Remove(w.name)
		return err
	}
	return sess.addSegment(name)
}

func snapshotName(algorithm, commit string) string {
	return "snap-" + algorithm + "-" + commit + ".otx"
}

// writeSnapshot installs a snapshot, replacing one of the same commit.
func (sess *session) writeSnapshot(s Snapshot) error {
	content := encodeSnapshot(s, sess.store.identity)
	if len(content) > maxSnapshotFileBytes {
		return fmt.Errorf("%w: the snapshot is larger than %d bytes", ErrUnavailable, maxSnapshotFileBytes)
	}
	file, temporary, err := sess.createTemporary()
	if err != nil {
		return err
	}
	_, werr := file.Write(content)
	serr := file.Sync()
	cerr := file.Close()
	if werr != nil || serr != nil || cerr != nil {
		_ = sess.root.Remove(temporary)
		return fmt.Errorf("%w: cannot write a snapshot", ErrUnavailable)
	}
	name := snapshotName(s.Algorithm, s.Commit)
	if err := sess.install(temporary, name); err != nil {
		_ = sess.root.Remove(temporary)
		return err
	}
	sess.snapshots[name] = int64(len(content))
	return nil
}

// readSnapshot reads a snapshot file. A stale or corrupt one is removed and
// reported as missing.
func (sess *session) readSnapshot(name string) (Snapshot, bool, error) {
	if _, ok := sess.snapshots[name]; !ok {
		return Snapshot{}, false, nil
	}
	file, info, err := sess.openProtected(name)
	if err != nil {
		return Snapshot{}, false, err
	}
	defer file.Close()
	if info.Size() > maxSnapshotFileBytes {
		return Snapshot{}, false, fmt.Errorf("%w: %s is larger than %d bytes", ErrUnavailable, name, maxSnapshotFileBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxSnapshotFileBytes+1))
	if err != nil || int64(len(data)) != info.Size() {
		return Snapshot{}, false, ErrUnavailable
	}
	snapshot, err := decodeSnapshot(data, sess.store.identity)
	if errors.Is(err, errCorrupt) || errors.Is(err, errStale) || err == nil && name != snapshotName(snapshot.Algorithm, snapshot.Commit) {
		delete(sess.snapshots, name)
		return Snapshot{}, false, sess.remove(name)
	}
	return snapshot, err == nil, err
}

// allSnapshots reads every snapshot, newest build first.
func (sess *session) allSnapshots() ([]Snapshot, error) {
	names := make([]string, 0, len(sess.snapshots))
	for name := range sess.snapshots {
		names = append(names, name)
	}
	slices.Sort(names)
	out := []Snapshot{}
	for _, name := range names {
		s, ok, err := sess.readSnapshot(name)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, s)
		}
	}
	slices.SortStableFunc(out, func(a, b Snapshot) int { return b.BuiltAt.Compare(a.BuiltAt) })
	return out, nil
}

// liveRecords returns the keys of the records the snapshots use that the
// store holds, and their bytes.
func (sess *session) liveRecords(snapshots []Snapshot) (map[Key]bool, int64) {
	live := map[Key]bool{}
	var bytes int64
	for _, s := range snapshots {
		for _, f := range s.Files {
			if f.Status != StatusIndexed {
				continue
			}
			key := s.key(f)
			if l, ok := sess.records[key]; ok && !live[key] {
				live[key] = true
				bytes += l.length
			}
		}
	}
	return live, bytes
}

// evict applies the store limits: it keeps the newest snapshots up to
// MaxSnapshots, drops the oldest while their records pass MaxBytes (never
// the newest), and rewrites the segments when they hold records no snapshot
// uses or the files pass MaxBytes.
func (sess *session) evict() error {
	snapshots, err := sess.allSnapshots()
	if err != nil {
		return err
	}
	limits := sess.store.limits
	keep := min(len(snapshots), limits.MaxSnapshots)
	live, liveBytes := sess.liveRecords(snapshots[:keep])
	for keep > 1 && liveBytes+sess.snapshotBytes(snapshots[:keep]) > limits.MaxBytes {
		keep--
		live, liveBytes = sess.liveRecords(snapshots[:keep])
	}
	for _, s := range snapshots[keep:] {
		name := snapshotName(s.Algorithm, s.Commit)
		delete(sess.snapshots, name)
		if err := sess.remove(name); err != nil {
			return err
		}
	}
	var segmentBytes int64
	for _, seg := range sess.segments {
		segmentBytes += seg.size
	}
	if segmentBytes+sess.snapshotBytes(snapshots[:keep]) <= limits.MaxBytes && len(sess.segments) <= maxSegments && segmentBytes <= liveBytes+compactionSlack {
		return sess.syncFolder()
	}
	return sess.compact(live)
}

func (sess *session) snapshotBytes(snapshots []Snapshot) int64 {
	var n int64
	for _, s := range snapshots {
		n += sess.snapshots[snapshotName(s.Algorithm, s.Commit)]
	}
	return n
}

// compact writes the live records to one new segment and removes the rest.
func (sess *session) compact(live map[Key]bool) error {
	keys := make([]Key, 0, len(live))
	for key := range live {
		keys = append(keys, key)
	}
	slices.SortFunc(keys, func(a, b Key) int {
		x, y := sess.records[a], sess.records[b]
		if x.segment != y.segment {
			return x.segment - y.segment
		}
		return int(x.offset - y.offset)
	})
	old := sess.segments
	w, err := sess.newSegment()
	if err != nil {
		return err
	}
	for _, key := range keys {
		l := sess.records[key]
		data, err := readRecord(old[l.segment].file, l)
		if err == nil {
			err = w.add(key, l.flags, data)
		}
		if err != nil {
			sess.discard(w)
			return fmt.Errorf("%w: cannot compact the index", ErrUnavailable)
		}
	}
	oldRecords := sess.records
	sess.segments, sess.records = nil, map[Key]location{}
	if err := sess.installSegment(w); err != nil {
		sess.segments, sess.records = old, oldRecords
		return err
	}
	for _, seg := range old {
		_ = seg.file.Close()
		if err := sess.remove(seg.name); err != nil {
			return err
		}
	}
	return sess.syncFolder()
}
