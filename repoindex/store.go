package repoindex

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
	// ErrDamaged reports damage: a file that fails its check or a record a
	// snapshot needs that is missing. The index is cleared, and the next
	// build starts over; Builder.Load and Builder.Build do that.
	ErrDamaged = errors.New("the repository index was damaged and has been cleared")

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

// Store is an index folder. It is private to this account (mode 0700 on
// Unix, an owner-only access list on Windows), and so is every file in it:
// segment files hold blob records and snapshot files list a commit's files.
// Every file starts with the format and the analysis identity, so a file of
// another format or analyzer build is removed when the store is opened. One
// process uses the folder at a time.
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
		if err := fileauthority.MkdirAllPrivate(s.dir); err != nil {
			return nil, fmt.Errorf("%w: cannot create %s", ErrUnavailable, s.dir)
		}
	}
	info, err := os.Lstat(s.dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotIndexed
	}
	if err != nil || !fileauthority.PrivateDirectory(s.dir, info) {
		return nil, fmt.Errorf("%w: %s must be a private folder (%s)", ErrUnavailable, s.dir, fileauthority.PrivateDirectoryRequirement(info))
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
			if err := sess.remove(name); err != nil {
				return err
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

// protected checks that a name in the folder is a private regular file.
func (sess *session) protected(name string) (os.FileInfo, error) {
	info, err := sess.root.Lstat(name)
	if err != nil || !fileauthority.PrivateFile(filepath.Join(sess.store.dir, name), info) {
		return nil, fmt.Errorf("%w: %s is not %s", ErrUnavailable, name, fileauthority.PrivateFileRequirement())
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
	if err != nil || !os.SameFile(before, opened) || !fileauthority.PrivateOpenFile(file, opened) {
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
		if errors.Is(err, errStale) {
			return sess.remove(name)
		}
		if errors.Is(err, errCorrupt) {
			return sess.clear()
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

func (sess *session) syncFolder() error {
	if err := fileauthority.SyncDirectory(sess.store.dir); err != nil {
		return fmt.Errorf("%w: cannot sync %s", ErrUnavailable, sess.store.dir)
	}
	return nil
}

func (sess *session) has(key Key) bool {
	_, ok := sess.records[key]
	return ok
}

func (sess *session) recordBytes(key Key) int64 { return sess.records[key].length }

// record reads a record. A record that is missing or fails its check is
// damage, which clears the index.
func (sess *session) record(key Key) (blobRecord, error) {
	l, ok := sess.records[key]
	if !ok {
		return blobRecord{}, sess.clear()
	}
	data, err := readRecord(sess.segments[l.segment].file, l)
	if err == nil {
		var record blobRecord
		if record, err = decodeBlobRecord(data); err == nil {
			return record, nil
		}
	}
	return blobRecord{}, sess.clear()
}

// clear is the one answer to damage: it removes every segment and
// snapshot, so that the index starts over, and reports ErrDamaged.
func (sess *session) clear() error {
	for _, seg := range sess.segments {
		_ = seg.file.Close()
	}
	sess.segments, sess.records, sess.snapshots = nil, map[Key]location{}, map[string]int64{}
	entries, err := os.ReadDir(sess.store.dir)
	if err != nil {
		return ErrUnavailable
	}
	for _, entry := range entries {
		if name := entry.Name(); strings.HasPrefix(name, "seg-") || strings.HasPrefix(name, "snap-") {
			if err := sess.remove(name); err != nil {
				return err
			}
		}
	}
	return ErrDamaged
}
