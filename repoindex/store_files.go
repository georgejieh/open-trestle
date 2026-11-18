package repoindex

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"

	"github.com/georgejieh/open-trestle/internal/fileauthority"
)

// createTemporary creates a private temporary file in the folder.
func (sess *session) createTemporary() (*os.File, string, error) {
	var random [12]byte
	_, _ = rand.Read(random[:])
	name := "tmp-" + hex.EncodeToString(random[:])
	file, err := fileauthority.CreatePrivateFile(filepath.Join(sess.store.dir, name))
	if err != nil {
		return nil, "", fmt.Errorf("%w: cannot write in %s", ErrUnavailable, sess.store.dir)
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
	if errors.Is(err, errCorrupt) || err == nil && name != snapshotName(snapshot.Algorithm, snapshot.Commit) {
		return Snapshot{}, false, sess.clear()
	}
	if errors.Is(err, errStale) {
		delete(sess.snapshots, name)
		return Snapshot{}, false, sess.remove(name)
	}
	return snapshot, err == nil, err
}

func (sess *session) snapshot(algorithm, commit string) (Snapshot, error) {
	snapshot, ok, err := sess.readSnapshot(snapshotName(algorithm, commit))
	if err == nil && !ok {
		err = ErrNotIndexed
	}
	return snapshot, err
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
