package repoindex

import (
	"fmt"
	"slices"
)

// liveRecords returns the keys of the records the snapshots use that the
// store holds, and their bytes.
func (sess *session) liveRecords(snapshots []Snapshot) (map[Key]bool, int64) {
	live := map[Key]bool{}
	var bytes int64
	for _, s := range snapshots {
		for _, f := range s.Files {
			if f.Status != StatusIndexed && f.Status != StatusBinary {
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

// compact writes the live records to one new segment and then removes the
// old segments. A damaged record clears the index. The new segment's name
// is made durable before any old segment is removed.
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
		if err != nil {
			sess.discard(w)
			return sess.clear()
		}
		if err := w.add(key, l.flags, data); err != nil {
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
	if err := sess.syncFolder(); err != nil {
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
