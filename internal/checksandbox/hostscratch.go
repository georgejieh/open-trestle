//go:build windows || darwin

package checksandbox

import (
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
)

// readRegularFile reads the runner's report from the scratch after the run,
// refusing a link or anything larger than the report limit.
func readRegularFile(path string) []byte {
	link, err := os.Lstat(path)
	if err != nil || !link.Mode().IsRegular() {
		return nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()
	// The file opened must be the one checked, not a link put in its place.
	if opened, err := file.Stat(); err != nil || !os.SameFile(link, opened) {
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(file, reportLimit+1))
	if err != nil || len(data) > reportLimit {
		return nil
	}
	return data
}

// scratchMeter measures what a run stores. Windows and macOS offer no size
// bound for a folder without administrator rights, so this is a
// measurement, not a quota: it adds up everything stored below the folders
// the sandbox can write, alternate data streams included, and also counts
// how far the free space of their volumes has fallen since the run
// started, which covers files deleted while still open and anything else
// the walk cannot see. Other programs filling the same volume count too.
type scratchMeter struct {
	folders []string
	limit   int64
	volumes []volumeSpace
}

// volumeSpace is one volume's free space when the run started.
type volumeSpace struct {
	path string
	free uint64
}

func newScratchMeter(folders []string, limit int64) *scratchMeter {
	meter := &scratchMeter{folders: folders, limit: limit}
	seen := map[string]bool{}
	for _, folder := range folders {
		if volume, free, ok := volumeFree(folder); ok && !seen[volume] {
			seen[volume] = true
			meter.volumes = append(meter.volumes, volumeSpace{path: folder, free: free})
		}
	}
	return meter
}

// exceeded reports whether the run has stored more than the limit.
func (meter *scratchMeter) exceeded() bool {
	return meter.spaceTaken() > meter.limit || foldersSize(meter.folders, meter.limit) > meter.limit
}

// spaceTaken is how far the volumes' free space has fallen.
func (meter *scratchMeter) spaceTaken() int64 {
	var taken int64
	for _, volume := range meter.volumes {
		if _, free, ok := volumeFree(volume.path); ok && free < volume.free {
			taken += int64(volume.free - free)
		}
	}
	return taken
}

// watchDisk takes the meter's measurement every quarter second and calls
// exceeded once when it passes the limit, so a burst of writes can pass
// the limit for up to one interval before the kill.
func watchDisk(ctx context.Context, meter *scratchMeter, exceeded func()) *atomic.Bool {
	over := new(atomic.Bool)
	go func() {
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if meter.exceeded() {
					over.Store(true)
					exceeded()
					return
				}
			}
		}
	}()
	return over
}

// foldersSize adds up what is stored below each folder, stopping once past
// limit.
func foldersSize(folders []string, limit int64) int64 {
	var total int64
	for _, folder := range folders {
		total += folderSize(folder, limit-total)
		if total > limit {
			break
		}
	}
	return total
}

// folderSize adds up what is stored in root and below it, stopping once
// past limit.
func folderSize(root string, limit int64) int64 {
	var total int64
	_ = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		total += storedSize(path, entry)
		if total > limit {
			return filepath.SkipAll
		}
		return nil
	})
	return total
}

// lstatSize is the size of a file's main content. The size a folder
// listing reports for a file still being written can be stale on NTFS; the
// file's own metadata is current.
func lstatSize(path string, entry fs.DirEntry) int64 {
	if entry.IsDir() {
		return 0
	}
	if info, err := os.Lstat(path); err == nil {
		return info.Size()
	}
	return 0
}
