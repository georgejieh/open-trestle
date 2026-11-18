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

// watchDisk measures the folders the sandbox can write every interval and
// calls exceeded once when together they hold more than limit bytes. Windows and macOS offer no size
// bound for a folder without administrator rights, so a burst of writes
// can pass the limit for up to one interval before the kill.
func watchDisk(ctx context.Context, folders []string, limit int64, exceeded func()) *atomic.Bool {
	over := new(atomic.Bool)
	go func() {
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if foldersSize(folders, limit) > limit {
					over.Store(true)
					exceeded()
					return
				}
			}
		}
	}()
	return over
}

// foldersSize adds up file sizes below each folder, stopping once past
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

// folderSize adds up file sizes below root, stopping once past limit.
func folderSize(root string, limit int64) int64 {
	var total int64
	_ = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return nil
		}
		// The size a folder listing reports for a file still being written
		// can be stale on NTFS; the file's own metadata is current.
		if info, err := os.Lstat(path); err == nil {
			total += info.Size()
		}
		if total > limit {
			return filepath.SkipAll
		}
		return nil
	})
	return total
}
