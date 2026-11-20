package checksandbox

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Prefixes of the temporary folders that a review's checks create: Run
// makes the scratches, internal/repochecks the Go seeds and cmd/trestle
// the tree copies. SweepStale removes old ones.
const (
	scratchFolderPrefix = "open-trestle-check-"
	GoSeedFolderPrefix  = "open-trestle-go-seed-"
	TreesFolderPrefix   = "open-trestle-trees-"
)

// staleAge is how old a leftover must be before SweepStale removes it. No
// review's checks run this long, so one this old belongs to a run that was
// killed.
const staleAge = time.Hour

// SweepStale removes what earlier runs left when they were killed before
// they could clean up: scratch folders, Go seed folders and tree copies in
// the temporary folder, and on Windows the sandboxes' AppContainer
// profiles. It touches only those older than an hour, so the checks of a
// review running at the same time keep theirs. Call it once at the start
// of a review that runs checks; what it cannot remove, a later sweep tries
// again.
func SweepStale() {
	cutoff := time.Now().Add(-staleAge)
	parent := os.TempDir()
	entries, err := os.ReadDir(parent)
	if err == nil {
		for _, entry := range entries {
			if entry.IsDir() && sweptFolder(entry.Name()) && olderThan(entry, cutoff) {
				_ = removeScratch(filepath.Join(parent, entry.Name()))
			}
		}
	}
	sweepProfiles(cutoff)
}

// RemoveToolchainGrants takes back the read access that runs on Windows gave
// the sandbox's toolchain capability on toolchain and cache folders, as
// recorded when each was granted; `trestle checks off` calls it. Folders
// whose access could not be changed stay recorded for the next call. On
// other systems nothing is granted and it returns nil.
func RemoveToolchainGrants() error { return removeToolchainGrants() }

func sweptFolder(name string) bool {
	for _, prefix := range []string{scratchFolderPrefix, GoSeedFolderPrefix, TreesFolderPrefix} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func olderThan(entry os.DirEntry, cutoff time.Time) bool {
	info, err := entry.Info()
	return err == nil && info.ModTime().Before(cutoff)
}

// removeScratch deletes a scratch folder. A test can lock folders inside it
// against deletion; unlockTree gives them back first where that can happen.
func removeScratch(path string) error {
	if os.RemoveAll(path) == nil {
		return nil
	}
	unlockTree(path)
	return os.RemoveAll(path)
}

// leftover is path when removeScratch failed to delete it, and "" otherwise.
func leftover(path string) string {
	if removeScratch(path) != nil {
		return path
	}
	return ""
}
