//go:build linux

package checksandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// processLimit is the RLIMIT_NPROC value that lets limit processes and
// threads run in the sandbox. Before Linux 5.14 that limit counts every
// process and thread of the account, not only those of the sandbox's user
// namespace, so the ones already running are added.
func processLimit(limit int) int {
	var name unix.Utsname
	if unix.Uname(&name) == nil && !countsHostTasks(unix.ByteSliceToString(name.Release[:])) {
		return limit
	}
	return limit + accountTasks()
}

// countsHostTasks reports whether a kernel of this release counts the
// account's host processes against a user namespace's RLIMIT_NPROC. An
// unreadable release is taken to be old.
func countsHostTasks(release string) bool {
	var major, minor int
	if _, err := fmt.Sscanf(release, "%d.%d", &major, &minor); err != nil {
		return true
	}
	return major < 5 || major == 5 && minor < 14
}

// accountTasks counts the threads of the processes whose real user is this
// account.
func accountTasks() int {
	uid := strconv.Itoa(os.Getuid())
	paths, _ := filepath.Glob("/proc/[0-9]*/status")
	total := 0
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		owned, threads := false, 0
		for _, line := range strings.Split(string(data), "\n") {
			if value, ok := strings.CutPrefix(line, "Uid:"); ok {
				fields := strings.Fields(value)
				owned = len(fields) > 0 && fields[0] == uid
			} else if value, ok := strings.CutPrefix(line, "Threads:"); ok {
				threads, _ = strconv.Atoi(strings.TrimSpace(value))
			}
		}
		if owned {
			total += threads
		}
	}
	return total
}
