package syntaxworker

import (
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// physicalMemory is the machine's memory, or the memory limit of the
// process's cgroup when that is lower, as in a container.
func physicalMemory() uint64 {
	var info unix.Sysinfo_t
	if unix.Sysinfo(&info) != nil {
		return 0
	}
	memory := uint64(info.Totalram) * uint64(info.Unit)
	if limit, err := os.ReadFile("/sys/fs/cgroup/memory.max"); err == nil {
		if value, err := strconv.ParseUint(strings.TrimSpace(string(limit)), 10, 64); err == nil && value > 0 && value < memory {
			memory = value
		}
	}
	return memory
}
