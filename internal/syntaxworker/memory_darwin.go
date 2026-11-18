package syntaxworker

import "golang.org/x/sys/unix"

func physicalMemory() uint64 {
	memory, err := unix.SysctlUint64("hw.memsize")
	if err != nil {
		return 0
	}
	return memory
}
