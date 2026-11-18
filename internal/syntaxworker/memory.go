package syntaxworker

import "runtime"

const (
	// workerMemoryBytes is the memory one worker may use: a guest instance
	// at its linear-memory cap, the idle instances it keeps and the host.
	workerMemoryBytes = 768 << 20
	// unknownMemoryBytes stands in for the physical memory where the
	// platform does not report it.
	unknownMemoryBytes = 4 << 30
)

// DefaultWorkers is one worker per CPU, bounded so that the workers fit in
// half of the physical memory.
func DefaultWorkers() int {
	memory := physicalMemory()
	if memory == 0 {
		memory = unknownMemoryBytes
	}
	return max(1, min(runtime.GOMAXPROCS(0), int(memory/2/workerMemoryBytes)))
}
