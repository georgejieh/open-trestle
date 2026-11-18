//go:build !linux && !darwin

package syntaxworker

// physicalMemory is unknown here; DefaultWorkers assumes a fixed amount.
func physicalMemory() uint64 { return 0 }
