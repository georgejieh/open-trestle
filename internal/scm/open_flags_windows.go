package scm

import "os"

// regularFileOpenFlags needs no non-blocking flag on Windows: a directory
// entry there cannot be a FIFO, so opening one never waits for a writer.
func regularFileOpenFlags() int {
	return os.O_RDONLY
}

func nonblockingRegularFileOpenSupported() bool {
	return true
}

func confinedRootOpenSupported() bool {
	return true
}
