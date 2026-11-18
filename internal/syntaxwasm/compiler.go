package syntaxwasm

import (
	"runtime"

	"golang.org/x/sys/cpu"
)

// compilerSupported reports whether wazero's compiler supports this
// platform and CPU. It repeats wazero's own platform check, which is
// internal to wazero. wazero also probes for executable memory; when the
// platform refuses it, creating the runtime or compiling a module fails,
// and the analyzer reports analysis_unavailable the same way. The
// interpreter is never used: it is too slow for review use.
func compilerSupported() bool {
	switch runtime.GOOS {
	case "linux", "darwin", "freebsd", "netbsd", "windows":
		if runtime.GOARCH == "arm64" {
			return true
		}
	case "dragonfly", "solaris", "illumos":
	default:
		return false
	}
	return runtime.GOARCH == "amd64" && cpu.X86.HasSSE41
}
