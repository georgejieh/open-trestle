package syntaxwasm

import (
	"runtime"

	"golang.org/x/sys/cpu"
)

// compilerSupported reports whether wazero's compiler runs here. It mirrors
// wazero's own platform check, which is internal to wazero: amd64 with
// SSE4.1 or arm64, on Linux, macOS, Windows, FreeBSD or NetBSD. Without the
// compiler the analyzer reports analysis_unavailable rather than falling
// back to the interpreter, which is too slow for review use.
func compilerSupported() bool {
	switch runtime.GOOS {
	case "linux", "darwin", "windows", "freebsd", "netbsd":
	default:
		return false
	}
	switch runtime.GOARCH {
	case "arm64":
		return true
	case "amd64":
		return cpu.X86.HasSSE41
	}
	return false
}
