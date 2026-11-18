package checksandbox

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

// platformProbe holds the Linux-only escape attempts.
func platformProbe(mode string, _ []string) int {
	switch mode {
	case "ptrace":
		child := exec.Command(os.Args[0], "__probe", "sleep", "traced")
		if child.Start() != nil {
			return 1
		}
		defer child.Process.Kill()
		if unix.PtraceAttach(child.Process.Pid) == nil {
			return probeEscaped
		}
		if unix.PtraceSeize(child.Process.Pid) == nil {
			return probeEscaped
		}
	case "mount":
		target := filepath.Join(os.Getenv("TMPDIR"), "mnt")
		if os.Mkdir(target, 0o755) != nil {
			return 1
		}
		if unix.Mount("tmpfs", target, "tmpfs", 0, "") == nil {
			return probeEscaped
		}
		if unix.Mount("/", target, "", unix.MS_BIND, "") == nil {
			return probeEscaped
		}
	case "unshare":
		if unix.Unshare(unix.CLONE_NEWUSER|unix.CLONE_NEWNS) == nil {
			return probeEscaped
		}
	case "proc":
		// Other processes' environments and the host's processes are not
		// visible: only the sandbox's processes have /proc entries.
		paths, err := filepath.Glob("/proc/[0-9]*")
		if err != nil || len(paths) == 0 {
			return 1
		}
		for _, path := range paths {
			if name := filepath.Base(path); name != "1" && name != strconv.Itoa(os.Getpid()) {
				return probeEscaped
			}
		}
	default:
		return 2
	}
	return probeBlocked
}

// processAlive reports whether a child of this process has not exited; a
// child that died is a zombie until reaped, so its state is read.
func processAlive(pid int) bool {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	return err == nil && !bytes.Contains(data, []byte(") Z "))
}

// environmentLeaks reports whether value appears in any environment that
// /proc shows.
func environmentLeaks(value string) bool {
	paths, _ := filepath.Glob("/proc/[0-9]*/environ")
	for _, path := range paths {
		if data, err := os.ReadFile(path); err == nil && bytes.Contains(data, []byte(value)) {
			return true
		}
	}
	return false
}

// assertNoneLeft fails if a host process still carries tag in its command
// line.
func assertNoneLeft(t *testing.T, tag string, _ []byte) {
	t.Helper()
	paths, _ := filepath.Glob("/proc/[0-9]*/cmdline")
	for _, path := range paths {
		if data, err := os.ReadFile(path); err == nil && bytes.Contains(data, []byte(tag)) {
			t.Fatalf("a process survived the time limit: %s", path)
		}
	}
}

func TestEscapePtrace(t *testing.T) {
	requireBlocked(t, runProbe(t, probeSpec(t, "ptrace")))
}

func TestEscapeMount(t *testing.T) {
	requireBlocked(t, runProbe(t, probeSpec(t, "mount")))
}

func TestEscapeNestedNamespace(t *testing.T) {
	requireBlocked(t, runProbe(t, probeSpec(t, "unshare")))
}

func TestEscapeHostProcesses(t *testing.T) {
	requireBlocked(t, runProbe(t, probeSpec(t, "proc")))
}
