package checksandbox

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

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
	case "terminal":
		if file, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
			file.Close()
			return probeEscaped
		}
		if sid, err := unix.Getsid(0); err != nil || sid == unix.Getpid() {
			return 1
		}
	case "capabilities":
		status, err := os.ReadFile("/proc/self/status")
		if err != nil {
			return 1
		}
		for _, line := range strings.Split(string(status), "\n") {
			if name, value, ok := strings.Cut(line, ":\t"); ok && strings.HasPrefix(name, "Cap") && strings.Trim(value, "0") != "" {
				return probeEscaped
			}
		}
	case "descriptors":
		// Only standard input, output and error may reach the command; a
		// pipe beyond them would be the sandbox's own channel to its parent.
		for descriptor := 3; descriptor < 64; descriptor++ {
			var stat unix.Stat_t
			if unix.Fstat(descriptor, &stat) == nil && stat.Mode&unix.S_IFMT == unix.S_IFIFO {
				return probeEscaped
			}
		}
	case "unshare":
		if unix.Unshare(unix.CLONE_NEWUSER|unix.CLONE_NEWNS) == nil {
			return probeEscaped
		}
	case "kill-init":
		// Ending process 1 would end the run without a report.
		for _, signal := range []unix.Signal{unix.SIGTERM, unix.SIGINT, unix.SIGHUP, unix.SIGQUIT, unix.SIGUSR1, unix.SIGABRT, unix.SIGSEGV, unix.SIGPIPE} {
			_ = unix.Kill(1, signal)
		}
		time.Sleep(time.Second)
	case "init-descriptors":
		// Process 1's status pipe would let the command forge the report.
		for _, path := range []string{"/proc/1/fd/4", "/proc/1/fd/3"} {
			if file, err := os.OpenFile(path, os.O_WRONLY, 0); err == nil {
				file.Close()
				return probeEscaped
			}
		}
	case "oom-score":
		if score, err := os.ReadFile("/proc/self/oom_score_adj"); err != nil || strings.TrimSpace(string(score)) != "1000" {
			fmt.Printf("oom_score_adj %q\n", score)
			return 1
		}
		return 0
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

func TestEscapeTerminal(t *testing.T) {
	requireBlocked(t, runProbe(t, probeSpec(t, "terminal")))
}

func TestEscapeCapabilities(t *testing.T) {
	requireBlocked(t, runProbe(t, probeSpec(t, "capabilities")))
}

func TestEscapeInheritedDescriptors(t *testing.T) {
	requireBlocked(t, runProbe(t, probeSpec(t, "descriptors")))
}

func TestEscapeHostProcesses(t *testing.T) {
	requireBlocked(t, runProbe(t, probeSpec(t, "proc")))
}

func TestEscapeSignalFirstProcess(t *testing.T) {
	requireBlocked(t, runProbe(t, probeSpec(t, "kill-init")))
}

func TestEscapeFirstProcessDescriptors(t *testing.T) {
	requireBlocked(t, runProbe(t, probeSpec(t, "init-descriptors")))
}

func TestSandboxGoesFirstToTheOutOfMemoryKiller(t *testing.T) {
	if result := runProbe(t, probeSpec(t, "oom-score")); !result.Succeeded() {
		t.Fatalf("result %+v stdout %q", result, result.Stdout)
	}
}

func TestSystemProgramsAreFoundByName(t *testing.T) {
	spec := probeSpec(t)
	spec.Args = []string{"/usr/bin/env", "sh", "-c", "exit 7"}
	if result := runProbe(t, spec); result.ExitCode != 7 {
		t.Fatalf("result %+v stderr %q", result, result.Stderr)
	}
}
