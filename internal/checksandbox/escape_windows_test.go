package checksandbox

import (
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func platformProbe(string, []string) int { return 2 }

// environmentLeaks has nothing to scan on Windows: no process can read
// another's environment without opening it, which the AppContainer cannot.
func environmentLeaks(string) bool { return false }

func processAlive(pid int) bool {
	handle, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(handle)
	event, _ := windows.WaitForSingleObject(handle, 0)
	return event == uint32(windows.WAIT_TIMEOUT)
}

// assertNoneLeft fails if a process whose ID the probe printed is still
// running.
func assertNoneLeft(t *testing.T, _ string, stdout []byte) {
	t.Helper()
	found := 0
	for _, line := range strings.Split(string(stdout), "\n") {
		text, ok := strings.CutPrefix(strings.TrimSpace(line), "pid ")
		if !ok {
			continue
		}
		pid, err := strconv.ParseUint(text, 10, 32)
		if err != nil {
			continue
		}
		found++
		handle, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
		if err != nil {
			continue
		}
		event, _ := windows.WaitForSingleObject(handle, 0)
		windows.CloseHandle(handle)
		if event != windows.WAIT_OBJECT_0 {
			t.Fatalf("process %d survived the time limit", pid)
		}
	}
	if found != 2 {
		t.Fatalf("the probe printed %d process IDs, want 2: %q", found, stdout)
	}
}
