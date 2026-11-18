package checksandbox

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// platformProbe holds the Windows-only escape attempts.
func platformProbe(mode string, _ []string) int {
	if mode != "fill-profile" {
		return 2
	}
	folder, err := ownProfileFolder()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	file, err := os.Create(filepath.Join(folder, "fill"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer file.Close()
	chunk := make([]byte, 1<<20)
	for {
		if _, err := file.Write(chunk); err != nil {
			return 0
		}
	}
}

// ownProfileFolder asks Windows for this AppContainer's profile storage,
// the one place outside the scratch a sandboxed process may write.
func ownProfileFolder() (string, error) {
	const tokenAppContainerSid = 31
	token := windows.GetCurrentProcessToken()
	buffer := make([]byte, 256)
	var size uint32
	if err := windows.GetTokenInformation(token, tokenAppContainerSid, &buffer[0], uint32(len(buffer)), &size); err != nil {
		return "", err
	}
	sid := *(**windows.SID)(unsafe.Pointer(&buffer[0]))
	return profileFolder(sid)
}

func TestEscapeDiskFillThroughTheProfileFolderIsBounded(t *testing.T) {
	spec := probeSpec(t, "fill-profile")
	result, err := Run(context.Background(), spec)
	if err != nil {
		t.Skipf("the sandbox is unavailable here: %v", err)
	}
	if !result.DiskExceeded || result.TimedOut || result.Duration > spec.Limits.Time/3 {
		t.Fatalf("writes to the profile folder were not bounded: %+v stderr %q", result, result.Stderr)
	}
}

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
