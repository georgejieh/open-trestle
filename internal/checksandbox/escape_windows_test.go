package checksandbox

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// platformProbe holds the Windows-only escape attempts.
func platformProbe(mode string, args []string) int {
	switch mode {
	case "fill-profile":
		return fillFile(filepath.Join(ownProfileFolder(args[0]), "fill"))
	case "fill-stream":
		// An alternate data stream does not change the file's size.
		return fillFile(filepath.Join(os.Getenv("TMPDIR"), "fill:hidden"))
	case "registry":
		readable := readableValues(registry.CURRENT_USER, "", 2)
		if readable == 0 {
			return probeBlocked
		}
		// Only the count: the values can be secrets.
		fmt.Printf("%d values readable\n", readable)
		return probeEscaped
	case "registry-value":
		return readValue(args[0])
	case "lock-scratch":
		return lockFolder(os.Getenv("TMPDIR"))
	case "lock-profile":
		return lockFolder(ownProfileFolder(args[0]))
	}
	return 2
}

// readValue reads the probe value the test planted under path in HKCU. Only
// a denied access counts as blocked; any other failure means the probe did
// not test what it should.
func readValue(path string) int {
	key, err := registry.OpenKey(registry.CURRENT_USER, path, registry.QUERY_VALUE)
	if err == nil {
		defer key.Close()
		_, _, err = key.GetStringValue(probeValueName)
	}
	switch {
	case err == nil:
		return probeEscaped
	case errors.Is(err, windows.ERROR_ACCESS_DENIED):
		return probeBlocked
	}
	fmt.Fprintln(os.Stderr, err)
	return 1
}

// readableValues counts the values the process can read in the key at path
// below root and in its subkeys, depth levels down.
func readableValues(root registry.Key, path string, depth int) int {
	key, err := registry.OpenKey(root, path, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return 0
	}
	defer key.Close()
	readable := 0
	names, _ := key.ReadValueNames(-1)
	for _, name := range names {
		if _, _, err := key.GetValue(name, nil); err == nil {
			readable++
		}
	}
	if depth == 0 {
		return readable
	}
	subkeys, _ := key.ReadSubKeyNames(-1)
	for _, subkey := range subkeys {
		readable += readableValues(key, subkey, depth-1)
	}
	return readable
}

// lockFolder writes a folder in base and then denies everyone access to
// it, so that the account could delete it only after taking its
// permissions back. A real attack would deny OWNER RIGHTS too, which only
// an administrator can undo; the probe does not, so that a failure leaves
// nothing the tests' user cannot remove. A folder created with such
// permissions from the start is not blocked; see docs/repository-checks.md.
func lockFolder(base string) int {
	folder := filepath.Join(base, "locked")
	if os.Mkdir(folder, 0o755) != nil || os.WriteFile(filepath.Join(folder, "file"), []byte("locked"), 0o644) != nil {
		return 1
	}
	everyone, err := windows.StringToSid("S-1-1-0")
	if err != nil {
		return 1
	}
	deny, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_ALL, AccessMode: windows.DENY_ACCESS,
		Trustee: windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_WELL_KNOWN_GROUP, TrusteeValue: windows.TrusteeValueFromSID(everyone)},
	}}, nil)
	runtime.KeepAlive(everyone)
	if err != nil {
		return 1
	}
	if windows.SetNamedSecurityInfo(folder, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, deny, nil) == nil {
		return probeEscaped
	}
	return probeBlocked
}

func TestEscapeLockTheScratchAgainstCleanup(t *testing.T) {
	for _, mode := range []string{"lock-scratch", "lock-profile"} {
		t.Run(mode, func(t *testing.T) {
			result := runProbe(t, profileProbeSpec(t, mode))
			requireBlocked(t, result)
			if result.Leftover != "" {
				t.Fatalf("the scratch was left behind: %s", result.Leftover)
			}
		})
	}
}

// fillFile writes to path until writing fails.
func fillFile(path string) int {
	file, err := os.Create(path)
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

// ownProfileFolder is this AppContainer's profile storage in the user's
// local application data, the one place outside the scratch a sandboxed
// process may write. The sandbox cannot ask Windows for it, but the
// profile's name is in its temporary folder's path and the rest is easy to
// guess.
func ownProfileFolder(localAppData string) string {
	name := filepath.Base(filepath.Dir(filepath.Dir(os.Getenv("TMPDIR"))))
	return filepath.Join(localAppData, "Packages", name, "AC")
}

// profileProbeSpec runs a probe that finds the profile folder.
func profileProbeSpec(t *testing.T, mode string) Spec {
	t.Helper()
	return probeSpec(t, mode, os.Getenv("LOCALAPPDATA"))
}

func TestEscapeDiskFillThroughTheProfileFolderIsBounded(t *testing.T) {
	requireDiskBounded(t, profileProbeSpec(t, "fill-profile"))
}

func TestEscapeDiskFillThroughAnAlternateStreamIsBounded(t *testing.T) {
	requireDiskBounded(t, probeSpec(t, "fill-stream"))
}

func requireDiskBounded(t *testing.T, spec Spec) {
	t.Helper()
	result := runProbe(t, spec)
	if !result.DiskExceeded || result.TimedOut || result.Duration > spec.Limits.Time/3 {
		t.Fatalf("the writes were not bounded: %+v stderr %q", result, result.Stderr)
	}
}

// probeValueName names the harmless value the registry test plants.
const probeValueName = "probe"

// TestEscapeReadUserRegistry checks that the sandbox reads no value of the
// user's registry hive, such as the variables setx saves in
// HKCU\Environment, which can hold keys: first a value planted for the
// test in a subkey of Environment, which grants every AppContainer reading,
// then any value two levels down. A subkey sets no environment variable.
func TestEscapeReadUserRegistry(t *testing.T) {
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	path := `Environment\OpenTrestle.Probe.` + hex.EncodeToString(random)
	key, _, err := registry.CreateKey(registry.CURRENT_USER, path, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	defer registry.DeleteKey(registry.CURRENT_USER, path)
	err = key.SetStringValue(probeValueName, "harmless")
	if err == nil {
		_, _, err = key.GetStringValue(probeValueName)
	}
	key.Close()
	if err != nil {
		t.Fatal(err)
	}
	t.Run("planted value", func(t *testing.T) {
		requireBlocked(t, runProbe(t, probeSpec(t, "registry-value", path)))
	})
	t.Run("whole hive", func(t *testing.T) {
		requireBlocked(t, runProbe(t, probeSpec(t, "registry")))
	})
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
