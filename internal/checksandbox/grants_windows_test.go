package checksandbox

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"golang.org/x/sys/windows"
)

func TestRemoveToolchainGrantsTakesBackRecordedGrants(t *testing.T) {
	capability, err := capabilitySid(toolchainCapability)
	if err != nil {
		t.Fatal(err)
	}
	folder := privateFolder(t)
	tool := filepath.Join(folder, "tool.exe")
	if err := os.WriteFile(tool, []byte("tool"), 0o644); err != nil {
		t.Fatal(err)
	}
	logon, err := logonSid()
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureReadable(folder, capability, logon); err != nil {
		t.Fatal(err)
	}
	if !readableBy(t, tool, capability) || !readableBy(t, tool, logon) {
		t.Fatal("the folder was not granted to the toolchain capability and the logon session")
	}
	if err := RemoveToolchainGrants(); err != nil {
		t.Fatal(err)
	}
	if readableBy(t, folder, capability) || readableBy(t, tool, capability) || readableBy(t, folder, logon) || readableBy(t, tool, logon) {
		t.Fatal("the grants were not taken back")
	}
	record, err := grantRecordPath()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(record); !os.IsNotExist(err) {
		t.Fatalf("the record is still there: %v", err)
	}
}

func TestEnsureReadableReplacesAnEarlierLogonSessionsGrant(t *testing.T) {
	capability, err := capabilitySid(toolchainCapability)
	if err != nil {
		t.Fatal(err)
	}
	logon, err := logonSid()
	if err != nil {
		t.Fatal(err)
	}
	earlier, err := windows.StringToSid("S-1-5-5-0-1")
	if err != nil {
		t.Fatal(err)
	}
	folder := privateFolder(t)
	if err := grant(folder, windows.GENERIC_READ|windows.GENERIC_EXECUTE, earlier); err != nil {
		t.Fatal(err)
	}
	if err := ensureReadable(folder, capability, logon); err != nil {
		t.Fatal(err)
	}
	defer RemoveToolchainGrants()
	if readableBy(t, folder, earlier) || !readableBy(t, folder, logon) {
		t.Fatal("the earlier session's grant was not replaced by this session's")
	}
}

// privateFolder is a temporary folder only the user can use, whatever the
// temporary folder's own permissions, so no group the sandbox keeps reads
// it.
func privateFolder(t *testing.T) string {
	t.Helper()
	folder := t.TempDir()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	dacl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{access(user.User.Sid, windows.GRANT_ACCESS, windows.GENERIC_ALL)}, nil)
	runtime.KeepAlive(user)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(folder, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	return folder
}

func readableBy(t *testing.T, path string, sid *windows.SID) bool {
	t.Helper()
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	return grantsRead(dacl, sid)
}
