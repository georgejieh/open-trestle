package checksandbox

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestRemoveToolchainGrantsTakesBackRecordedGrants(t *testing.T) {
	capability, err := capabilitySid(toolchainCapability)
	if err != nil {
		t.Fatal(err)
	}
	folder := t.TempDir()
	tool := filepath.Join(folder, "tool.exe")
	if err := os.WriteFile(tool, []byte("tool"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ensureReadable(folder, capability); err != nil {
		t.Fatal(err)
	}
	if !readableBy(t, tool, capability) {
		t.Fatal("the folder was not granted to the toolchain capability")
	}
	if err := RemoveToolchainGrants(); err != nil {
		t.Fatal(err)
	}
	if readableBy(t, folder, capability) || readableBy(t, tool, capability) {
		t.Fatal("the grant was not taken back")
	}
	record, err := grantRecordPath()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(record); !os.IsNotExist(err) {
		t.Fatalf("the record is still there: %v", err)
	}
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
