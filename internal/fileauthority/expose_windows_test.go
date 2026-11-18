//go:build windows

package fileauthority_test

import (
	"os/exec"
	"testing"
)

// changeAccess grants Everyone modify access to path.
func changeAccess(t *testing.T, path string) {
	t.Helper()
	if output, err := exec.Command("icacls", path, "/grant", "*S-1-1-0:(M)").CombinedOutput(); err != nil {
		t.Fatalf("icacls: %v\n%s", err, output)
	}
}
