//go:build linux && amd64 && race

package sandbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func sandboxTestExecutable(t *testing.T) string {
	t.Helper()
	helper := filepath.Join(t.TempDir(), "sandbox-native.test")
	// The filter denies clone3, which the cgo thread-creation path can require.
	build := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "test", "-mod=readonly", "-race=false", "-c", "-o", helper, ".")
	build.Env = append(os.Environ(), "GOROOT="+runtime.GOROOT(), "GOTOOLCHAIN=local", "CGO_ENABLED=0", "GOFLAGS=")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build native sandbox helper: %v; output=%s", err, output)
	}
	return helper
}
