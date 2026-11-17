//go:build windows

package main

import (
	"os"
	"os/exec"
	"testing"
)

// setTestMode gives path the access that matters about mode on Unix: group
// or other write bits grant Everyone modify access. Any other mode changes
// nothing, because the tests' files and folders already inherit owner-only
// access.
func setTestMode(_ testing.TB, path string, mode os.FileMode) error {
	if mode&0o022 == 0 {
		return nil
	}
	return exec.Command("icacls", path, "/grant", "*S-1-1-0:(M)").Run()
}
