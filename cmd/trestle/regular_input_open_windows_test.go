//go:build windows

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWindowsRegularInputPathRejectsPipeAndDeviceNamespaces(t *testing.T) {
	for path, want := range map[string]bool{
		`C:\input.json`:                         true,
		`\\server\share\input.json`:             true,
		`\\?\C:\input.json`:                     true,
		`\\?\UNC\server\share\input.json`:       true,
		`\\.\pipe\input`:                        false,
		`\\?\pipe\input`:                        false,
		`\\server\pipe\input`:                   false,
		`\\.\PhysicalDrive0`:                    false,
		`\\?\GLOBALROOT\Device\HarddiskVolume1`: false,
	} {
		if got := windowsRegularInputPath(path); got != want {
			t.Errorf("windowsRegularInputPath(%q)=%t, want %t", path, got, want)
		}
	}
}

func TestOpenRegularInputFileNativeOpensRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input.json")
	if err := os.WriteFile(path, []byte("input"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := openRegularInputFileNative(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	information, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if !information.Mode().IsRegular() {
		t.Fatalf("opened mode=%v, want regular file", information.Mode())
	}
}

func TestOpenRegularInputFileNativeRejectsDevice(t *testing.T) {
	file, err := openRegularInputFileNative("NUL")
	if file != nil {
		file.Close()
		t.Fatal("device returned an open file")
	}
	if err == nil {
		t.Fatal("device was accepted")
	}
}
