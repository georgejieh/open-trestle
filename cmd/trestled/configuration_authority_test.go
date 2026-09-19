package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRuntimeConfigurationRejectsReplaceableAncestor(t *testing.T) {
	root := t.TempDir()
	shared := filepath.Join(root, "shared")
	private := filepath.Join(shared, "private")
	if err := os.MkdirAll(private, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, 0777); err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(private, "policy.json")
	if err := os.WriteFile(filename, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := openRuntimeConfigurationFile(filename)
	if file != nil {
		file.Close()
	}
	if !errors.Is(err, ErrInvalidDaemonConfiguration) || file != nil {
		t.Fatalf("replaceable policy path accepted: %v", err)
	}
}
