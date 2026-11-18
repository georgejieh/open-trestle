package ownersonly

import (
	"bytes"
	"os"
	"testing"
)

// The secret scanner module keeps its own copy of the implementation, because
// it cannot import this module.
func TestScannerModuleCopyMatches(t *testing.T) {
	root, err := os.ReadFile("ownersonly_windows.go")
	if err != nil {
		t.Fatal(err)
	}
	scanner, err := os.ReadFile("../../workers/secret-scanner/internal/ownersonly/ownersonly_windows.go")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(root, scanner) {
		t.Fatal("root and secret scanner copies of ownersonly_windows.go differ")
	}
}
