//go:build !unix

package fileauthority

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteNewProtectedFileUnsupportedPlatformRefusesBeforeCreate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "retained-memory-input.json")
	content := []byte("unsupported-platform-content")
	err := WriteNewProtectedFile(context.Background(), path, content, len(content))
	if !errors.Is(err, ErrProtectedWriteRefused) {
		t.Fatalf("unsupported platform did not fail closed before create: %v", err)
	}
	if err != nil && (strings.Contains(err.Error(), path) || strings.Contains(err.Error(), string(content))) {
		t.Fatal("unsupported-platform refusal leaked path or content")
	}
	if _, statErr := os.Lstat(path); !os.IsNotExist(statErr) {
		t.Fatal("unsupported-platform refusal created output")
	}
}
