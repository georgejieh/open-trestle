package semanticimpact

import (
	"bytes"
	"errors"
	"runtime"
	"strings"
	"testing"
)

func TestInputRejectsDuplicateFilesBeforeCopyingContent(t *testing.T) {
	file, err := NewFile("a.go", bytes.Repeat([]byte{'a'}, maximumFileBytes))
	if err != nil {
		t.Fatal(err)
	}
	files := []File{file, file}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	input, err := NewInput(strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), nil, files, nil)
	runtime.ReadMemStats(&after)
	if !errors.Is(err, ErrInvalidInput) || input.identity != "" {
		t.Fatalf("duplicate accepted: %v", err)
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated >= maximumFileBytes {
		t.Fatalf("copied content before rejecting duplicates: allocated=%d", allocated)
	}
}
