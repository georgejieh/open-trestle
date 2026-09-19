package main

import (
	"errors"
	"io"
	"testing"
)

type retainedTextShortWriter struct{}

func (retainedTextShortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }
func TestRetainedMemoryTextReceiptRejectsShortWrite(t *testing.T) {
	err := writeLocalGitRetainedMemoryInputReceipt("text", localGitRetainedMemoryInputReceipt{Status: "authored"}, retainedTextShortWriter{})
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short text receipt write = %v, want short write", err)
	}
}
