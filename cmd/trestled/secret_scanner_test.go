package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/secretscan"
)

func TestDaemonSaysWhyTheScannerIsUnavailable(t *testing.T) {
	scanner := installedDaemonScanner(func(string) string { return "" })
	if scanner.sanitizer() != nil {
		t.Fatal("an unusable scanner produced a sanitizer")
	}
	var stderr bytes.Buffer
	scanner.prepare(context.Background(), &stderr)
	if want := "trestled: the secret scanner is unavailable, so requests to models will be refused: " + secretscan.ErrHelperNotPinned.Error(); !strings.Contains(stderr.String(), want) {
		t.Fatalf("stderr = %q", stderr.String())
	}
}
