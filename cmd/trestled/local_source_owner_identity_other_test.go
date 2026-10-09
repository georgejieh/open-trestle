//go:build !linux

package main

import (
	"errors"
	"os"
	"testing"
)

func TestLocalSourceDirectoryIdentityUnsupportedPlatform(t *testing.T) {
	info, err := os.Stat(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := localSourceDirectoryIdentityFromInfo(info); !errors.Is(err, errLocalSourceOwnerUnsupported) {
		t.Fatalf("non-Linux identity: %v", err)
	}
}
