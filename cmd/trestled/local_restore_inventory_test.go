package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestRestoredInventoryComparesClosedBytesWithoutMutation(t *testing.T) {
	path := t.TempDir()
	if err := os.WriteFile(filepath.Join(path, "record"), []byte("closed bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(path, "empty"), 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	first, err := inventoryRestoredTree(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	second, err := inventoryRestoredTree(context.Background(), root)
	if err != nil || !reflect.DeepEqual(first, second) {
		t.Fatalf("unstable inventory: %v", err)
	}
	if len(first) != 2 {
		t.Fatalf("inventory omissions: %d", len(first))
	}
	if err := os.WriteFile(filepath.Join(path, "record"), []byte("changed byte"), 0o600); err != nil {
		t.Fatal(err)
	}
	changed, err := inventoryRestoredTree(context.Background(), root)
	if err != nil || reflect.DeepEqual(first, changed) {
		t.Fatalf("changed bytes not reflected: %v", err)
	}
	if err := os.Symlink("record", filepath.Join(path, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := inventoryRestoredTree(context.Background(), root); !errors.Is(err, errRestoreObservationMismatch) {
		t.Fatalf("symlink accepted: %v", err)
	}
}
