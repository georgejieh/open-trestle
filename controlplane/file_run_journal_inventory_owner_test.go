package controlplane

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestStartupInventoryOwnerLeafAllowanceIsExactAndCounted(t *testing.T) {
	for _, variant := range []string{"private-owner", "public-owner", "directory-owner", "symlink-owner", "staging-owner", "owner-counts-toward-limit"} {
		t.Run(variant, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "journal")
			journal, err := NewFileRunJournal(root)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := journal.Close(); err != nil {
					t.Error(err)
				}
			}()
			owner := filepath.Join(root, ".local-source-owner.json")
			switch variant {
			case "private-owner", "public-owner", "owner-counts-toward-limit":
				if err := os.WriteFile(owner, []byte("owner bytes are not inventory authority"), 0600); err != nil {
					t.Fatal(err)
				}
				if variant == "public-owner" {
					if err := os.Chmod(owner, 0644); err != nil {
						t.Fatal(err)
					}
				}
			case "directory-owner":
				if err := os.Mkdir(owner, 0700); err != nil {
					t.Fatal(err)
				}
			case "symlink-owner":
				if err := os.Symlink(".run-writer.lock", owner); err != nil {
					t.Fatal(err)
				}
			case "staging-owner":
				if err := os.WriteFile(filepath.Join(root, ".local-source-owner-0123.tmp"), []byte("x"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if variant == "owner-counts-toward-limit" {
				for index := 0; index < maxStartupInventoryEntries-1; index++ {
					if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("filler-%04d", index)), []byte("x"), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			_, err = journal.InspectStartupInventory(context.Background())
			switch variant {
			case "private-owner":
				if err != nil {
					t.Fatalf("private owner must not bypass or fail empty exhaustive inventory: %v", err)
				}
			case "owner-counts-toward-limit":
				if !errors.Is(err, ErrStartupInventoryLimit) {
					t.Fatalf("owner must count within direct entry bound: %v", err)
				}
			default:
				if !errors.Is(err, ErrInvalidStartupInventoryEntry) {
					t.Fatalf("invalid owner variant accepted or misclassified: %v", err)
				}
			}
		})
	}
}
