package fileauthority

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRemoveValidatedProtectedFileBindsValidatedEntry(t *testing.T) {
	for _, change := range []string{"none", "replacement", "symlink", "invalid"} {
		t.Run(change, func(t *testing.T) {
			directory := t.TempDir()
			if err := os.Chmod(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(directory, "advice.json")
			if err := os.WriteFile(target, []byte("original"), 0o600); err != nil {
				t.Fatal(err)
			}
			err := RemoveValidatedProtectedFile(context.Background(), target, 65536, func(encoded []byte) error {
				if string(encoded) != "original" {
					t.Fatal("validated different content")
				}
				if change == "invalid" {
					return errors.New("refused")
				}
				if change == "replacement" || change == "symlink" {
					if err := os.Rename(target, filepath.Join(directory, "old")); err != nil {
						t.Fatal(err)
					}
					if change == "replacement" {
						if err := os.WriteFile(target, []byte("replacement"), 0o600); err != nil {
							t.Fatal(err)
						}
					} else if err := os.Symlink("old", target); err != nil {
						t.Fatal(err)
					}
				}
				return nil
			})
			if change == "none" {
				if err != nil {
					t.Fatal(err)
				}
				if _, err := os.Lstat(target); !os.IsNotExist(err) {
					t.Fatal("target not removed")
				}
			} else {
				if !errors.Is(err, ErrProtectedRemoveRefused) {
					t.Fatalf("got %v", err)
				}
				if _, err := os.Lstat(target); err != nil {
					t.Fatal("refusal removed target")
				}
			}
		})
	}
}

func TestRemoveValidatedProtectedFileRejectsCanceledOrOversizeInput(t *testing.T) {
	for _, kind := range []string{"canceled", "oversize"} {
		directory := t.TempDir()
		if err := os.Chmod(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(directory, "advice.json")
		if err := os.WriteFile(target, []byte("original"), 0o600); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		limit := 65536
		if kind == "canceled" {
			cancel()
		} else {
			limit = 1
		}
		called := false
		err := RemoveValidatedProtectedFile(ctx, target, limit, func([]byte) error { called = true; return nil })
		cancel()
		if !errors.Is(err, ErrProtectedRemoveRefused) || called {
			t.Fatal("invalid removal reached validation")
		}
		if value, err := os.ReadFile(target); err != nil || string(value) != "original" {
			t.Fatal("invalid removal changed target")
		}
	}
}
