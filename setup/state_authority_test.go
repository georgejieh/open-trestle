package setup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSetupStateRejectsReplaceableAncestorBeforeMutations(t *testing.T) {
	shared := filepath.Join(t.TempDir(), "shared")
	private := filepath.Join(shared, "private")
	if err := os.MkdirAll(private, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(private, "plan.json")
	state, err := OpenStateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := NewPlan(ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", setupTime(0))
	if err != nil {
		t.Fatal(err)
	}
	if err := state.Initialize(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, 0777); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectStateFile(context.Background(), path); !errors.Is(err, ErrInvalidStatePath) {
		t.Errorf("inspection trusted replaceable history: %v", err)
	}
	for _, candidate := range []string{path, filepath.Join(private, "new.json")} {
		opened, err := OpenStateFile(candidate)
		if opened != nil {
			opened.Close()
		}
		if !errors.Is(err, ErrInvalidStatePath) || opened != nil {
			t.Errorf("writer trusted replaceable path: %v", err)
		}
	}
	for _, suffix := range []string{".lock", ".receipts"} {
		if _, err := os.Lstat(filepath.Join(private, "new.json") + suffix); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("rejected writer created %s: %v", suffix, err)
		}
	}
}
