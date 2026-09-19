package setup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestInitialPlanWriteDoesNotBypassReservedStaging(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plan.json")
	state, err := OpenStateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := NewPlan(ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", setupTime(0))
	if err != nil {
		t.Fatal(err)
	}
	partial := []byte("interrupted plan bytes")
	if err := os.WriteFile(path+".next", partial, 0600); err != nil {
		t.Fatal(err)
	}
	err = state.Initialize(context.Background(), plan)
	if err == nil {
		t.Error("initial write bypassed an existing staging file")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("failed initial write published final plan: %v", err)
	}
	if got, err := os.ReadFile(path + ".next"); err != nil || string(got) != string(partial) {
		t.Error("existing stage overwritten")
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	state, err = OpenStateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	if err := state.Initialize(context.Background(), plan); err != nil {
		t.Fatalf("recovered initialization: %v", err)
	}
	got, err := state.Current(context.Background())
	if err != nil || got.Identity() != plan.Identity() {
		t.Fatalf("recovered plan: %v", err)
	}
	if _, err := os.Lstat(path + ".next"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("installed plan retained staging: %v", err)
	}
}
