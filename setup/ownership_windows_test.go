//go:build windows

package setup

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/ownersonly/ownersonlytest"
)

func TestWindowsStateFilesAreOwnerOnlyBelowAReadableParent(t *testing.T) {
	parent := ownersonlytest.TempDir(t)
	// Entries created here without their own descriptor would inherit read
	// access for Users.
	ownersonlytest.Grant(t, parent, ownersonlytest.Users+":(OI)(CI)(RX)")
	if err := os.Mkdir(filepath.Join(parent, "state"), 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "state", "plan.json")
	state, err := OpenStateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := NewPlan(ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", setupTime(0))
	if err != nil {
		t.Fatal(err)
	}
	if err = state.Initialize(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if err = state.Close(); err != nil {
		t.Fatal(err)
	}
	ownersonlytest.RequireOwnerOnly(t, path)
	ownersonlytest.RequireOwnerOnly(t, path+".receipts")
	if inspected, err := InspectStateFile(context.Background(), path); err != nil || inspected.Identity() != plan.Identity() {
		t.Fatalf("inspect: %v", err)
	}
	backupRoot := filepath.Join(parent, "backup")
	if err := makePrivateDirectory(backupRoot); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(backupRoot, "plan.snapshot.json")
	if _, err := CreateBackupSnapshot(context.Background(), path, backup, plan.Identity()); err != nil {
		t.Fatal(err)
	}
	ownersonlytest.RequireOwnerOnly(t, backup)
	// The parent of a backup must itself be private.
	open := filepath.Join(parent, "open")
	if err := os.Mkdir(open, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateBackupSnapshot(context.Background(), path, filepath.Join(open, "plan.snapshot.json"), plan.Identity()); err == nil {
		t.Fatal("a backup was written into a folder others can read")
	}
}

func TestWindowsStateFileRefusesAParentOthersCanWrite(t *testing.T) {
	parent := ownersonlytest.TempDir(t)
	ownersonlytest.Grant(t, parent, ownersonlytest.AuthenticatedUsers+":(OI)(CI)(M)")
	if state, err := OpenStateFile(filepath.Join(parent, "plan.json")); err == nil {
		_ = state.Close()
		t.Fatal("a state file below a folder others can write was opened")
	}
}

func TestWindowsProcessIdentity(t *testing.T) {
	identity, ok := currentProcessIdentity()
	if !ok || !strings.HasPrefix(identity, "user:S-1-") || !strings.Contains(identity, ";groups:[") {
		t.Fatalf("identity = %q, %v", identity, ok)
	}
	again, ok := currentProcessIdentity()
	if !ok || again != identity {
		t.Fatal("the process identity is not stable")
	}
}
