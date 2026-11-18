//go:build windows

package filelock

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/georgejieh/open-trestle/internal/ownersonly"
	"github.com/georgejieh/open-trestle/internal/ownersonly/ownersonlytest"
)

// readOnlyMode is the mode Windows reports for a file written with mode
// 0400, which only sets its read-only attribute.
const readOnlyMode os.FileMode = 0o444

// privateLockFile reports whether only the owner and the system's own
// accounts can access path.
func privateLockFile(t *testing.T, path string) bool {
	t.Helper()
	return ownersonly.CheckPath(path, nil, ownersonly.Rule{Owner: ownersonly.OwnerCurrentUser, Others: ownersonly.OthersNone}) == nil
}

func TestWindowsLockFileIsOwnerOnlyBelowAReadableFolder(t *testing.T) {
	directory := ownersonlytest.TempDir(t)
	ownersonlytest.Grant(t, directory, ownersonlytest.Users+":(OI)(CI)(RX)")
	path := filepath.Join(directory, "writer.lock")
	lock, err := Acquire(path)
	if err != nil {
		t.Fatal(err)
	}
	ownersonlytest.RequireOwnerOnly(t, path)
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := Acquire(path)
	if err != nil {
		t.Fatalf("its own lock file was refused: %v", err)
	}
	if err := again.Close(); err != nil {
		t.Fatal(err)
	}
	// A lock file that inherited read access for Users is refused.
	inherited := filepath.Join(directory, "inherited.lock")
	if err := os.WriteFile(inherited, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if lock, err := Acquire(inherited); !errors.Is(err, ErrInvalidPath) || lock != nil {
		t.Fatalf("a lock file others can open was used: %v", err)
	}
}
