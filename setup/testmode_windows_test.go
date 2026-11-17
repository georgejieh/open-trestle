//go:build windows

package setup

import (
	"os"
	"os/exec"
	"testing"

	"github.com/georgejieh/open-trestle/internal/ownersonly"
	"github.com/georgejieh/open-trestle/internal/ownersonly/ownersonlytest"
)

func icacls(path string, arguments ...string) error {
	return exec.Command("icacls", append([]string{path}, arguments...)...).Run()
}

// setTestMode gives path the access that mode would give it on Unix: its
// explicit ACEs are removed so that it inherits from its parent, which in
// these tests grants only the current user, LocalSystem and Administrators;
// group or other write bits grant Everyone modify access, other group or
// other bits grant Users read access, and no owner bit denies the current
// user every right until the test ends.
func setTestMode(t testing.TB, path string, mode os.FileMode) error {
	t.Helper()
	if err := icacls(path, "/reset"); err != nil {
		return err
	}
	switch {
	case mode&0o022 != 0:
		ownersonlytest.Grant(t, path, ownersonlytest.Everyone+":(M)")
	case mode&0o055 != 0:
		ownersonlytest.Grant(t, path, ownersonlytest.Users+":(RX)")
	}
	if mode&0o700 == 0 {
		user, err := ownersonly.CurrentUserSID()
		if err != nil {
			return err
		}
		if err := icacls(path, "/deny", "*"+user+":(F)"); err != nil {
			return err
		}
		t.Cleanup(func() { _ = icacls(path, "/remove:d", "*"+user) })
	}
	return nil
}

// hasTestMode reports whether path, which info describes, has the access
// setTestMode gives for mode, as far as the ownership checks tell apart.
func hasTestMode(_ testing.TB, path string, info os.FileInfo, mode os.FileMode) bool {
	switch {
	case mode&0o077 == 0:
		return privateToProcess(path, info, ownerOnlyPermission)
	case mode&0o022 == 0:
		return unwritableByOthers(path, info) && !privateToProcess(path, info, ownerOnlyPermission)
	}
	return !unwritableByOthers(path, info)
}
