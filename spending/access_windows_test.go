//go:build windows

package spending

import (
	"os"
	"os/exec"
	"testing"

	"github.com/georgejieh/open-trestle/internal/ownersonly"
	"github.com/georgejieh/open-trestle/internal/ownersonly/ownersonlytest"
)

// private reports whether only this account, SYSTEM and Administrators can
// access path.
func private(t *testing.T, path string) bool {
	t.Helper()
	return ownersonly.CheckPath(path, nil, ownersonly.Rule{Owner: ownersonly.OwnerCurrentUser, Others: ownersonly.OthersNone}) == nil
}

// exposeToOthers grants Users read access to path.
func exposeToOthers(t *testing.T, path string, _ os.FileMode) {
	t.Helper()
	ownersonlytest.Grant(t, path, ownersonlytest.Users+":(RX)")
}

// makePrivate removes the access exposeToOthers granted.
func makePrivate(t *testing.T, path string, _ os.FileMode) {
	t.Helper()
	if output, err := exec.Command("icacls", path, "/remove:g", ownersonlytest.Users).CombinedOutput(); err != nil {
		t.Fatalf("icacls: %v\n%s", err, output)
	}
}
