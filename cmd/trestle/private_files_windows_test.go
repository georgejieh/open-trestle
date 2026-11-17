//go:build windows

package main

import (
	"os"
	"testing"

	"github.com/georgejieh/open-trestle/internal/ownersonly"
	"github.com/georgejieh/open-trestle/internal/ownersonly/ownersonlytest"
)

// privateTestFile reports whether only this account, SYSTEM and
// Administrators can access path.
func privateTestFile(t *testing.T, path string) bool {
	t.Helper()
	return ownersonly.CheckPath(path, nil, ownersonly.Rule{Owner: ownersonly.OwnerCurrentUser, Others: ownersonly.OthersNone}) == nil
}

// exposeTestDirectory lets Users list path.
func exposeTestDirectory(t *testing.T, path string) {
	t.Helper()
	ownersonlytest.Grant(t, path, ownersonlytest.Users+":(RX)")
}

// privateDirectoryRefusal is part of the explanation for a directory that is
// not private.
const privateDirectoryRefusal = "only this account, SYSTEM, Administrators and TrustedInstaller"

// setTestMode gives path the access that matters about mode on Unix: group
// or other write bits grant Everyone modify access, and any other mode
// changes nothing, because the tests' files already inherit owner-only
// access.
func setTestMode(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if mode&0o022 != 0 {
		ownersonlytest.Grant(t, path, ownersonlytest.Everyone+":(M)")
	}
}
