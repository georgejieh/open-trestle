//go:build windows

package ownersonlytest

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/ownersonly"
)

// Well-known SIDs in the form icacls accepts.
const (
	Everyone           = "*S-1-1-0"
	Users              = "*S-1-5-32-545"
	AuthenticatedUsers = "*S-1-5-11"
)

// Grant adds an allow ACE to path, such as Users+":(R)" or
// Everyone+":(OI)(CI)(M)", with icacls.
func Grant(t testing.TB, path, ace string) {
	t.Helper()
	if output, err := exec.Command("icacls", path, "/grant", ace).CombinedOutput(); err != nil {
		t.Fatalf("icacls %s /grant %s: %v\n%s", path, ace, err, output)
	}
}

// ACL returns the access-control list of path as icacls prints it.
func ACL(t testing.TB, path string) string {
	t.Helper()
	output, err := exec.Command("icacls", path).CombinedOutput()
	if err != nil {
		t.Fatalf("icacls %s: %v\n%s", path, err, output)
	}
	return string(output)
}

// RequireOwnerOnly fails the test unless path is owned by the current user
// and its DACL is protected, inherits nothing and grants access only to the
// current user, LocalSystem and Administrators.
func RequireOwnerOnly(t testing.TB, path string) {
	t.Helper()
	if err := ownersonly.CheckPath(path, nil, ownersonly.Rule{Owner: ownersonly.OwnerCurrentUser, Others: ownersonly.OthersNone}); err != nil {
		t.Fatalf("%s is not owner-only: %v", path, err)
	}
	if acl := ACL(t, path); strings.Contains(acl, "(I)") {
		t.Fatalf("%s inherits access entries:\n%s", path, acl)
	}
}

// Junction creates a directory junction at link that points at target.
// Creating a junction needs no privilege.
func Junction(t testing.TB, link, target string) {
	t.Helper()
	if output, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J %s %s: %v\n%s", link, target, err, output)
	}
}

// TempDir returns a new owner-only directory inside t.TempDir. It fails the
// test when the temporary directory or a directory above it lets another
// principal write, because nothing below such a directory can pass an
// ancestor check; TMP must then name a directory below the user profile.
func TempDir(t testing.TB) string {
	t.Helper()
	base := t.TempDir()
	for current := base; ; current = filepath.Dir(current) {
		if err := ownersonly.CheckPath(current, nil, ownersonly.Rule{Owner: ownersonly.OwnerTrusted, Others: ownersonly.OthersReadAdd}); err != nil {
			t.Fatalf("%s lets another principal write; set TMP to a directory below the user profile", current)
		}
		if filepath.Dir(current) == current {
			break
		}
	}
	directory := filepath.Join(base, "private")
	if err := ownersonly.Mkdir(directory); err != nil {
		t.Fatal(err)
	}
	return directory
}
